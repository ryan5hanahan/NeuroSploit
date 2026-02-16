#!/usr/bin/env python3
"""
MCP Client - Model Context Protocol tool connectivity.

Provides a standard interface for connecting to MCP servers and
executing tools. Supports three transport modes:

  - direct:  In-process import of co-located tool handlers (default).
             Zero overhead, no subprocess, no protocol framing.
  - stdio:   Spawn server as a subprocess, communicate via JSON-RPC.
  - sse:     Connect to a remote server over HTTP/SSE.

Coexists with existing subprocess-based tool execution:
- MCP is tried first when enabled
- Falls back silently to subprocess if MCP unavailable
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    logger.debug("MCP package not installed. MCP tool connectivity disabled.")

try:
    from mcp.client.sse import sse_client
    HAS_MCP_SSE = True
except ImportError:
    HAS_MCP_SSE = False


# ---------------------------------------------------------------------------
# Sentinel for "direct" transport — no protocol, just in-process calls
# ---------------------------------------------------------------------------
_DIRECT_SESSION = "direct"


class MCPToolClient:
    """Client for connecting to MCP servers and executing tools.

    For co-located servers (same Python process), use transport="direct"
    to bypass MCP protocol overhead entirely.  The client imports TOOL_HANDLERS
    from the server module and calls them in-process.

    For remote or out-of-process servers, use transport="stdio" or "sse".
    """

    def __init__(self, config: Dict):
        mcp_config = config.get('mcp_servers', {})
        # "direct" transport works without the mcp package
        has_any_transport = HAS_MCP or any(
            s.get('transport') == 'direct'
            for s in mcp_config.get('servers', {}).values()
        )
        self.enabled = mcp_config.get('enabled', False) and has_any_transport
        self.servers_config = mcp_config.get('servers', {})
        self._sessions: Dict[str, Any] = {}           # server_name -> ClientSession | _DIRECT_SESSION
        self._contexts: Dict[str, list] = {}           # server_name -> [context_managers]
        self._direct_handlers: Dict[str, Dict] = {}    # server_name -> {tool_name: handler}
        self._available_tools: Dict[str, List[Dict]] = {}

        if self.enabled:
            logger.info(f"MCP client initialized with {len(self.servers_config)} server(s)")
        elif mcp_config.get('enabled', False):
            logger.warning("MCP enabled in config but no usable transport available. "
                          "Install with: pip install mcp>=1.0.0")

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect(self, server_name: str) -> bool:
        """Establish connection to an MCP server.

        Returns True if connection successful, False otherwise.
        """
        if not self.enabled:
            return False

        if server_name in self._sessions:
            return True

        server_config = self.servers_config.get(server_name)
        if not server_config:
            logger.error(f"MCP server '{server_name}' not found in config")
            return False

        transport = server_config.get('transport', 'direct')

        try:
            if transport == 'direct':
                return await self._connect_direct(server_name, server_config)
            elif transport == 'stdio':
                return await self._connect_stdio(server_name, server_config)
            elif transport == 'sse':
                return await self._connect_sse(server_name, server_config)
            else:
                logger.error(f"Unsupported MCP transport: {transport}")
                return False
        except Exception as e:
            logger.error(f"Failed to connect to MCP server '{server_name}': {e}")
            return False

    async def _connect_direct(self, server_name: str, config: Dict) -> bool:
        """Connect via direct in-process import.

        Imports TOOL_HANDLERS and TOOLS from the server module so calls
        bypass MCP protocol framing entirely.
        """
        module_path = config.get('module')

        # Infer module from command/args if module not explicit
        if not module_path:
            args = config.get('args', [])
            if len(args) >= 2 and args[0] == '-m':
                module_path = args[1]

        if not module_path:
            logger.error(f"MCP server '{server_name}': cannot determine module for direct import")
            return False

        try:
            import importlib
            mod = importlib.import_module(module_path)
            handlers = getattr(mod, 'TOOL_HANDLERS', None)
            tools_list = getattr(mod, 'TOOLS', None)

            if not handlers:
                logger.error(f"Module '{module_path}' has no TOOL_HANDLERS")
                return False

            self._direct_handlers[server_name] = handlers
            self._sessions[server_name] = _DIRECT_SESSION

            # Build tool list from TOOLS definitions or handler keys
            if tools_list:
                self._available_tools[server_name] = [
                    {"name": t.get("name", t.get("function", {}).get("name", "")),
                     "description": t.get("description", "")}
                    for t in tools_list
                ]
            else:
                self._available_tools[server_name] = [
                    {"name": name, "description": ""} for name in handlers
                ]

            logger.info(f"Connected to MCP server '{server_name}' via direct import "
                       f"({len(self._available_tools[server_name])} tools available)")
            return True

        except Exception as e:
            logger.error(f"Direct import of '{module_path}' failed: {e}")
            return False

    async def _connect_stdio(self, server_name: str, config: Dict) -> bool:
        """Connect to a stdio-based MCP server.

        Enters the stdio_client context manager and keeps it alive by storing
        the exit callback.  Cleaned up in disconnect_all().
        """
        if not HAS_MCP:
            return False

        command = config.get('command', '')
        args = config.get('args', [])

        if not command:
            logger.error(f"MCP server '{server_name}' has no command specified")
            return False

        server_params = StdioServerParameters(
            command=command, args=args, env=config.get('env')
        )

        try:
            stdio_cm = stdio_client(server_params)
            read_stream, write_stream = await asyncio.wait_for(
                stdio_cm.__aenter__(), timeout=30
            )

            session = ClientSession(read_stream, write_stream)
            await asyncio.wait_for(session.initialize(), timeout=30)

            tools_result = await session.list_tools()
            self._available_tools[server_name] = [
                {"name": t.name, "description": t.description}
                for t in tools_result.tools
            ]

            self._sessions[server_name] = session
            self._contexts[server_name] = [stdio_cm]
            logger.info(f"Connected to MCP server '{server_name}' via stdio "
                       f"({len(self._available_tools[server_name])} tools available)")
            return True

        except Exception as e:
            logger.error(f"Stdio connection to '{server_name}' failed: {e}")
            return False

    async def _connect_sse(self, server_name: str, config: Dict) -> bool:
        """Connect to an SSE-based MCP server.

        Enters the sse_client context manager and keeps it alive by storing
        the exit callback.  Cleaned up in disconnect_all().
        """
        if not HAS_MCP_SSE:
            logger.error("MCP SSE transport not available")
            return False

        url = config.get('url', '')
        if not url:
            logger.error(f"MCP server '{server_name}' has no URL specified")
            return False

        try:
            sse_cm = sse_client(url)
            read_stream, write_stream = await asyncio.wait_for(
                sse_cm.__aenter__(), timeout=30
            )

            session = ClientSession(read_stream, write_stream)
            await asyncio.wait_for(session.initialize(), timeout=30)

            tools_result = await session.list_tools()
            self._available_tools[server_name] = [
                {"name": t.name, "description": t.description}
                for t in tools_result.tools
            ]

            self._sessions[server_name] = session
            self._contexts[server_name] = [sse_cm]
            logger.info(f"Connected to MCP server '{server_name}' via SSE "
                       f"({len(self._available_tools[server_name])} tools available)")
            return True

        except Exception as e:
            logger.error(f"SSE connection to '{server_name}' failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    async def call_tool(self, server_name: str, tool_name: str,
                         arguments: Optional[Dict] = None) -> Optional[str]:
        """Call a tool on an MCP server.

        Returns the tool result as a JSON string, or None on failure.
        """
        if not self.enabled:
            return None

        session = self._sessions.get(server_name)
        if not session:
            connected = await self.connect(server_name)
            if not connected:
                return None
            session = self._sessions.get(server_name)

        # Direct in-process path — call handler with no protocol overhead
        if session is _DIRECT_SESSION:
            handlers = self._direct_handlers.get(server_name, {})
            handler = handlers.get(tool_name)
            if not handler:
                logger.error(f"Tool '{tool_name}' not found in direct handlers")
                return None
            try:
                result = await handler(arguments or {})
                return json.dumps(result, default=str)
            except Exception as e:
                logger.error(f"Direct tool call failed ({tool_name}): {e}")
                return json.dumps({"error": str(e)})

        # MCP protocol path (stdio / SSE)
        try:
            result = await session.call_tool(tool_name, arguments or {})
            if result.content:
                texts = [c.text for c in result.content if hasattr(c, 'text')]
                return '\n'.join(texts) if texts else str(result.content)
            return ""

        except Exception as e:
            logger.error(f"MCP tool call failed ({server_name}/{tool_name}): {e}")
            return None

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def list_tools(self, server_name: str = None) -> Dict[str, List[Dict]]:
        """List available tools from MCP servers."""
        if server_name:
            return {server_name: self._available_tools.get(server_name, [])}
        return dict(self._available_tools)

    def find_tool_server(self, tool_name: str) -> Optional[str]:
        """Find which MCP server provides a given tool."""
        for server_name, tools in self._available_tools.items():
            for tool in tools:
                if tool["name"] == tool_name:
                    return server_name
        return None

    async def try_tool(self, tool_name: str, arguments: Optional[Dict] = None) -> Optional[str]:
        """Try to execute a tool via any available MCP server.

        Searches all configured servers for the tool and executes it.
        Returns None silently if no server has the tool (for fallback pattern).
        """
        if not self.enabled:
            return None

        # Connect to any servers not yet connected
        for server_name in self.servers_config:
            if server_name not in self._sessions:
                await self.connect(server_name)

        server = self.find_tool_server(tool_name)
        if server:
            return await self.call_tool(server, tool_name, arguments)

        return None  # Silent fallback

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def disconnect_all(self):
        """Disconnect from all MCP servers and clean up transport contexts."""
        for server_name in list(self._sessions.keys()):
            session = self._sessions.pop(server_name, None)

            # Direct sessions have no transport to clean up
            if session is _DIRECT_SESSION:
                self._direct_handlers.pop(server_name, None)
                continue

            # Close MCP session
            if session and hasattr(session, 'close'):
                try:
                    await session.close()
                except Exception as e:
                    logger.debug(f"Error closing MCP session '{server_name}': {e}")

            # Exit transport context managers
            for cm in self._contexts.pop(server_name, []):
                try:
                    await cm.__aexit__(None, None, None)
                except Exception as e:
                    logger.debug(f"Error closing MCP transport '{server_name}': {e}")

        self._available_tools.clear()
        logger.info("Disconnected from all MCP servers")
