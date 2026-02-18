"""Tool adapter — converts MCP tool schemas to provider-native formats."""

import json
from typing import Any, Dict, List, Optional


class ToolAdapter:
    """Converts MCP tool definitions to provider-specific tool formats.

    MCP tools already have JSON Schema inputSchema, which maps closely
    to Claude's tool format. This adapter handles the translation layer
    for all providers.
    """

    @staticmethod
    def mcp_to_claude(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert MCP tools to Claude Messages API tool format.

        MCP format:
            {"name": "...", "description": "...", "inputSchema": {...}}
        Claude format:
            {"name": "...", "description": "...", "input_schema": {...}}
        """
        claude_tools = []
        for tool in tools:
            claude_tools.append({
                "name": tool["name"],
                "description": tool.get("description", ""),
                "input_schema": tool.get("inputSchema", {"type": "object", "properties": {}}),
            })
        return claude_tools

    @staticmethod
    def mcp_to_openai(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert MCP tools to OpenAI function calling format.

        OpenAI format:
            {"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}
        """
        openai_tools = []
        for tool in tools:
            schema = tool.get("inputSchema", {"type": "object", "properties": {}})
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": schema,
                },
            })
        return openai_tools

    @staticmethod
    def mcp_to_bedrock(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert MCP tools to Bedrock Converse API tool format.

        Bedrock format:
            {"toolSpec": {"name": "...", "description": "...", "inputSchema": {"json": {...}}}}
        """
        bedrock_tools = []
        for tool in tools:
            schema = tool.get("inputSchema", {"type": "object", "properties": {}})
            bedrock_tools.append({
                "toolSpec": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "inputSchema": {"json": schema},
                }
            })
        return bedrock_tools

    @staticmethod
    def mcp_to_json_prompt(tools: List[Dict[str, Any]]) -> str:
        """Render tool schemas as prompt text for providers without native tool calling.

        Used for Ollama, LM Studio, and any fallback providers. The LLM responds
        with a JSON object specifying which tool to call.
        """
        lines = ["You have access to the following tools:\n"]

        for tool in tools:
            name = tool["name"]
            desc = tool.get("description", "No description")
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {})
            required = schema.get("required", [])

            lines.append(f"### {name}")
            lines.append(f"{desc}\n")

            if props:
                lines.append("Parameters:")
                for pname, pdef in props.items():
                    ptype = pdef.get("type", "any")
                    pdesc = pdef.get("description", "")
                    req = " (required)" if pname in required else ""
                    lines.append(f"  - {pname}: {ptype}{req} — {pdesc}")

            lines.append("")

        lines.append(
            "To use a tool, respond with a JSON object:\n"
            '{"tool": "tool_name", "arguments": {<parameters>}}\n\n'
            "If you don't need a tool, respond normally."
        )
        return "\n".join(lines)

    @staticmethod
    def tool_result_to_claude(tool_call_id: str, content: str, is_error: bool = False) -> Dict[str, Any]:
        """Format a tool result for Claude's multi-turn tool use."""
        return {
            "type": "tool_result",
            "tool_use_id": tool_call_id,
            "content": content,
            **({"is_error": True} if is_error else {}),
        }

    @staticmethod
    def tool_result_to_openai(tool_call_id: str, content: str) -> Dict[str, Any]:
        """Format a tool result for OpenAI's function calling."""
        return {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": content,
        }

    @staticmethod
    def for_provider(
        provider_name: str,
        tools: List[Dict[str, Any]],
    ) -> Optional[Any]:
        """Convert tools for a specific provider. Returns None if provider
        doesn't support native tools (use mcp_to_json_prompt instead)."""
        converters = {
            "anthropic": ToolAdapter.mcp_to_claude,
            "openai": ToolAdapter.mcp_to_openai,
            "bedrock": ToolAdapter.mcp_to_bedrock,
        }
        converter = converters.get(provider_name)
        if converter:
            return converter(tools)
        return None
