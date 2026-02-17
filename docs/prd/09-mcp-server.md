# MCP Server

## Overview

NeuroSploit exposes pentest tools via the Model Context Protocol (MCP), enabling external LLM agents (Claude Desktop, Cursor, etc.) to invoke NeuroSploit's capabilities through a standardized tool interface. The MCP server surfaces core scanning tools, sandboxed security scanners, and proxy controls.

## Transport

| Transport | Activation | Description |
|-----------|-----------|-------------|
| stdio (default) | Standard invocation | Communication over standard input/output |
| SSE | `MCP_TRANSPORT=sse` env var | Server-Sent Events over HTTP |

Configuration in `config.json`: `mcp_servers.servers.neurosploit_tools` with `"transport": "direct"`.

## Tools

### Core Tools (8)

| Tool | Description | Requirements |
|------|-------------|-------------|
| `screenshot_capture` | Capture a screenshot of a URL using Playwright | `ENABLE_BROWSER_VALIDATION` |
| `payload_delivery` | Deliver a test payload to a target URL and analyze the response | None |
| `dns_lookup` | Perform DNS lookups (A, AAAA, MX, TXT, CNAME, NS records) | None |
| `port_scan` | Scan ports on a target host | None |
| `technology_detect` | Detect web technologies and frameworks on a URL | None |
| `subdomain_enumerate` | Enumerate subdomains for a domain | None |
| `save_finding` | Save a vulnerability finding to the database | None |
| `get_vuln_prompt` | Get an AI testing prompt for a specific vulnerability type | None |

### Sandbox Tools (4)

| Tool | Description | Requirements |
|------|-------------|-------------|
| `execute_nuclei` | Run Nuclei vulnerability scanner in Docker sandbox | Docker, neurosploit-kali image |
| `execute_naabu` | Run Naabu port scanner in Docker sandbox | Docker, neurosploit-kali image |
| `sandbox_health` | Check sandbox container health status | Docker |
| `sandbox_exec` | Execute arbitrary commands in the Kali sandbox container | Docker, neurosploit-kali image |

### ProjectDiscovery Extended Tools (9)

| Tool | Description |
|------|-------------|
| `execute_cvemap` | CVE mapping and enrichment |
| `execute_tlsx` | TLS/SSL analysis |
| `execute_asnmap` | ASN mapping |
| `execute_mapcidr` | CIDR range operations |
| `execute_alterx` | Subdomain wordlist generation |
| `execute_shuffledns` | Mass DNS resolution |
| `execute_cloudlist` | Cloud asset enumeration |
| `execute_interactsh` | Out-of-band interaction server |
| `execute_notify` | Send notifications |

### Proxy Tools (7)

| Tool | Description |
|------|-------------|
| `proxy_status` | Check mitmproxy status |
| `proxy_flows` | List captured HTTP flows |
| `proxy_capture` | Start/stop traffic capture |
| `proxy_replay` | Replay captured requests |
| `proxy_intercept` | Set intercept rules |
| `proxy_clear` | Clear captured flows |
| `proxy_export` | Export captured traffic |

## Usage

```bash
# stdio transport (default)
python3 -m core.mcp_server

# SSE transport
MCP_TRANSPORT=sse python3 -m core.mcp_server
```

## Configuration

MCP servers are enabled in `config.json`:

```json
{
  "mcp_servers": {
    "enabled": true,
    "servers": {
      "neurosploit_tools": {
        "transport": "direct"
      }
    }
  }
}
```

## Integration with External Agents

External LLM agents connect to the MCP server and receive a tool manifest listing all available tools with their parameter schemas. The agent can then invoke tools by name with appropriate arguments. Results are returned as structured JSON.

For Claude Desktop integration, the MCP server is registered in the Claude Desktop MCP configuration file pointing to the NeuroSploit `core.mcp_server` module.

## Limitations

- Sandbox tools require Docker and the `neurosploit-kali` image to be built and available.
- Proxy tools require the mitmproxy container to be running (`docker compose --profile proxy up`).
- Screenshot capture requires Playwright and Chromium installed in the environment.
- No authentication or authorization on MCP tools -- any connected agent has full access to all tools.
