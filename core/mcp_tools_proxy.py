"""
NeuroSploit v3 - mitmproxy MCP Tool Handlers

Communicates with mitmproxy's REST API at http://neurosploit-mitmproxy:8082.
Provides flow inspection, capture control, replay, and export.

Start mitmproxy with: docker compose --profile proxy up -d
"""

import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

MITMPROXY_API = "http://neurosploit-mitmproxy:8082"
MITMPROXY_LOCAL = "http://localhost:8082"


async def _proxy_request(
    path: str, method: str = "GET", data: Any = None
) -> Dict:
    """Make an HTTP request to the mitmproxy REST API."""
    import aiohttp

    # Try internal Docker network first, fall back to localhost
    for base_url in [MITMPROXY_API, MITMPROXY_LOCAL]:
        url = f"{base_url}{path}"
        try:
            async with aiohttp.ClientSession() as session:
                kwargs = {"timeout": aiohttp.ClientTimeout(total=10)}
                if data is not None:
                    kwargs["json"] = data

                if method == "GET":
                    async with session.get(url, **kwargs) as resp:
                        if resp.content_type == "application/json":
                            return await resp.json()
                        return {"text": await resp.text(), "status": resp.status}
                elif method == "PUT":
                    async with session.put(url, **kwargs) as resp:
                        if resp.content_type == "application/json":
                            return await resp.json()
                        return {"text": await resp.text(), "status": resp.status}
                elif method == "DELETE":
                    async with session.delete(url, **kwargs) as resp:
                        return {"status": resp.status}
                elif method == "POST":
                    async with session.post(url, **kwargs) as resp:
                        if resp.content_type == "application/json":
                            return await resp.json()
                        return {"text": await resp.text(), "status": resp.status}
        except Exception:
            continue

    return {"error": "mitmproxy not reachable. Start with: docker compose --profile proxy up -d"}


async def _is_proxy_up() -> bool:
    """Quick check if mitmproxy API is reachable."""
    result = await _proxy_request("/flows")
    return "error" not in result


# ---------------------------------------------------------------------------
# proxy_status - Health and stats
# ---------------------------------------------------------------------------
async def _proxy_status() -> Dict:
    """Check mitmproxy health, flow count, and connection info."""
    flows = await _proxy_request("/flows")
    if "error" in flows:
        return {
            "status": "offline",
            "error": flows["error"],
            "proxy_address": "http://neurosploit-mitmproxy:8081",
            "web_ui": "http://localhost:8082",
            "start_command": "docker compose --profile proxy up -d",
        }

    flow_count = len(flows) if isinstance(flows, list) else 0
    return {
        "status": "online",
        "flow_count": flow_count,
        "proxy_address": "http://neurosploit-mitmproxy:8081",
        "web_ui": "http://localhost:8082",
    }


# ---------------------------------------------------------------------------
# proxy_flows - Retrieve captured flows
# ---------------------------------------------------------------------------
async def _proxy_flows(
    filter_expr: Optional[str] = None,
    limit: int = 50,
) -> Dict:
    """Retrieve captured HTTP flows from mitmproxy."""
    flows = await _proxy_request("/flows")
    if "error" in flows:
        return flows
    if not isinstance(flows, list):
        return {"error": "Unexpected response from mitmproxy", "raw": str(flows)[:500]}

    # Apply limit
    flows = flows[-limit:] if len(flows) > limit else flows

    results = []
    for flow in flows:
        req = flow.get("request", {})
        resp = flow.get("response", {})

        entry = {
            "id": flow.get("id", ""),
            "method": req.get("method", ""),
            "url": req.get("pretty_url", req.get("url", "")),
            "status_code": resp.get("status_code", 0),
            "content_length": resp.get("content_length", 0),
            "timestamp": req.get("timestamp_start", 0),
        }

        # Simple text filter
        if filter_expr:
            match_str = f"{entry['method']} {entry['url']} {entry['status_code']}"
            if filter_expr.lower() not in match_str.lower():
                continue

        results.append(entry)

    return {
        "flows": results,
        "count": len(results),
        "total_captured": len(flows),
    }


# ---------------------------------------------------------------------------
# proxy_capture - Configure capture filter
# ---------------------------------------------------------------------------
async def _proxy_capture(filter_expr: str = "") -> Dict:
    """Set or clear the mitmproxy view filter for capturing flows."""
    if filter_expr:
        result = await _proxy_request(
            "/options", method="PUT",
            data={"view_filter": filter_expr}
        )
    else:
        result = await _proxy_request(
            "/options", method="PUT",
            data={"view_filter": ""}
        )

    if "error" in result:
        return result

    return {
        "status": "ok",
        "filter": filter_expr or "(all traffic)",
    }


# ---------------------------------------------------------------------------
# proxy_replay - Replay a captured flow
# ---------------------------------------------------------------------------
async def _proxy_replay(
    flow_id: str,
    modify_headers: Optional[Dict[str, str]] = None,
    modify_body: Optional[str] = None,
) -> Dict:
    """Replay a captured flow, optionally with modifications."""
    if not flow_id:
        return {"error": "flow_id is required"}

    # Modify flow before replay if needed
    if modify_headers or modify_body:
        flow = await _proxy_request(f"/flows/{flow_id}")
        if "error" in flow:
            return flow

        updates = {}
        if modify_headers:
            req = flow.get("request", {})
            headers = req.get("headers", [])
            for key, value in modify_headers.items():
                found = False
                for i, (k, v) in enumerate(headers):
                    if k.lower() == key.lower():
                        headers[i] = [key, value]
                        found = True
                        break
                if not found:
                    headers.append([key, value])
            updates["request"] = {"headers": headers}

        if modify_body:
            updates.setdefault("request", {})["content"] = modify_body

        if updates:
            await _proxy_request(f"/flows/{flow_id}", method="PUT", data=updates)

    # Trigger replay
    result = await _proxy_request(f"/flows/{flow_id}/replay", method="POST")

    if "error" in result:
        return result

    return {
        "status": "replayed",
        "flow_id": flow_id,
        "modified_headers": bool(modify_headers),
        "modified_body": bool(modify_body),
    }


# ---------------------------------------------------------------------------
# proxy_intercept - Set/clear intercept breakpoints
# ---------------------------------------------------------------------------
async def _proxy_intercept(
    pattern: str = "",
    enabled: bool = True,
) -> Dict:
    """Set or clear mitmproxy intercept filter. Matching flows will be paused."""
    if enabled and pattern:
        result = await _proxy_request(
            "/options", method="PUT",
            data={"intercept": pattern}
        )
    else:
        result = await _proxy_request(
            "/options", method="PUT",
            data={"intercept": ""}
        )

    if "error" in result:
        return result

    return {
        "status": "ok",
        "intercept_enabled": enabled and bool(pattern),
        "pattern": pattern if enabled else "(disabled)",
    }


# ---------------------------------------------------------------------------
# proxy_clear - Clear all captured flows
# ---------------------------------------------------------------------------
async def _proxy_clear() -> Dict:
    """Clear all captured flows from mitmproxy."""
    result = await _proxy_request("/flows", method="DELETE")
    if "error" in result:
        return result

    return {"status": "cleared"}


# ---------------------------------------------------------------------------
# proxy_export - Export a flow as curl or HAR
# ---------------------------------------------------------------------------
async def _proxy_export(
    flow_id: str,
    format: str = "curl",
) -> Dict:
    """Export a captured flow as curl command or raw request/response."""
    if not flow_id:
        return {"error": "flow_id is required"}

    flow = await _proxy_request(f"/flows/{flow_id}")
    if "error" in flow:
        return flow
    if not isinstance(flow, dict) or "request" not in flow:
        return {"error": f"Flow {flow_id} not found"}

    req = flow.get("request", {})
    resp = flow.get("response", {})

    if format == "curl":
        # Build curl command
        method = req.get("method", "GET")
        url = req.get("pretty_url", req.get("url", ""))
        headers = req.get("headers", [])
        content = req.get("content", "")

        parts = [f"curl -X {method}"]
        for k, v in headers:
            if k.lower() not in ("host", "content-length"):
                parts.append(f"-H '{k}: {v}'")
        if content:
            parts.append(f"-d '{content}'")
        parts.append(f"'{url}'")

        return {
            "flow_id": flow_id,
            "format": "curl",
            "command": " \\\n  ".join(parts),
        }
    else:
        # Raw request/response format
        return {
            "flow_id": flow_id,
            "format": "raw",
            "request": {
                "method": req.get("method", ""),
                "url": req.get("pretty_url", ""),
                "headers": req.get("headers", []),
                "content": (req.get("content", "") or "")[:5000],
            },
            "response": {
                "status_code": resp.get("status_code", 0),
                "headers": resp.get("headers", []),
                "content": (resp.get("content", "") or "")[:5000],
            },
        }
