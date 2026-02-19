"""HTTP request tool for the LLM-driven agent.

Wraps the existing RequestEngine for resilient HTTP requests with
retry, circuit breaker, and response formatting.
"""

import json
import logging
import time
from typing import Any, Dict

logger = logging.getLogger(__name__)

MAX_RESPONSE_BODY = 30 * 1024  # 30KB


async def handle_http_request(args: Dict[str, Any], context: Any) -> str:
    """Execute an HTTP request and return formatted response.

    Args:
        args: {"method", "url", "headers", "body", "follow_redirects"}
        context: ExecutionContext.

    Returns:
        Formatted HTTP response (status, headers, body).
    """
    method = args.get("method", "GET").upper()
    url = args.get("url", "")
    headers = args.get("headers", {})
    body = args.get("body")
    follow_redirects = args.get("follow_redirects", True)

    # Merge auth headers from context (tool args override)
    if hasattr(context, 'get_auth_headers'):
        label = args.get("credential_label")
        auth_headers = context.get_auth_headers(label=label)
        if auth_headers:
            headers = {**auth_headers, **headers}

    if not url:
        return "Error: URL is required"

    logger.info(f"[HTTP] {method} {url}")

    try:
        # Try using the existing RequestEngine
        response = await _request_with_engine(method, url, headers, body, follow_redirects)
        return response
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"RequestEngine failed, using aiohttp: {e}")

    try:
        # Fall back to aiohttp
        response = await _request_with_aiohttp(method, url, headers, body, follow_redirects)
        return response
    except Exception as e:
        return f"HTTP request failed: {type(e).__name__}: {str(e)}"


async def _request_with_engine(
    method: str, url: str, headers: Dict, body: str, follow_redirects: bool
) -> str:
    """Use the existing RequestEngine for the HTTP request."""
    import aiohttp
    from backend.core.request_engine import RequestEngine

    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(ssl=False)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        engine = RequestEngine(session=session, default_timeout=30)

        kwargs: Dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": headers,
            "allow_redirects": follow_redirects,
            "timeout": 30,
        }

        if body and method in ("POST", "PUT", "PATCH"):
            content_type = headers.get("Content-Type", headers.get("content-type", ""))
            if "json" in content_type:
                try:
                    kwargs["json_data"] = json.loads(body)
                except (json.JSONDecodeError, TypeError):
                    kwargs["data"] = body
            else:
                kwargs["data"] = body

        response = await engine.request(**kwargs)

        if response is None:
            raise RuntimeError("RequestEngine returned None (total failure)")

        return _format_response(
            status=response.status,
            headers=response.headers if response.headers else {},
            body=response.body if response.body else "",
            url=url,
            method=method,
        )


async def _request_with_aiohttp(
    method: str, url: str, headers: Dict, body: str, follow_redirects: bool
) -> str:
    """Use aiohttp directly for the HTTP request."""
    import aiohttp

    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(ssl=False)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        kwargs: Dict[str, Any] = {
            "headers": headers,
            "allow_redirects": follow_redirects,
        }

        if body and method in ("POST", "PUT", "PATCH"):
            content_type = headers.get("Content-Type", headers.get("content-type", ""))
            if "json" in content_type:
                try:
                    kwargs["json"] = json.loads(body)
                except (json.JSONDecodeError, TypeError):
                    kwargs["data"] = body
            else:
                kwargs["data"] = body

        async with session.request(method, url, **kwargs) as response:
            response_body = await response.text()
            response_headers = dict(response.headers)

            return _format_response(
                status=response.status,
                headers=response_headers,
                body=response_body,
                url=str(response.url),
                method=method,
            )


def _format_response(
    status: int, headers: Dict, body: str, url: str, method: str
) -> str:
    """Format an HTTP response for the LLM."""
    lines = [
        f"HTTP {status} — {method} {url}",
        "",
        "Response Headers:",
    ]

    # Include relevant headers
    interesting_headers = {
        "content-type", "server", "x-powered-by", "set-cookie",
        "location", "www-authenticate", "access-control-allow-origin",
        "x-frame-options", "content-security-policy", "x-csrf-token",
        "authorization", "x-request-id",
    }

    for key, value in sorted(headers.items()):
        if key.lower() in interesting_headers:
            lines.append(f"  {key}: {value}")

    lines.append("")
    lines.append("Response Body:")

    # Truncate body if needed
    if len(body) > MAX_RESPONSE_BODY:
        body = body[:MAX_RESPONSE_BODY] + "\n\n[BODY TRUNCATED — 30KB limit]"

    lines.append(body)

    return "\n".join(lines)
