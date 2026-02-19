"""Browser automation tool for the LLM-driven agent.

Extends existing BrowserValidator with session management,
link/form extraction, JavaScript execution, and screenshot capture.
"""

import asyncio
import base64
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class BrowserSession:
    """Manages a persistent Playwright browser session for an operation.

    Maintains browser state (cookies, localStorage) across tool calls
    within a single operation. Handles lifecycle (start/stop) automatically.
    """

    def __init__(self, artifacts_dir: str, auth_headers: Optional[Dict[str, str]] = None):
        self.artifacts_dir = artifacts_dir
        self._auth_headers = auth_headers or {}
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._started = False
        self._screenshot_count = 0

    async def ensure_started(self) -> None:
        """Start the browser if not already running."""
        if self._started and self._page:
            return

        try:
            from playwright.async_api import async_playwright

            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )

            # Separate cookie headers from extra HTTP headers
            extra_headers = {}
            cookie_str = ""
            for key, value in self._auth_headers.items():
                if key.lower() == "cookie":
                    cookie_str = value
                else:
                    extra_headers[key] = value

            context_kwargs: Dict[str, Any] = {
                "viewport": {"width": 1280, "height": 720},
                "user_agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "ignore_https_errors": True,
            }
            if extra_headers:
                context_kwargs["extra_http_headers"] = extra_headers

            self._context = await self._browser.new_context(**context_kwargs)

            # Add cookies if provided
            if cookie_str:
                cookies = _parse_cookies(cookie_str, "")
                if cookies:
                    await self._context.add_cookies(cookies)

            self._page = await self._context.new_page()
            self._started = True
            logger.info("[Browser] Session started")

        except Exception as e:
            logger.error(f"[Browser] Failed to start: {e}")
            raise

    async def close(self) -> None:
        """Close the browser session."""
        try:
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except Exception:
            pass
        finally:
            self._started = False
            self._page = None
            self._context = None
            self._browser = None
            self._playwright = None

    async def navigate(self, url: str) -> Dict[str, Any]:
        """Navigate to a URL and return page info."""
        await self.ensure_started()

        try:
            response = await self._page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await self._page.wait_for_timeout(1000)  # Allow JS to settle

            title = await self._page.title()
            final_url = self._page.url
            status = response.status if response else 0

            # Get page text content (truncated)
            content = await self._page.evaluate("() => document.body?.innerText || ''")
            if len(content) > 5000:
                content = content[:5000] + "\n[CONTENT TRUNCATED]"

            return {
                "title": title,
                "url": final_url,
                "status": status,
                "content_preview": content,
            }

        except Exception as e:
            return {"error": str(e), "url": url}

    async def extract_links(self) -> List[Dict[str, str]]:
        """Extract all links from the current page."""
        await self.ensure_started()

        links = await self._page.evaluate("""() => {
            const links = [];
            document.querySelectorAll('a[href]').forEach(a => {
                links.push({
                    href: a.href,
                    text: a.innerText.trim().substring(0, 100),
                    rel: a.rel || '',
                });
            });
            return links;
        }""")

        return links

    async def extract_forms(self) -> List[Dict[str, Any]]:
        """Extract all forms from the current page."""
        await self.ensure_started()

        forms = await self._page.evaluate("""() => {
            const forms = [];
            document.querySelectorAll('form').forEach(form => {
                const fields = [];
                form.querySelectorAll('input, select, textarea').forEach(el => {
                    fields.push({
                        tag: el.tagName.toLowerCase(),
                        name: el.name || '',
                        type: el.type || '',
                        value: el.value || '',
                        placeholder: el.placeholder || '',
                        required: el.required,
                    });
                });
                forms.push({
                    action: form.action || '',
                    method: (form.method || 'GET').toUpperCase(),
                    id: form.id || '',
                    fields: fields,
                });
            });
            return forms;
        }""")

        return forms

    async def screenshot(self, label: str) -> str:
        """Take a full-page screenshot."""
        await self.ensure_started()

        screenshots_dir = os.path.join(self.artifacts_dir, "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)

        self._screenshot_count += 1
        filename = f"{self._screenshot_count:03d}_{label}.png"
        filepath = os.path.join(screenshots_dir, filename)

        await self._page.screenshot(path=filepath, full_page=True)
        logger.info(f"[Browser] Screenshot saved: {filepath}")

        return filepath

    async def execute_js(self, script: str) -> str:
        """Execute JavaScript in the page context."""
        await self.ensure_started()

        try:
            result = await self._page.evaluate(script)
            if result is None:
                return "null"
            if isinstance(result, (dict, list)):
                return json.dumps(result, indent=2)
            return str(result)
        except Exception as e:
            return f"JavaScript error: {type(e).__name__}: {str(e)}"

    async def get_page_source(self) -> str:
        """Get current page HTML source (truncated)."""
        await self.ensure_started()

        content = await self._page.content()
        if len(content) > 30000:
            content = content[:30000] + "\n<!-- TRUNCATED -->"
        return content


# ---------------------------------------------------------------------------
# Singleton session per operation
# ---------------------------------------------------------------------------

_sessions: Dict[str, BrowserSession] = {}


def _parse_cookies(cookie_str: str, domain: str) -> List[Dict[str, Any]]:
    """Parse a Cookie header string into Playwright cookie objects."""
    cookies = []
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        cookies.append({
            "name": name.strip(),
            "value": value.strip(),
            "domain": domain or "localhost",
            "path": "/",
        })
    return cookies


def get_browser_session(
    operation_id: str,
    artifacts_dir: str,
    auth_headers: Optional[Dict[str, str]] = None,
    credential_label: Optional[str] = None,
) -> BrowserSession:
    """Get or create a browser session for an operation.

    Each credential_label gets its own browser context so cookies/headers
    don't bleed between identities.
    """
    key = f"{operation_id}:{credential_label or 'default'}"
    if key not in _sessions:
        _sessions[key] = BrowserSession(artifacts_dir, auth_headers=auth_headers)
    return _sessions[key]


async def close_browser_session(operation_id: str) -> None:
    """Close and remove all browser sessions for an operation."""
    keys_to_close = [k for k in _sessions if k == operation_id or k.startswith(f"{operation_id}:")]
    for key in keys_to_close:
        session = _sessions.pop(key, None)
        if session:
            await session.close()


# ---------------------------------------------------------------------------
# Tool handler functions (match ToolExecutor handler signature)
# ---------------------------------------------------------------------------

def _get_context_auth_headers(context: Any, label: Optional[str] = None) -> Optional[Dict[str, str]]:
    """Extract auth headers from ExecutionContext if available."""
    if hasattr(context, 'get_auth_headers'):
        headers = context.get_auth_headers(label=label)
        return headers if headers else None
    return None


async def handle_browser_navigate(args: Dict[str, Any], context: Any) -> str:
    """Handle browser_navigate tool call."""
    label = args.get("credential_label")
    session = get_browser_session(
        context.operation_id, context.artifacts_dir,
        auth_headers=_get_context_auth_headers(context, label=label),
        credential_label=label,
    )
    result = await session.navigate(args["url"])

    if "error" in result:
        return f"Navigation failed: {result['error']}"

    return (
        f"Title: {result['title']}\n"
        f"URL: {result['url']}\n"
        f"Status: {result['status']}\n"
        f"Content:\n{result['content_preview']}"
    )


async def handle_browser_extract_links(args: Dict[str, Any], context: Any) -> str:
    """Handle browser_extract_links tool call."""
    session = get_browser_session(
        context.operation_id, context.artifacts_dir,
        auth_headers=_get_context_auth_headers(context),
    )
    links = await session.extract_links()

    if not links:
        return "No links found on the current page."

    lines = [f"Found {len(links)} links:"]
    for link in links[:100]:  # Cap at 100 links
        text = link.get("text", "").strip()
        href = link.get("href", "")
        if text:
            lines.append(f"  [{text}] → {href}")
        else:
            lines.append(f"  {href}")

    if len(links) > 100:
        lines.append(f"  ... and {len(links) - 100} more")

    return "\n".join(lines)


async def handle_browser_extract_forms(args: Dict[str, Any], context: Any) -> str:
    """Handle browser_extract_forms tool call."""
    session = get_browser_session(
        context.operation_id, context.artifacts_dir,
        auth_headers=_get_context_auth_headers(context),
    )
    forms = await session.extract_forms()

    if not forms:
        return "No forms found on the current page."

    lines = [f"Found {len(forms)} form(s):"]
    for i, form in enumerate(forms):
        lines.append(f"\nForm #{i+1}:")
        lines.append(f"  Action: {form.get('action', '(none)')}")
        lines.append(f"  Method: {form.get('method', 'GET')}")

        fields = form.get("fields", [])
        if fields:
            lines.append("  Fields:")
            for field in fields:
                name = field.get("name", "(unnamed)")
                ftype = field.get("type", "text")
                req = " (required)" if field.get("required") else ""
                lines.append(f"    - {name}: {ftype}{req}")

    return "\n".join(lines)


async def handle_browser_screenshot(args: Dict[str, Any], context: Any) -> str:
    """Handle browser_screenshot tool call."""
    session = get_browser_session(
        context.operation_id, context.artifacts_dir,
        auth_headers=_get_context_auth_headers(context),
    )
    label = args.get("label", "screenshot")
    filepath = await session.screenshot(label)
    return f"Screenshot saved: {filepath}"


async def handle_browser_execute_js(args: Dict[str, Any], context: Any) -> str:
    """Handle browser_execute_js tool call."""
    session = get_browser_session(
        context.operation_id, context.artifacts_dir,
        auth_headers=_get_context_auth_headers(context),
    )
    result = await session.execute_js(args["script"])
    return result
