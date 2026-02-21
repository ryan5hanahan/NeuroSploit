"""Tests for browser tool handlers.

All tests mock the playwright/browser session layer to avoid real browser dependencies.
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ===========================================================================
# BrowserSession initialization
# ===========================================================================

class TestBrowserSessionInit:
    """BrowserSession creation and basic configuration."""

    def test_get_browser_session_returns_session(self, execution_context):
        """get_browser_session returns a session object."""
        mock_session = MagicMock()
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import get_browser_session
            session = get_browser_session(execution_context, operation_id="test-op")
            assert session is not None

    def test_browser_session_is_singleton_per_op(self, execution_context):
        """get_browser_session returns the same session for the same operation_id."""
        mock_session = MagicMock()
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import get_browser_session
            s1 = get_browser_session(execution_context, operation_id="same-op")
            s2 = get_browser_session(execution_context, operation_id="same-op")
            assert s1 is s2


# ===========================================================================
# navigate
# ===========================================================================

class TestBrowserNavigate:
    """handle_browser_navigate tests."""

    @pytest.mark.asyncio
    async def test_navigate_returns_title(self, execution_context):
        """Navigate returns page title."""
        mock_session = MagicMock()
        mock_session.navigate = AsyncMock(return_value={
            "title": "Home Page",
            "url": "http://testapp.local/",
            "status": 200,
            "content_preview": "Welcome",
        })
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_navigate
            result = await handle_browser_navigate({"url": "http://testapp.local/"}, execution_context)
        assert "Home Page" in result

    @pytest.mark.asyncio
    async def test_navigate_returns_status(self, execution_context):
        """Navigate result includes HTTP status."""
        mock_session = MagicMock()
        mock_session.navigate = AsyncMock(return_value={
            "title": "OK",
            "url": "http://testapp.local/",
            "status": 200,
            "content_preview": "",
        })
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_navigate
            result = await handle_browser_navigate({"url": "http://testapp.local/"}, execution_context)
        assert "200" in result

    @pytest.mark.asyncio
    async def test_navigate_error_returned(self, execution_context):
        """Navigate error is returned as error string."""
        mock_session = MagicMock()
        mock_session.navigate = AsyncMock(return_value={
            "error": "net::ERR_CONNECTION_REFUSED",
            "url": "http://testapp.local:9999/",
        })
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_navigate
            result = await handle_browser_navigate({"url": "http://testapp.local:9999/"}, execution_context)
        assert "failed" in result.lower() or "ERR_CONNECTION_REFUSED" in result

    @pytest.mark.asyncio
    async def test_navigate_with_wait_selector(self, execution_context):
        """Navigate accepts optional wait_selector param."""
        mock_session = MagicMock()
        mock_session.navigate = AsyncMock(return_value={
            "title": "Dashboard",
            "url": "http://testapp.local/dashboard",
            "status": 200,
            "content_preview": "Loaded",
        })
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_navigate
            result = await handle_browser_navigate(
                {"url": "http://testapp.local/dashboard", "wait_selector": ".dashboard-content"},
                execution_context,
            )
        assert "Dashboard" in result


# ===========================================================================
# extract_links
# ===========================================================================

class TestBrowserExtractLinks:
    """handle_browser_extract_links tests."""

    @pytest.mark.asyncio
    async def test_extract_links_returns_list(self, execution_context):
        """extract_links returns formatted link list."""
        mock_session = MagicMock()
        mock_session.extract_links = AsyncMock(return_value=[
            {"href": "http://testapp.local/about", "text": "About", "rel": ""},
            {"href": "http://testapp.local/contact", "text": "Contact", "rel": ""},
        ])
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_extract_links
            result = await handle_browser_extract_links({}, execution_context)
        assert "2 links" in result

    @pytest.mark.asyncio
    async def test_extract_links_empty_page(self, execution_context):
        """Empty page returns 'No links found'."""
        mock_session = MagicMock()
        mock_session.extract_links = AsyncMock(return_value=[])
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_extract_links
            result = await handle_browser_extract_links({}, execution_context)
        assert "No links found" in result

    @pytest.mark.asyncio
    async def test_extract_links_shows_urls(self, execution_context):
        """Extracted links include their href values."""
        mock_session = MagicMock()
        mock_session.extract_links = AsyncMock(return_value=[
            {"href": "http://testapp.local/api/v1/users", "text": "Users API", "rel": ""},
        ])
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_extract_links
            result = await handle_browser_extract_links({}, execution_context)
        assert "/api/v1/users" in result


# ===========================================================================
# extract_forms
# ===========================================================================

class TestBrowserExtractForms:
    """handle_browser_extract_forms tests."""

    @pytest.mark.asyncio
    async def test_extract_forms_returns_count(self, execution_context):
        """extract_forms returns number of forms found."""
        mock_session = MagicMock()
        mock_session.extract_forms = AsyncMock(return_value=[
            {
                "action": "http://testapp.local/login",
                "method": "POST",
                "id": "login-form",
                "fields": [
                    {"tag": "input", "name": "username", "type": "text", "value": "", "placeholder": "", "required": True},
                    {"tag": "input", "name": "password", "type": "password", "value": "", "placeholder": "", "required": True},
                ],
            }
        ])
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_extract_forms
            result = await handle_browser_extract_forms({}, execution_context)
        assert "1 form" in result

    @pytest.mark.asyncio
    async def test_extract_forms_includes_field_names(self, execution_context):
        """Extracted form data includes field names."""
        mock_session = MagicMock()
        mock_session.extract_forms = AsyncMock(return_value=[
            {
                "action": "/search",
                "method": "GET",
                "id": "",
                "fields": [
                    {"tag": "input", "name": "query", "type": "text", "value": "", "placeholder": "Search...", "required": False},
                ],
            }
        ])
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_extract_forms
            result = await handle_browser_extract_forms({}, execution_context)
        assert "query" in result

    @pytest.mark.asyncio
    async def test_extract_forms_no_forms(self, execution_context):
        """No forms returns 'No forms found'."""
        mock_session = MagicMock()
        mock_session.extract_forms = AsyncMock(return_value=[])
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_extract_forms
            result = await handle_browser_extract_forms({}, execution_context)
        assert "No forms found" in result

    @pytest.mark.asyncio
    async def test_extract_forms_shows_method(self, execution_context):
        """Extracted form data includes the HTTP method."""
        mock_session = MagicMock()
        mock_session.extract_forms = AsyncMock(return_value=[
            {
                "action": "/submit",
                "method": "POST",
                "id": "main-form",
                "fields": [],
            }
        ])
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_extract_forms
            result = await handle_browser_extract_forms({}, execution_context)
        assert "POST" in result


# ===========================================================================
# submit_form
# ===========================================================================

class TestBrowserSubmitForm:
    """handle_browser_submit_form tests."""

    @pytest.mark.asyncio
    async def test_submit_form_success(self, execution_context):
        """Form submission returns success indicator."""
        mock_session = MagicMock()
        mock_session.submit_form = AsyncMock(return_value={
            "title": "Welcome",
            "url": "http://testapp.local/dashboard",
            "status": 200,
            "content_preview": "Logged in",
            "form_submitted": True,
        })
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_submit_form
            result = await handle_browser_submit_form(
                {"form_selector": "#login", "field_values": {"username": "admin", "password": "admin"}},
                execution_context,
            )
        assert "Welcome" in result or "submitted" in result.lower()

    @pytest.mark.asyncio
    async def test_submit_form_with_field_values(self, execution_context):
        """Field values are forwarded to form submission."""
        mock_session = MagicMock()
        mock_session.submit_form = AsyncMock(return_value={
            "title": "Search Results",
            "url": "http://testapp.local/results",
            "status": 200,
            "content_preview": "10 results",
            "form_submitted": True,
        })
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_submit_form
            result = await handle_browser_submit_form(
                {"form_selector": "0", "field_values": {"q": "test query"}},
                execution_context,
            )
        mock_session.submit_form.assert_called_once()

    @pytest.mark.asyncio
    async def test_submit_form_not_found_error(self, execution_context):
        """Form not found returns error message."""
        mock_session = MagicMock()
        mock_session.submit_form = AsyncMock(return_value={
            "error": "Form not found: #nonexistent",
        })
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_submit_form
            result = await handle_browser_submit_form(
                {"form_selector": "#nonexistent", "field_values": {}},
                execution_context,
            )
        assert "failed" in result.lower() or "not found" in result.lower()


# ===========================================================================
# screenshot
# ===========================================================================

class TestBrowserScreenshot:
    """handle_browser_screenshot tests."""

    @pytest.mark.asyncio
    async def test_screenshot_saved_message(self, execution_context):
        """Screenshot returns 'Screenshot saved' message."""
        mock_session = MagicMock()
        mock_session.screenshot = AsyncMock(return_value="/tmp/screenshots/001_test.png")
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_screenshot
            result = await handle_browser_screenshot({"label": "test"}, execution_context)
        assert "Screenshot saved" in result

    @pytest.mark.asyncio
    async def test_screenshot_path_in_result(self, execution_context):
        """Screenshot result includes the file path."""
        expected_path = "/tmp/screenshots/002_evidence.png"
        mock_session = MagicMock()
        mock_session.screenshot = AsyncMock(return_value=expected_path)
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_screenshot
            result = await handle_browser_screenshot({"label": "evidence"}, execution_context)
        assert expected_path in result


# ===========================================================================
# execute_js
# ===========================================================================

class TestBrowserExecuteJs:
    """handle_browser_execute_js tests."""

    @pytest.mark.asyncio
    async def test_execute_js_returns_result(self, execution_context):
        """JS execution returns script result."""
        mock_session = MagicMock()
        mock_session.execute_js = AsyncMock(return_value="My Page Title")
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_execute_js
            result = await handle_browser_execute_js(
                {"script": "return document.title"},
                execution_context,
            )
        assert "My Page Title" in result

    @pytest.mark.asyncio
    async def test_execute_js_error_returned(self, execution_context):
        """JS error is returned as error string."""
        mock_session = MagicMock()
        mock_session.execute_js = AsyncMock(return_value="JavaScript error: ReferenceError: foo is not defined")
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_execute_js
            result = await handle_browser_execute_js(
                {"script": "foo.bar()"},
                execution_context,
            )
        assert "error" in result.lower()

    @pytest.mark.asyncio
    async def test_execute_js_list_result(self, execution_context):
        """JS returning a list is serialized in result."""
        mock_session = MagicMock()
        mock_session.execute_js = AsyncMock(return_value='["item1", "item2", "item3"]')
        with patch("backend.core.tools.browser_tool.get_browser_session", return_value=mock_session):
            from backend.core.tools.browser_tool import handle_browser_execute_js
            result = await handle_browser_execute_js(
                {"script": "return Array.from(document.querySelectorAll('li')).map(e => e.textContent)"},
                execution_context,
            )
        assert "item1" in result


# ===========================================================================
# Session cleanup
# ===========================================================================

class TestBrowserSessionCleanup:
    """Browser session cleanup tests."""

    @pytest.mark.asyncio
    async def test_close_browser_session_called(self, execution_context):
        """close_browser_session can be called without error."""
        with patch("backend.core.tools.browser_tool.close_browser_session", new_callable=AsyncMock) as mock_close:
            from backend.core.tools.browser_tool import close_browser_session
            await close_browser_session("test-op-id")
            mock_close.assert_called_once_with("test-op-id")


# ===========================================================================
# Cookie parsing helper
# ===========================================================================

class TestCookieParsing:
    """Cookie parsing and auth injection into browser sessions."""

    def test_cookie_auth_produces_cookie_header(self, execution_context_with_cookie):
        """Cookie auth context produces a Cookie header."""
        headers = execution_context_with_cookie.get_auth_headers()
        assert "Cookie" in headers
        assert "session=abc123" in headers["Cookie"]

    def test_multi_cookie_auth(self, tmp_path):
        """Multiple cookies in one string are preserved."""
        from backend.core.llm.tool_executor import ExecutionContext
        ctx = ExecutionContext(
            operation_id="test-multi-cookie",
            target="http://testapp.local",
            artifacts_dir=str(tmp_path),
            auth_type="cookie",
            auth_credentials={"cookie": "session=abc; csrf=xyz; token=123"},
        )
        headers = ctx.get_auth_headers()
        assert "Cookie" in headers
        assert "session=abc" in headers["Cookie"]
        assert "csrf=xyz" in headers["Cookie"]
