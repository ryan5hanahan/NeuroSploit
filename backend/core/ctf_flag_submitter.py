"""
NeuroSploit v3 - CTF Flag Submitter

Auto-submit captured flags to a CTF platform's submission endpoint.
Supports common CTF platform APIs (CTFd, HTB, THM, etc.) by trying
multiple common request body formats.
"""
import aiohttp
from typing import List, Dict

from backend.core.ctf_flag_detector import CapturedFlag


class CTFFlagSubmitter:
    """Auto-submit captured flags to a CTF platform's submission endpoint."""

    def __init__(self, submit_url: str, platform_token: str = ""):
        self.submit_url = submit_url.rstrip("/")
        self.platform_token = platform_token

    async def submit_flag(
        self, flag_value: str, session: aiohttp.ClientSession
    ) -> Dict:
        """Submit a single flag. Returns {"success": bool, "message": str, "flag_value": str}."""
        if not self.submit_url:
            return {"success": False, "message": "No submit URL configured", "flag_value": flag_value}

        headers = {"User-Agent": "NeuroSploit/3.0"}
        if self.platform_token:
            headers["Authorization"] = f"Bearer {self.platform_token}"

        # Try common submission body formats in order
        json_payloads = [
            {"flag": flag_value},
            {"answer": flag_value},
            {"submission": flag_value},
            {"key": flag_value},
        ]

        for payload in json_payloads:
            try:
                async with session.post(
                    self.submit_url,
                    json=payload,
                    headers=headers,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    body = await resp.text()
                    if resp.status in (200, 201):
                        body_lower = body.lower()
                        if any(k in body_lower for k in ("correct", "success", "accepted", "solved", "already")):
                            return {"success": True, "message": body[:200], "flag_value": flag_value}
                    # 4xx with "already" means previously submitted (still counts)
                    if resp.status in (200, 201, 400) and "already" in body.lower():
                        return {"success": True, "message": f"Already submitted: {body[:200]}", "flag_value": flag_value}
            except Exception:
                continue

        # Fallback: try form-encoded
        try:
            async with session.post(
                self.submit_url,
                data={"flag": flag_value},
                headers=headers,
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                body = await resp.text()
                if resp.status in (200, 201):
                    body_lower = body.lower()
                    if any(k in body_lower for k in ("correct", "success", "accepted", "solved", "already")):
                        return {"success": True, "message": body[:200], "flag_value": flag_value}
        except Exception:
            pass

        return {"success": False, "message": "Flag not accepted by platform", "flag_value": flag_value}

    async def submit_all(
        self, flags: List[CapturedFlag], session: aiohttp.ClientSession
    ) -> List[Dict]:
        """Submit all captured flags. Returns results per flag."""
        if not self.submit_url or not flags:
            return []

        results = []
        for flag in flags:
            result = await self.submit_flag(flag.flag_value, session)
            results.append(result)
        return results
