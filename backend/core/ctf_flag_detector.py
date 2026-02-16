"""
NeuroSploit v3 - CTF Flag Detector

Centralized pattern registry for detecting CTF flags across platforms:
NetWars, HackTheBox, TryHackMe, PortSwigger, PicoCTF, and generic formats.
"""
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict


# Built-in flag patterns keyed by platform
BUILTIN_FLAG_PATTERNS: Dict[str, List[re.Pattern]] = {
    "netwars": [
        re.compile(r'(?:flag|FLAG)\{[^\}]{1,200}\}'),
    ],
    "htb": [
        re.compile(r'HTB\{[^\}]{1,200}\}'),
        re.compile(r'(?<![a-fA-F0-9])[a-f0-9]{32}(?![a-fA-F0-9])'),       # bare 32-char MD5 hex
        re.compile(r'(?<![a-fA-F0-9])[a-f0-9]{64}(?![a-fA-F0-9])'),       # bare 64-char SHA256 hex
    ],
    "tryhackme": [
        re.compile(r'[Tt][Hh][Mm]\{[^\}]{1,200}\}'),
    ],
    "portswigger": [
        re.compile(r'Congratulations,?\s+you\s+solved\s+the\s+lab', re.IGNORECASE),
        re.compile(r'class\s*=\s*["\']congratulations-message["\']', re.IGNORECASE),
    ],
    "picoctf": [
        re.compile(r'picoCTF\{[^\}]{1,200}\}'),
    ],
    "generic": [
        re.compile(r'[Cc][Tt][Ff]\{[^\}]{1,200}\}'),
    ],
}


@dataclass
class CapturedFlag:
    flag_value: str
    platform: str
    source: str             # body, header, log
    found_in_url: str = ""
    found_in_field: str = ""
    request_method: str = ""
    request_payload: str = ""
    timestamp: str = ""
    finding_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class CTFFlagDetector:
    """Scans HTTP responses and log messages for CTF flag patterns."""

    def __init__(self, custom_patterns: Optional[List[str]] = None):
        self.patterns: Dict[str, List[re.Pattern]] = dict(BUILTIN_FLAG_PATTERNS)
        self._seen_flags: set = set()
        self.captured_flags: List[CapturedFlag] = []
        self.start_time: float = time.time()
        self.first_flag_time: Optional[float] = None
        self._flag_timeline: List[dict] = []

        # Compile user-supplied custom regexes
        if custom_patterns:
            compiled = []
            for pat_str in custom_patterns:
                pat_str = pat_str.strip()
                if pat_str:
                    try:
                        compiled.append(re.compile(pat_str))
                    except re.error:
                        pass  # skip invalid regex
            if compiled:
                self.patterns["custom"] = compiled

    def scan_response(
        self,
        response_dict: dict,
        request_url: str = "",
        method: str = "",
        payload: str = "",
    ) -> List[CapturedFlag]:
        """Scan an HTTP response (body + headers) for flag patterns.

        Args:
            response_dict: dict with 'body' (str) and optionally 'headers' (dict)
            request_url: the URL that produced this response
            method: HTTP method used
            payload: the payload that triggered the response

        Returns:
            List of newly captured (non-duplicate) flags
        """
        new_flags: List[CapturedFlag] = []
        body = str(response_dict.get("body", "") or "")
        headers = response_dict.get("headers", {}) or {}

        # Scan body
        for platform, patterns in self.patterns.items():
            for pat in patterns:
                for match in pat.finditer(body):
                    flag_val = match.group(0)
                    if flag_val not in self._seen_flags:
                        self._seen_flags.add(flag_val)
                        captured = CapturedFlag(
                            flag_value=flag_val,
                            platform=platform,
                            source="body",
                            found_in_url=request_url,
                            found_in_field="response_body",
                            request_method=method,
                            request_payload=payload[:500] if payload else "",
                            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        )
                        new_flags.append(captured)

        # Scan headers
        for hdr_name, hdr_val in headers.items():
            hdr_val_str = str(hdr_val)
            for platform, patterns in self.patterns.items():
                for pat in patterns:
                    for match in pat.finditer(hdr_val_str):
                        flag_val = match.group(0)
                        if flag_val not in self._seen_flags:
                            self._seen_flags.add(flag_val)
                            captured = CapturedFlag(
                                flag_value=flag_val,
                                platform=platform,
                                source="header",
                                found_in_url=request_url,
                                found_in_field=hdr_name,
                                request_method=method,
                                request_payload=payload[:500] if payload else "",
                                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            )
                            new_flags.append(captured)

        # Track first flag time and timeline
        if new_flags:
            now = time.time()
            if self.first_flag_time is None:
                self.first_flag_time = now
            for f in new_flags:
                self.captured_flags.append(f)
                self._flag_timeline.append({
                    "flag": f.flag_value[:80],
                    "platform": f.platform,
                    "elapsed_seconds": round(now - self.start_time, 2),
                })

        return new_flags

    def scan_text(self, text: str, source: str = "log", url: str = "") -> List[CapturedFlag]:
        """Scan arbitrary text (e.g. log messages) for flag patterns.

        Returns:
            List of newly captured (non-duplicate) flags
        """
        new_flags: List[CapturedFlag] = []
        for platform, patterns in self.patterns.items():
            for pat in patterns:
                for match in pat.finditer(text):
                    flag_val = match.group(0)
                    if flag_val not in self._seen_flags:
                        self._seen_flags.add(flag_val)
                        captured = CapturedFlag(
                            flag_value=flag_val,
                            platform=platform,
                            source=source,
                            found_in_url=url,
                            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        )
                        new_flags.append(captured)
                        self.captured_flags.append(captured)

        if new_flags and self.first_flag_time is None:
            self.first_flag_time = time.time()
            for f in new_flags:
                self._flag_timeline.append({
                    "flag": f.flag_value[:80],
                    "platform": f.platform,
                    "elapsed_seconds": round(time.time() - self.start_time, 2),
                })

        return new_flags

    def get_metrics(self) -> dict:
        elapsed = round(time.time() - self.start_time, 2)
        ttff = round(self.first_flag_time - self.start_time, 2) if self.first_flag_time else None
        platforms = set(f.platform for f in self.captured_flags)
        return {
            "flags_captured": len(self.captured_flags),
            "unique_platforms": list(platforms),
            "time_to_first_flag": ttff,
            "elapsed_seconds": elapsed,
            "flag_timeline": self._flag_timeline,
        }

    def to_serializable(self) -> List[dict]:
        return [f.to_dict() for f in self.captured_flags]
