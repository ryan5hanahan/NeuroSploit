"""
NeuroSploit v3 - Command Safety Analyzer

Parses shell commands to detect dangerous patterns, extract targets,
and enforce an allowlist of permitted tool binaries. Provides defense
against trivial bypass of string-pattern blocklists.

Components:
  - CommandAnalyzer: Static analysis of shell command strings
  - CommandDecision: Result of a command safety check
"""

import base64
import ipaddress
import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional, Set, Tuple
from urllib.parse import urlparse, unquote

logger = logging.getLogger(__name__)


@dataclass
class CommandDecision:
    """Result of a command safety analysis."""
    allowed: bool
    reason: str = ""
    extracted_targets: List[str] = field(default_factory=list)
    risk_level: str = "low"  # "low" | "medium" | "high" | "critical"


# ---------------------------------------------------------------------------
# Blocked command patterns (expanded)
# ---------------------------------------------------------------------------

# Exact binary names that are always blocked
BLOCKED_BINARIES: FrozenSet[str] = frozenset({
    "shutdown", "reboot", "halt", "poweroff", "init",
    "mkfs", "fdisk", "parted",
    "mount", "umount",
    "useradd", "userdel", "usermod", "groupadd", "groupdel",
    "visudo", "passwd",
    "systemctl", "service",
    "crontab",
    "iptables", "ip6tables", "nft", "ufw",
})

# Dangerous argument patterns — (binary, regex_on_full_command)
BLOCKED_PATTERNS: List[Tuple[Optional[str], re.Pattern]] = [
    # rm with recursive force on root or wide paths
    ("rm", re.compile(r"rm\s+.*-[rR].*\s+/\s*$|rm\s+.*-[rR].*\s+/\*|rm\s+.*-[rR].*\s+\.\.")),
    ("rm", re.compile(r"rm\s+-rf\s+/")),
    # dd writing to block devices
    ("dd", re.compile(r"dd\s+.*if=.*of=/dev/")),
    # chmod/chown on root
    ("chmod", re.compile(r"chmod\s+.*-[rR].*\s+/")),
    ("chown", re.compile(r"chown\s+.*-[rR].*\s+/")),
    # Fork bomb patterns
    (None, re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;?\s*:")),
    (None, re.compile(r"\.\(\)\s*\{\s*\.\|\.&\s*\}\s*;?\s*\.")),
    # Kill init/PID 1
    ("kill", re.compile(r"kill\s+.*\b1\b")),
    ("kill", re.compile(r"kill\s+-9\s+1\b")),
    # Writing to system files
    (None, re.compile(r">\s*/etc/(passwd|shadow|sudoers|hosts)")),
    (None, re.compile(r"tee\s+/etc/(passwd|shadow|sudoers)")),
    # Kernel manipulation
    (None, re.compile(r"insmod|rmmod|modprobe")),
    (None, re.compile(r"sysctl\s+-w")),
]

# Piping download output to shell execution
PIPE_TO_SHELL: re.Pattern = re.compile(
    r"(curl|wget|fetch)\s+.*\|\s*(sh|bash|zsh|dash|python|python3|perl|ruby|node)\b"
)

# Inline code execution patterns
INLINE_EXEC_PATTERNS: List[re.Pattern] = [
    re.compile(r"python3?\s+-c\s+['\"].*(?:os\.system|subprocess|exec|eval)"),
    re.compile(r"perl\s+-e\s+['\"].*(?:system|exec|`)`"),
    re.compile(r"ruby\s+-e\s+['\"].*(?:system|exec|`)"),
    re.compile(r"node\s+-e\s+['\"].*(?:child_process|exec)"),
    re.compile(r"\beval\s+"),
]

# Base64 encoded command detection
B64_EXEC_PATTERN: re.Pattern = re.compile(
    r"(?:echo|printf)\s+['\"]?([A-Za-z0-9+/=]{20,})['\"]?\s*\|\s*(?:base64\s+-d|b64decode)\s*\|\s*(sh|bash|python)"
)

# Allowed tool binaries — commands must start with one of these
ALLOWED_BINARIES: FrozenSet[str] = frozenset({
    # Reconnaissance
    "nmap", "masscan", "subfinder", "httpx", "katana", "gau",
    "waybackurls", "dnsx", "dig", "whois", "host", "nslookup",
    "whatweb", "wafw00f", "amass", "assetfinder", "gobuster",
    "dirsearch", "ffuf", "feroxbuster", "arjun", "hakrawler",
    "wfuzz", "dirb",
    # Vulnerability scanning
    "nuclei", "nikto", "dalfox", "sqlmap", "commix",
    "wpscan", "joomscan", "droopescan",
    "sslyze", "testssl", "sslscan",
    # Network utilities
    "curl", "wget", "nc", "ncat", "netcat",
    "ping", "traceroute", "tracepath",
    # General utilities
    "echo", "cat", "head", "tail", "grep", "awk", "sed",
    "sort", "uniq", "wc", "tr", "cut", "tee",
    "ls", "find", "file", "strings", "xxd", "hexdump",
    "jq", "yq", "xmllint",
    "base64", "md5sum", "sha256sum", "sha1sum",
    "date", "whoami", "id", "uname", "hostname",
    "env", "printenv", "pwd",
    "mkdir", "cp", "mv", "touch",
    "tar", "gzip", "gunzip", "zip", "unzip",
    "diff", "comm",
    # Python (for scripting — inline exec patterns checked separately)
    "python", "python3", "pip", "pip3",
    # Hydra for brute force (governed by phase)
    "hydra", "medusa", "hashcat", "john",
})


class CommandAnalyzer:
    """Static analysis of shell commands for safety enforcement.

    Capabilities:
      1. Split compound commands (;, &&, ||, |, $(...), backticks)
      2. Check each segment against blocked patterns
      3. Verify leading binary is in the allowlist
      4. Detect encoding bypass attempts (base64, URL encoding)
      5. Extract target hosts/IPs/URLs from commands
    """

    _custom_allowed: Set[str] = set()
    _custom_blocked: Set[str] = set()

    @classmethod
    def add_allowed_binary(cls, binary: str):
        cls._custom_allowed.add(binary.lower().strip())

    @classmethod
    def add_blocked_binary(cls, binary: str):
        cls._custom_blocked.add(binary.lower().strip())

    @classmethod
    def analyze(cls, command: str, strict: bool = True) -> CommandDecision:
        """Analyze a shell command for safety.

        Args:
            command: The full shell command string.
            strict: If True, unknown binaries are blocked.

        Returns:
            CommandDecision with allowed, reason, extracted_targets, risk_level.
        """
        if not command or not command.strip():
            return CommandDecision(allowed=True, reason="empty command")

        command = command.strip()

        # 1. Check for encoding bypass attempts
        bypass = cls._check_encoding_bypass(command)
        if bypass:
            return CommandDecision(
                allowed=False,
                reason=f"Encoding bypass detected: {bypass}",
                risk_level="critical",
            )

        # 2. Check full command against blocked patterns
        pattern_match = cls._check_blocked_patterns(command)
        if pattern_match:
            return CommandDecision(
                allowed=False,
                reason=f"Dangerous pattern: {pattern_match}",
                risk_level="critical",
            )

        # 3. Check pipe-to-shell
        if PIPE_TO_SHELL.search(command):
            return CommandDecision(
                allowed=False,
                reason="Download piped to shell execution",
                risk_level="critical",
            )

        # 4. Split compound commands and analyze each segment
        segments = cls._split_command(command)
        all_targets: List[str] = []
        max_risk = "low"

        for segment in segments:
            segment = segment.strip()
            if not segment:
                continue

            # Check inline execution
            for pat in INLINE_EXEC_PATTERNS:
                if pat.search(segment):
                    return CommandDecision(
                        allowed=False,
                        reason=f"Inline code execution: {segment[:80]}",
                        risk_level="high",
                    )

            # Extract the leading binary
            binary = cls._extract_binary(segment)
            if not binary:
                continue

            binary_lower = binary.lower()

            # Custom blocked
            if binary_lower in cls._custom_blocked:
                return CommandDecision(
                    allowed=False,
                    reason=f"Custom-blocked binary: {binary}",
                    risk_level="high",
                )

            # Built-in blocked
            if binary_lower in BLOCKED_BINARIES:
                return CommandDecision(
                    allowed=False,
                    reason=f"Blocked binary: {binary}",
                    risk_level="critical",
                )

            # Allowlist check (in strict mode)
            if strict:
                is_allowed = (
                    binary_lower in ALLOWED_BINARIES
                    or binary_lower in cls._custom_allowed
                    # Allow absolute paths to allowed binaries
                    or binary_lower.split("/")[-1] in ALLOWED_BINARIES
                    or binary_lower.split("/")[-1] in cls._custom_allowed
                )
                if not is_allowed:
                    return CommandDecision(
                        allowed=False,
                        reason=f"Binary not in allowlist: {binary}",
                        risk_level="medium",
                    )

            # Extract targets
            targets = cls._extract_targets(segment)
            all_targets.extend(targets)

        return CommandDecision(
            allowed=True,
            reason="Command passed safety analysis",
            extracted_targets=all_targets,
            risk_level=max_risk,
        )

    @classmethod
    def _split_command(cls, command: str) -> List[str]:
        """Split compound commands on ;, &&, ||, and |.

        Also extracts subshell contents from $(...) and backticks.
        """
        segments: List[str] = []

        # Extract $(...) subshells
        subshell_pattern = re.compile(r'\$\(([^)]+)\)')
        for match in subshell_pattern.finditer(command):
            segments.extend(cls._split_command(match.group(1)))

        # Extract backtick subshells
        backtick_pattern = re.compile(r'`([^`]+)`')
        for match in backtick_pattern.finditer(command):
            segments.extend(cls._split_command(match.group(1)))

        # Remove subshells from main command for further splitting
        cleaned = subshell_pattern.sub('__SUBSHELL__', command)
        cleaned = backtick_pattern.sub('__SUBSHELL__', cleaned)

        # Split on ; && ||
        parts = re.split(r'\s*(?:;|&&|\|\|)\s*', cleaned)
        for part in parts:
            part = part.strip()
            if not part:
                continue
            # Split on | (pipe) — each side is a separate command
            pipe_parts = re.split(r'\s*\|\s*', part)
            segments.extend(p.strip() for p in pipe_parts if p.strip())

        return segments

    @classmethod
    def _extract_binary(cls, segment: str) -> Optional[str]:
        """Extract the leading binary/command name from a segment."""
        segment = segment.strip()
        if not segment:
            return None

        # Handle variable assignments at start (VAR=val command)
        while re.match(r'^[A-Za-z_][A-Za-z0-9_]*=\S*\s+', segment):
            segment = re.sub(r'^[A-Za-z_][A-Za-z0-9_]*=\S*\s+', '', segment, count=1)

        # Handle sudo/env/nice prefixes
        prefixes = {"sudo", "env", "nice", "nohup", "timeout", "strace", "ltrace", "time"}
        parts = segment.split()
        while parts and parts[0].lower().split("/")[-1] in prefixes:
            parts.pop(0)
            # Skip flags after prefix
            while parts and parts[0].startswith("-"):
                parts.pop(0)

        if not parts:
            return None

        return parts[0].split("/")[-1]  # Strip path prefix

    @classmethod
    def _check_blocked_patterns(cls, command: str) -> Optional[str]:
        """Check command against blocked patterns. Returns match description or None."""
        command_lower = command.lower()

        for binary, pattern in BLOCKED_PATTERNS:
            if binary and binary not in command_lower:
                continue
            if pattern.search(command_lower):
                return pattern.pattern[:80]

        return None

    @classmethod
    def _check_encoding_bypass(cls, command: str) -> Optional[str]:
        """Detect encoding bypass attempts."""
        # Base64 pipe to shell
        if B64_EXEC_PATTERN.search(command):
            return "base64 decoded output piped to shell"

        # URL-encoded dangerous characters in commands
        if re.search(r'%2[fF]', command) and re.search(r'%2[eE]', command):
            # URL-encoded path traversal (../)
            decoded = unquote(command)
            if ".." in decoded and ("rm" in decoded or "cat /etc" in decoded):
                return "URL-encoded path traversal in command"

        # Hex-encoded strings being passed to execution
        if re.search(r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}', command):
            if re.search(r'\|\s*(sh|bash|python)', command):
                return "hex-encoded payload piped to shell"

        return None

    @classmethod
    def _extract_targets(cls, segment: str) -> List[str]:
        """Extract target hosts/IPs/URLs from a command segment."""
        targets: List[str] = []

        # URL extraction
        url_pattern = re.compile(r'https?://[^\s\'"<>]+')
        for match in url_pattern.finditer(segment):
            url = match.group()
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    targets.append(parsed.hostname)
            except Exception:
                pass

        # IP address extraction
        ip_pattern = re.compile(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b'
        )
        for match in ip_pattern.finditer(segment):
            ip_str = match.group(1)
            try:
                # Validate it's a real IP
                if "/" in ip_str:
                    ipaddress.ip_network(ip_str, strict=False)
                else:
                    ipaddress.ip_address(ip_str)
                targets.append(ip_str)
            except ValueError:
                pass

        # Common tool target flags
        flag_patterns = [
            # nmap targets
            re.compile(r'nmap\s+.*?(?:-[a-zA-Z]+\s+\S+\s+)*(\S+)\s*$'),
            # sqlmap -u
            re.compile(r'sqlmap\s+.*?-u\s+[\'"]?(\S+)'),
            # curl URL (first non-flag argument)
            re.compile(r'curl\s+(?:-[a-zA-Z]+\s+\S+\s+)*[\'"]?(https?://\S+)'),
            # wget URL
            re.compile(r'wget\s+(?:-[a-zA-Z]+\s+\S+\s+)*[\'"]?(https?://\S+)'),
            # nuclei -u / -target
            re.compile(r'nuclei\s+.*?(?:-u|-target)\s+[\'"]?(\S+)'),
            # httpx -u
            re.compile(r'httpx\s+.*?-u\s+[\'"]?(\S+)'),
            # ffuf -u
            re.compile(r'ffuf\s+.*?-u\s+[\'"]?(\S+)'),
        ]
        for pat in flag_patterns:
            m = pat.search(segment)
            if m:
                target = m.group(1).strip("'\"")
                try:
                    parsed = urlparse(target if "://" in target else f"https://{target}")
                    if parsed.hostname:
                        targets.append(parsed.hostname)
                except Exception:
                    targets.append(target)

        return list(set(targets))
