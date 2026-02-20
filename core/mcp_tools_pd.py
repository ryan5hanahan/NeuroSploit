"""
sploit.ai - ProjectDiscovery Tool MCP Handlers

Dedicated async handlers for the extended ProjectDiscovery suite:
  cvemap, tlsx, asnmap, mapcidr, alterx, shuffledns,
  cloudlist, interactsh-client, notify

Each handler: get sandbox -> build command with opsec flags -> execute -> parse -> return JSON.
"""

import asyncio
import json
import logging
import random
import shlex
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def _is_ip_or_cidr(s: str) -> bool:
    """Check if a string looks like an IPv4/IPv6 address or CIDR range."""
    import ipaddress
    try:
        ipaddress.ip_address(s.split("/")[0])
        return True
    except ValueError:
        return False


# Lazy sandbox import
_sandbox_available = None


def _check_sandbox():
    global _sandbox_available
    if _sandbox_available is None:
        try:
            from core.sandbox_manager import get_sandbox
            _sandbox_available = True
        except ImportError:
            _sandbox_available = False
    return _sandbox_available


async def _get_sb():
    from core.sandbox_manager import get_sandbox
    return await get_sandbox()


async def _apply_jitter(opsec_profile: Optional[str]):
    """Apply opsec jitter delay before execution if profile is set."""
    if not opsec_profile:
        return
    try:
        from core.sandbox_manager import _get_opsec
        opsec = _get_opsec()
        if opsec:
            jitter_min, jitter_max = opsec.get_jitter_range(opsec_profile)
            if jitter_max > 0:
                await asyncio.sleep(random.uniform(jitter_min, jitter_max))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# cvemap - CVE database lookup
# ---------------------------------------------------------------------------
async def _execute_cvemap(
    cve_id: Optional[str] = None,
    severity: Optional[str] = None,
    product: Optional[str] = None,
    vendor: Optional[str] = None,
    opsec_profile: Optional[str] = None,
) -> Dict:
    """Query CVE database via cvemap. Returns structured CVE data."""
    if not _check_sandbox():
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await _get_sb()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        args_parts = ["-json", "-silent"]
        if cve_id:
            args_parts.extend(["-id", cve_id])
        if severity:
            args_parts.extend(["-severity", severity])
        if product:
            args_parts.extend(["-product", product])
        if vendor:
            args_parts.extend(["-vendor", vendor])

        args = " ".join(args_parts)
        result = await sandbox.run_tool(
            "cvemap", args, timeout=120, opsec_profile=opsec_profile
        )

        findings = []
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    findings.append(data)
                except json.JSONDecodeError:
                    continue

        return {
            "tool": "cvemap",
            "exit_code": result.exit_code,
            "findings": findings,
            "findings_count": len(findings),
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# tlsx - TLS/SSL certificate analysis
# ---------------------------------------------------------------------------
async def _execute_tlsx(
    target: str,
    port: Optional[str] = None,
    scan_mode: Optional[str] = None,
    opsec_profile: Optional[str] = None,
) -> Dict:
    """Analyze TLS certificates, cipher suites, and versions."""
    if not _check_sandbox():
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await _get_sb()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        args_parts = ["-host", target, "-json", "-silent"]
        if port:
            args_parts.extend(["-port", port])
        if scan_mode:
            args_parts.extend(["-scan-mode", scan_mode])

        args = " ".join(args_parts)
        result = await sandbox.run_tool(
            "tlsx", args, timeout=120, opsec_profile=opsec_profile
        )

        findings = []
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    findings.append({
                        "host": data.get("host", ""),
                        "port": data.get("port", 443),
                        "tls_version": data.get("tls_version", ""),
                        "cipher": data.get("cipher", ""),
                        "subject_cn": data.get("subject_cn", ""),
                        "subject_an": data.get("subject_an", []),
                        "issuer": data.get("issuer_org", ""),
                        "not_before": data.get("not_before", ""),
                        "not_after": data.get("not_after", ""),
                        "expired": data.get("expired", False),
                        "self_signed": data.get("self_signed", False),
                    })
                except json.JSONDecodeError:
                    continue

        return {
            "tool": "tlsx",
            "target": target,
            "exit_code": result.exit_code,
            "findings": findings,
            "findings_count": len(findings),
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# asnmap - ASN/IP/Org mapping
# ---------------------------------------------------------------------------
async def _execute_asnmap(
    target: str,
    opsec_profile: Optional[str] = None,
) -> Dict:
    """Map IP/org/ASN to CIDR ranges and organization info."""
    if not _check_sandbox():
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await _get_sb()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        # Detect input type and use the correct flag
        target_stripped = target.strip()
        if target_stripped.upper().startswith("AS") and any(c.isdigit() for c in target_stripped):
            flag = "-a"
        elif _is_ip_or_cidr(target_stripped):
            flag = "-ip"
        else:
            flag = "-org"

        args = f"{flag} {target_stripped} -json -silent"
        result = await sandbox.run_tool(
            "asnmap", args, timeout=120, opsec_profile=opsec_profile
        )

        findings = []
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    findings.append(data)
                except json.JSONDecodeError:
                    # Plain text CIDR output
                    if "/" in line:
                        findings.append({"cidr": line.strip()})

        return {
            "tool": "asnmap",
            "target": target,
            "exit_code": result.exit_code,
            "findings": findings,
            "findings_count": len(findings),
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# mapcidr - CIDR manipulation
# ---------------------------------------------------------------------------
async def _execute_mapcidr(
    cidr: str,
    operation: str = "count",
    opsec_profile: Optional[str] = None,
) -> Dict:
    """Manipulate CIDR ranges: aggregate, split by host count, or count IPs."""
    if not _check_sandbox():
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await _get_sb()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        args_parts = ["-cidr", cidr, "-silent"]
        if operation == "aggregate":
            args_parts.append("-aggregate")
        elif operation == "count":
            args_parts.append("-count")
        elif operation.startswith("split"):
            # e.g. "split-24" for /24 subnets
            parts = operation.split("-")
            if len(parts) == 2:
                args_parts.extend(["-sbc", parts[1]])

        args = " ".join(args_parts)
        result = await sandbox.run_tool(
            "mapcidr", args, timeout=60, opsec_profile=opsec_profile
        )

        output_lines = []
        if result.stdout:
            output_lines = [
                l.strip() for l in result.stdout.strip().split("\n")
                if l.strip()
            ]

        return {
            "tool": "mapcidr",
            "cidr": cidr,
            "operation": operation,
            "exit_code": result.exit_code,
            "output": output_lines,
            "count": len(output_lines),
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# alterx - Subdomain permutation generation
# ---------------------------------------------------------------------------
async def _execute_alterx(
    domain: str,
    pattern: Optional[str] = None,
    enrich: bool = False,
    opsec_profile: Optional[str] = None,
) -> Dict:
    """Generate subdomain permutations from a domain."""
    if not _check_sandbox():
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await _get_sb()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        args_parts = ["-silent"]
        if pattern:
            args_parts.extend(["-pattern", pattern])
        if enrich:
            args_parts.append("-enrich")

        # Apply opsec jitter (alterx uses execute_raw, bypassing run_tool jitter)
        await _apply_jitter(opsec_profile)

        # alterx reads from stdin
        args = " ".join(args_parts)
        cmd = f"echo {shlex.quote(domain)} | alterx {args}"
        result = await sandbox.execute_raw(cmd, timeout=60)
        result.tool = "alterx"

        permutations = []
        if result.stdout:
            permutations = [
                l.strip() for l in result.stdout.strip().split("\n")
                if l.strip()
            ]

        return {
            "tool": "alterx",
            "domain": domain,
            "exit_code": result.exit_code,
            "permutations": permutations[:500],  # Cap output
            "count": len(permutations),
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# shuffledns - DNS resolution with wordlist
# ---------------------------------------------------------------------------
async def _execute_shuffledns(
    domain: str,
    wordlist: str = "/opt/wordlists/subdomains-5000.txt",
    resolvers: Optional[str] = None,
    opsec_profile: Optional[str] = None,
) -> Dict:
    """Brute-force and resolve subdomains using massdns backend."""
    if not _check_sandbox():
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await _get_sb()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        args_parts = ["-d", domain, "-w", wordlist, "-silent"]
        if resolvers:
            args_parts.extend(["-r", resolvers])
        else:
            # Use a default resolvers list if available
            args_parts.extend(["-r", "/opt/wordlists/resolvers.txt"])

        args = " ".join(args_parts)
        result = await sandbox.run_tool(
            "shuffledns", args, timeout=300, opsec_profile=opsec_profile
        )

        subdomains = []
        if result.stdout:
            subdomains = [
                l.strip() for l in result.stdout.strip().split("\n")
                if l.strip()
            ]

        return {
            "tool": "shuffledns",
            "domain": domain,
            "exit_code": result.exit_code,
            "subdomains": subdomains,
            "count": len(subdomains),
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# cloudlist - Cloud asset enumeration
# ---------------------------------------------------------------------------
async def _execute_cloudlist(
    provider: Optional[str] = None,
    opsec_profile: Optional[str] = None,
) -> Dict:
    """Enumerate cloud assets (IPs, hostnames, buckets) from configured providers."""
    if not _check_sandbox():
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await _get_sb()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        args_parts = ["-silent", "-json"]
        if provider:
            args_parts.extend(["-provider", provider])

        args = " ".join(args_parts)
        result = await sandbox.run_tool(
            "cloudlist", args, timeout=180, opsec_profile=opsec_profile
        )

        assets = []
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    assets.append(data)
                except json.JSONDecodeError:
                    assets.append({"asset": line.strip()})

        return {
            "tool": "cloudlist",
            "provider": provider,
            "exit_code": result.exit_code,
            "assets": assets,
            "count": len(assets),
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# interactsh-client - Out-of-band interaction testing
# ---------------------------------------------------------------------------
async def _execute_interactsh(
    action: str = "register",
    token: Optional[str] = None,
    poll_interval: Optional[int] = None,
    opsec_profile: Optional[str] = None,
) -> Dict:
    """Run interactsh-client for out-of-band interaction testing.

    interactsh-client is a long-running process that auto-registers an OOB URL
    on start and polls for interactions. We run it briefly with a timeout.

    Actions:
      - register: Start client, capture the generated OOB URL (runs ~5s)
      - poll: Start client with -n to wait for N interactions (runs until timeout)
    """
    if not _check_sandbox():
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await _get_sb()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        args_parts = ["-v"]

        # Check opsec profile for self-hosted server
        try:
            from core.sandbox_manager import _get_opsec
            opsec = _get_opsec()
            if opsec:
                tool_flags = opsec.get_tool_flags("interactsh-client", opsec_profile)
                if "server" in tool_flags:
                    args_parts.extend(["-server", tool_flags["server"]])
        except Exception:
            pass

        if poll_interval:
            args_parts.extend(["-poll-interval", str(poll_interval)])
        if token:
            args_parts.extend(["-token", token])

        if action == "register":
            # Run briefly to get the OOB URL, then kill via timeout.
            # interactsh-client prints the URL immediately on startup.
            timeout = 10
        elif action == "poll":
            # Wait for interactions (default: 1)
            args_parts.extend(["-n", "1", "-json"])
            timeout = 30
        else:
            return {"error": f"Unknown action: {action}. Use 'register' or 'poll'."}

        # interactsh-client must be run via execute_raw with timeout because
        # it's a long-running process; we rely on the timeout to stop it
        await _apply_jitter(opsec_profile)
        args = " ".join(args_parts)
        cmd = f"timeout {timeout} interactsh-client {args} 2>&1 || true"
        result = await sandbox.execute_raw(cmd, timeout=timeout + 5)
        result.tool = "interactsh-client"

        interactions = []
        oob_url = None
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    interactions.append(data)
                except json.JSONDecodeError:
                    # interactsh-client prints the URL as plain text on startup
                    stripped = line.strip()
                    if ".oast." in stripped or ".interact." in stripped:
                        oob_url = stripped
                    elif "Listing" in stripped and "URL" in stripped:
                        # "Listing 1 URL for OOB testing: <url>"
                        parts = stripped.split()
                        for part in parts:
                            if "." in part and len(part) > 10:
                                oob_url = part

        return {
            "tool": "interactsh-client",
            "action": action,
            "exit_code": result.exit_code,
            "oob_url": oob_url,
            "interactions": interactions,
            "count": len(interactions),
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# notify - Send notifications via configured providers
# ---------------------------------------------------------------------------
async def _execute_notify(
    message: str,
    provider: Optional[str] = None,
    severity: Optional[str] = None,
    opsec_profile: Optional[str] = None,
) -> Dict:
    """Send a notification message via configured providers (Slack, Discord, etc.)."""
    if not _check_sandbox():
        return {"error": "Sandbox module not available"}

    try:
        sandbox = await _get_sb()
        if not sandbox.is_available:
            return {"error": "Sandbox container not running"}

        args_parts = ["-silent"]
        if provider:
            args_parts.extend(["-provider", provider])
        if severity:
            args_parts.extend(["-severity", severity])

        # Apply opsec jitter (notify uses execute_raw, bypassing run_tool jitter)
        await _apply_jitter(opsec_profile)

        args = " ".join(args_parts)
        # notify reads from stdin
        cmd = f"echo {shlex.quote(message)} | notify {args}"
        result = await sandbox.execute_raw(cmd, timeout=30)
        result.tool = "notify"

        return {
            "tool": "notify",
            "message": message[:200],
            "exit_code": result.exit_code,
            "stdout": result.stdout[:1000] if result.stdout else "",
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# oob_verify - Simplified OOB verification wrapper
# ---------------------------------------------------------------------------
async def _oob_verify(
    action: str = "register",
    oob_url: Optional[str] = None,
    wait_seconds: Optional[int] = None,
    expected_protocol: Optional[str] = None,
) -> Dict:
    """High-level OOB verification wrapper around interactsh.

    Actions:
      - register: Register a new OOB URL and return injection templates.
      - poll/check: Poll for interactions, optionally filtering by protocol.
    """
    if action == "register":
        result = await _execute_interactsh(action="register")
        if result.get("error"):
            return result
        oob_domain = result.get("oob_url", "")
        return {
            "tool": "oob_verify",
            "action": "register",
            "oob_url": oob_domain,
            "subdomain": oob_domain.split(".")[0] if oob_domain else None,
            "inject_template": {
                "dns_canary": f"{{payload}}.{oob_domain}" if oob_domain else None,
                "http_canary": f"http://{oob_domain}/{{payload}}" if oob_domain else None,
            },
        }

    elif action in ("poll", "check"):
        poll_interval = wait_seconds if wait_seconds else None
        result = await _execute_interactsh(
            action="poll", poll_interval=poll_interval,
        )
        if result.get("error"):
            return result

        interactions = result.get("interactions", [])
        # Filter by expected protocol if specified
        if expected_protocol and interactions:
            interactions = [
                i for i in interactions
                if i.get("protocol", "").lower() == expected_protocol.lower()
            ]

        timestamps = [
            i.get("timestamp") or i.get("time", "")
            for i in interactions if i.get("timestamp") or i.get("time")
        ]

        return {
            "tool": "oob_verify",
            "action": action,
            "verified": len(interactions) > 0,
            "interactions": interactions,
            "interaction_count": len(interactions),
            "protocol": expected_protocol,
            "timestamps": timestamps,
        }

    else:
        return {"error": f"Unknown action: {action}. Use 'register', 'poll', or 'check'."}
