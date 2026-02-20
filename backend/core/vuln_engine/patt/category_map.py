"""
PATT Category Map — Maps PayloadsAllTheThings directories to sploit.ai vuln_type keys.

Three data structures:
- PATT_CATEGORY_MAP: directory name -> list of vuln_type keys
- NEW_VULN_TYPES: metadata for types introduced by PATT integration
- PATT_INTRUDER_FILE_MAP: routes specific Intruder/ filenames for 1:N categories
"""
from typing import Dict, List


# ---------------------------------------------------------------------------
# Directory -> vuln_type(s) mapping
# ---------------------------------------------------------------------------

PATT_CATEGORY_MAP: Dict[str, List[str]] = {
    # --- 1:1 Mappings (existing types) ---
    "Account Takeover": ["account_takeover"],
    "API Key Leaks": ["api_key_exposure"],
    "Brute Force Rate Limit": ["brute_force", "rate_limit_bypass"],
    "Business Logic Errors": ["business_logic"],
    "Clickjacking": ["clickjacking"],
    "Client Side Path Traversal": ["client_side_path_traversal"],
    "Command Injection": ["command_injection"],
    "CORS Misconfiguration": ["cors_misconfig"],
    "CRLF Injection": ["crlf_injection"],
    "Cross-Site Request Forgery": ["csrf"],
    "CSS Injection": ["css_injection"],
    "CSV Injection": ["csv_injection"],
    "Denial of Service": ["denial_of_service"],
    "Dependency Confusion": ["dependency_confusion"],
    "Directory Traversal": ["path_traversal", "lfi"],
    "DNS Rebinding": ["dns_rebinding"],
    "DOM Clobbering": ["dom_clobbering"],
    "External Variable Modification": ["external_variable_modification"],
    "File Inclusion": ["lfi", "rfi"],
    "Google Web Toolkit": ["gwt_deserialization"],
    "GraphQL Injection": ["graphql_injection", "graphql_introspection"],
    "Headless Browser": ["headless_browser_abuse"],
    "Hidden Parameters": ["forced_browsing"],
    "HTTP Parameter Pollution": ["parameter_pollution"],
    "Insecure Deserialization": ["insecure_deserialization"],
    "Insecure Direct Object References": ["idor", "bola"],
    "Insecure Management Interface": ["exposed_admin_panel"],
    "Insecure Randomness": ["weak_random"],
    "Insecure Source Code Management": ["source_code_disclosure"],
    "Java RMI": ["java_rmi"],
    "JSON Web Token": ["jwt_manipulation"],
    "LaTeX Injection": ["latex_injection"],
    "LDAP Injection": ["ldap_injection"],
    "Mass Assignment": ["mass_assignment"],
    "NoSQL Injection": ["nosql_injection"],
    "OAuth Misconfiguration": ["oauth_misconfiguration"],
    "Open Redirect": ["open_redirect"],
    "ORM Leak": ["orm_injection"],
    "Prompt Injection": ["prompt_injection"],
    "Prototype Pollution": ["prototype_pollution"],
    "Race Condition": ["race_condition"],
    "Regular Expression": ["redos"],
    "Request Smuggling": ["http_smuggling"],
    "Reverse Proxy Misconfigurations": ["reverse_proxy_misconfig"],
    "SAML Injection": ["saml_injection"],
    "Server Side Include Injection": ["ssi_injection"],
    "Server Side Request Forgery": ["ssrf", "ssrf_cloud"],
    "Server Side Template Injection": ["ssti"],
    "Tabnabbing": ["tabnabbing"],
    "Type Juggling": ["type_juggling"],
    "Upload Insecure Files": ["file_upload"],
    "Virtual Hosts": ["vhost_enumeration"],
    "Web Cache Deception": ["web_cache_deception"],
    "Web Sockets": ["websocket_hijacking"],
    "XPATH Injection": ["xpath_injection"],
    "XS-Leak": ["xs_leak"],
    "XSLT Injection": ["xslt_injection"],
    "XXE Injection": ["xxe"],
    "Zip Slip": ["zip_slip"],

    # --- 1:N fan-out (routed by filename/section) ---
    "SQL Injection": ["sqli_error", "sqli_union", "sqli_blind", "sqli_time"],
    "XSS Injection": ["xss_reflected", "xss_stored", "xss_dom", "blind_xss"],
}

# Directories explicitly skipped (reference material, not payloads)
PATT_SKIPPED_DIRS = {
    "Methodology and Resources",
    "CVE Exploits",
    "_LEARNING_AND_SOCIALS",
    "_template_vuln",
    "Encoding Transformations",
}


# ---------------------------------------------------------------------------
# Intruder file routing for 1:N categories
# ---------------------------------------------------------------------------

PATT_INTRUDER_FILE_MAP: Dict[str, Dict[str, str]] = {
    "SQL Injection": {
        "Error": "sqli_error",
        "Auth_Bypass": "sqli_error",
        "UNION": "sqli_union",
        "Blind": "sqli_blind",
        "Time": "sqli_time",
        "Out-of-Band": "sqli_blind",
    },
    "XSS Injection": {
        "XSS-Reflected": "xss_reflected",
        "XSS-Stored": "xss_stored",
        "XSS-DOM": "xss_dom",
        "XSS-Blind": "blind_xss",
        "XSS-WAF": "xss_reflected",
        "XSS-Filter-Bypass": "xss_reflected",
    },
}


# ---------------------------------------------------------------------------
# Markdown section routing for 1:N categories
# ---------------------------------------------------------------------------

PATT_SECTION_MAP: Dict[str, Dict[str, str]] = {
    "SQL Injection": {
        "Error based": "sqli_error",
        "Authentication bypass": "sqli_error",
        "UNION based": "sqli_union",
        "Boolean based": "sqli_blind",
        "Blind": "sqli_blind",
        "Time based": "sqli_time",
    },
    "XSS Injection": {
        "Reflected": "xss_reflected",
        "Stored": "xss_stored",
        "DOM": "xss_dom",
        "Blind": "blind_xss",
    },
}


# ---------------------------------------------------------------------------
# New vuln types introduced by PATT (19 types)
# ---------------------------------------------------------------------------

NEW_VULN_TYPES: Dict[str, dict] = {
    "account_takeover": {
        "title": "Account Takeover",
        "severity": "critical",
        "cwe_id": "CWE-284",
        "description": "Flaws in password reset, token handling, or session management enabling full account hijacking.",
        "impact": "Complete unauthorized access to victim accounts, data theft, identity fraud.",
        "remediation": "1. Use cryptographically secure reset tokens\n2. Expire tokens after single use\n3. Verify identity before password changes\n4. Send notifications on account changes",
    },
    "client_side_path_traversal": {
        "title": "Client-Side Path Traversal",
        "severity": "medium",
        "cwe_id": "CWE-22",
        "description": "Path traversal in client-side routing or fetch URLs leading to unintended API access.",
        "impact": "Access to unauthorized API endpoints, data exposure via client-side URL manipulation.",
        "remediation": "1. Validate paths server-side\n2. Use allowlists for API routes\n3. Normalize URLs before fetching\n4. Never trust client-provided path segments",
    },
    "denial_of_service": {
        "title": "Denial of Service",
        "severity": "medium",
        "cwe_id": "CWE-400",
        "description": "Application-layer DoS via resource exhaustion, algorithmic complexity, or amplification.",
        "impact": "Service unavailability, degraded performance, infrastructure cost amplification.",
        "remediation": "1. Implement rate limiting\n2. Set resource limits (timeouts, memory)\n3. Use pagination for large datasets\n4. Implement request size limits",
    },
    "dependency_confusion": {
        "title": "Dependency Confusion",
        "severity": "critical",
        "cwe_id": "CWE-427",
        "description": "Supply chain attack where a malicious public package overrides a private internal dependency.",
        "impact": "Remote code execution during build, backdoored deployments, credential theft.",
        "remediation": "1. Use scoped packages (@org/pkg)\n2. Configure private registries with priority\n3. Pin dependency versions\n4. Use package-lock files",
    },
    "dns_rebinding": {
        "title": "DNS Rebinding",
        "severity": "high",
        "cwe_id": "CWE-350",
        "description": "DNS records that swap between external and internal IPs to bypass same-origin policy.",
        "impact": "Access to internal services, bypass of network-level access controls, SSRF via DNS.",
        "remediation": "1. Validate Host header\n2. Pin DNS responses\n3. Use TLS with hostname verification\n4. Block private IPs in DNS resolution",
    },
    "external_variable_modification": {
        "title": "External Variable Modification",
        "severity": "high",
        "cwe_id": "CWE-473",
        "description": "External input modifies internal variables (PHP register_globals, env var injection).",
        "impact": "Authentication bypass, privilege escalation, configuration tampering.",
        "remediation": "1. Disable register_globals\n2. Validate all environment variables\n3. Use explicit variable initialization\n4. Filter external input sources",
    },
    "gwt_deserialization": {
        "title": "GWT (Google Web Toolkit) Deserialization",
        "severity": "high",
        "cwe_id": "CWE-502",
        "description": "Insecure deserialization in Google Web Toolkit RPC endpoints.",
        "impact": "Remote code execution, server compromise via crafted GWT-RPC payloads.",
        "remediation": "1. Update GWT to latest version\n2. Implement serialization whitelist\n3. Use JSON instead of GWT-RPC\n4. Restrict accessible service interfaces",
    },
    "headless_browser_abuse": {
        "title": "Headless Browser Abuse",
        "severity": "high",
        "cwe_id": "CWE-94",
        "description": "Server-side headless browser (Puppeteer, Playwright) exploited via injected content.",
        "impact": "SSRF via browser, file read via file:// protocol, RCE via browser exploits.",
        "remediation": "1. Sandbox headless browser\n2. Disable file:// protocol\n3. Set navigation timeouts\n4. Use --no-sandbox only in containers",
    },
    "java_rmi": {
        "title": "Java RMI Exploitation",
        "severity": "critical",
        "cwe_id": "CWE-502",
        "description": "Exposed Java RMI registry allowing deserialization attacks and remote method invocation.",
        "impact": "Remote code execution via deserialization gadget chains, full server compromise.",
        "remediation": "1. Disable RMI registry on public interfaces\n2. Use JEP 290 serialization filters\n3. Firewall RMI ports (1099)\n4. Use TLS for RMI connections",
    },
    "latex_injection": {
        "title": "LaTeX Injection",
        "severity": "high",
        "cwe_id": "CWE-94",
        "description": "User input processed by LaTeX compiler enabling file read or command execution.",
        "impact": "File read via \\input{/etc/passwd}, command execution via \\write18, server compromise.",
        "remediation": "1. Disable \\write18 and shell-escape\n2. Sandbox LaTeX compilation\n3. Use pdflatex with -no-shell-escape\n4. Whitelist allowed LaTeX commands",
    },
    "prompt_injection": {
        "title": "LLM Prompt Injection",
        "severity": "high",
        "cwe_id": "CWE-77",
        "description": "Adversarial input that manipulates LLM behavior to bypass instructions or leak system prompts.",
        "impact": "System prompt exfiltration, unauthorized actions via LLM, data leakage through AI responses.",
        "remediation": "1. Separate system and user prompts\n2. Implement output filtering\n3. Use structured output formats\n4. Apply input sanitization before LLM processing",
    },
    "redos": {
        "title": "Regular Expression Denial of Service (ReDoS)",
        "severity": "medium",
        "cwe_id": "CWE-1333",
        "description": "Crafted input causes catastrophic backtracking in vulnerable regular expressions.",
        "impact": "CPU exhaustion, service unavailability, thread pool starvation.",
        "remediation": "1. Use RE2 or other linear-time regex engines\n2. Set regex execution timeouts\n3. Avoid nested quantifiers\n4. Test regexes with ReDoS detection tools",
    },
    "reverse_proxy_misconfig": {
        "title": "Reverse Proxy Misconfiguration",
        "severity": "high",
        "cwe_id": "CWE-441",
        "description": "Nginx/Apache/HAProxy misconfiguration enabling path normalization bypass or header injection.",
        "impact": "Access control bypass, path traversal via proxy normalization differences, cache poisoning.",
        "remediation": "1. Normalize paths before routing\n2. Strip hop-by-hop headers\n3. Match proxy and backend path parsing\n4. Use merge_slashes in nginx",
    },
    "saml_injection": {
        "title": "SAML Injection / SAML Bypass",
        "severity": "critical",
        "cwe_id": "CWE-287",
        "description": "SAML response manipulation, XML signature wrapping, or assertion replay attacks.",
        "impact": "Authentication bypass, impersonation of any user, admin account takeover.",
        "remediation": "1. Validate XML signatures strictly\n2. Check assertion recipient and audience\n3. Reject unsigned assertions\n4. Implement replay protection with assertion IDs",
    },
    "ssi_injection": {
        "title": "Server-Side Include (SSI) Injection",
        "severity": "high",
        "cwe_id": "CWE-97",
        "description": "User input processed by SSI directives enabling command execution or file inclusion.",
        "impact": "File read via <!--#include -->, command execution via <!--#exec -->, information disclosure.",
        "remediation": "1. Disable SSI processing\n2. Sanitize user input for SSI directives\n3. Use Options -Includes in Apache\n4. Restrict SSI to specific directories",
    },
    "vhost_enumeration": {
        "title": "Virtual Host Enumeration",
        "severity": "medium",
        "cwe_id": "CWE-200",
        "description": "Discovery of hidden virtual hosts, subdomains, or internal applications on shared infrastructure.",
        "impact": "Access to internal/staging applications, expanded attack surface, information disclosure.",
        "remediation": "1. Use separate IPs for internal vhosts\n2. Require authentication on all vhosts\n3. Don't expose internal hostnames\n4. Use default vhost that returns 404",
    },
    "web_cache_deception": {
        "title": "Web Cache Deception",
        "severity": "high",
        "cwe_id": "CWE-525",
        "description": "Tricking cache into storing authenticated responses by appending cacheable extensions to URLs.",
        "impact": "Cached authenticated content accessible to attackers, PII leakage, session data exposure.",
        "remediation": "1. Set proper Cache-Control headers\n2. Use Vary: Cookie header\n3. Only cache static file extensions\n4. Validate URL path before caching",
    },
    "xs_leak": {
        "title": "Cross-Site Leak (XS-Leak)",
        "severity": "medium",
        "cwe_id": "CWE-203",
        "description": "Side-channel techniques that infer cross-origin information via timing, error events, or resource sizes.",
        "impact": "User state detection, search result inference, private data leakage across origins.",
        "remediation": "1. Use SameSite=Lax cookies\n2. Implement CORP/COEP headers\n3. Normalize error responses\n4. Use Fetch Metadata for request filtering",
    },
    "xslt_injection": {
        "title": "XSLT Injection",
        "severity": "high",
        "cwe_id": "CWE-91",
        "description": "User input processed by XSLT transformations enabling file read or code execution.",
        "impact": "File read, SSRF, remote code execution depending on XSLT processor capabilities.",
        "remediation": "1. Disable XSLT extensions\n2. Use XSLT 1.0 without extensions\n3. Sandbox XSLT processing\n4. Validate XML input before transformation",
    },
}

# Convenience: all new type keys
NEW_VULN_TYPE_KEYS = sorted(NEW_VULN_TYPES.keys())
