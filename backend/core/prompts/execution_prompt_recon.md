# Reconnaissance — Execution Guidance

## Objective
Map the target's attack surface through OSINT, DNS analysis, technology fingerprinting,
and endpoint enumeration. Do NOT attempt exploitation, vulnerability scanning, login,
or credential testing.

## Cognitive Loop

### Phase 1: Passive Reconnaissance (Budget 0-30%)

1. **DNS & WHOIS**
   - `dig {target} ANY`, `dig {target} MX`, `dig {target} TXT`
   - `whois {domain}`
   - `dnsx -d {domain} -a -aaaa -mx -ns -txt`

2. **Passive OSINT**
   - `gau {domain}` — historical URLs from Wayback Machine
   - `waybackurls {domain}` — archived endpoints
   - Check robots.txt, sitemap.xml, security.txt

### Phase 2: Active Enumeration (Budget 30-70%)

1. **Port & Service Scanning**
   - `nmap -sV -sC -p- {target}` — port scan with service detection
   - `masscan -p1-65535 {target} --rate=1000` — fast port scan

2. **Technology Fingerprinting**
   - `httpx -title -tech-detect -status-code -silent -u {target}`
   - `wafw00f {target}` — WAF/CDN detection
   - `whatweb {target}` — technology stack

3. **Subdomain Discovery**
   - `subfinder -d {domain} -silent` — passive subdomain enumeration
   - `dnsx -d {domain} -wordlist /opt/wordlists/subdomains-5000.txt`

4. **Endpoint & Content Discovery**
   - `gobuster dir -u {target} -w /opt/wordlists/common.txt -t 50`
   - `ffuf -u {target}/FUZZ -w /opt/wordlists/common.txt -mc 200,301,302,403`
   - `katana -u {target} -d 3 -silent` — crawl
   - Browser: `browser_navigate` + `browser_extract_links`

5. **Form & Input Mapping** (map only, do NOT submit)
   - `browser_extract_forms` — identify all forms, note field names
   - Document: login forms, search forms, upload forms, API endpoints
   - Note authentication mechanisms (cookie, JWT, API key, OAuth)

### Phase 3: Analysis & Reporting (Budget 70-100%)

1. **HTTP Header Analysis**
   - Security headers (CSP, HSTS, X-Frame-Options, etc.)
   - Server version disclosure
   - Cookie flags (HttpOnly, Secure, SameSite)

2. **Attack Surface Documentation**
   - Total endpoints discovered
   - Technologies and versions identified
   - Authentication mechanisms found
   - Potential entry points (forms, APIs, file uploads)
   - Infrastructure details (CDN, WAF, hosting)

3. Report findings and stop

---

## Payload Database

Use `get_vuln_info` to look up CWE IDs, severity ratings, and remediation guidance for documentation purposes:
- `get_vuln_info(vuln_type="", list_types=true)` — list all available types

Do NOT use `get_payloads` — payloads are not needed for reconnaissance.

---

## Batch Gate Protocol

**Run tools in parallel when**:
- Scanning multiple ports/hosts simultaneously
- Making independent HTTP GET requests for enumeration
- Running multiple passive recon tools

**Run tools sequentially when**:
- Next step depends on previous result (e.g., need subdomains before port scanning them)
- Rate limiting may be an issue

---

## FORBIDDEN Actions

These will be **BLOCKED by the governance layer** — do not attempt them:

- Do NOT submit any forms (`browser_submit_form` is blocked)
- Do NOT test credentials or attempt login
- Do NOT run vulnerability scanners (nuclei, nikto, dalfox, wfuzz)
- Do NOT send exploitation payloads
- Do NOT use sqlmap, hydra, commix, or any exploitation tool
- Do NOT attempt password guessing or brute force
- Do NOT use `get_payloads` — no payloads needed for recon
- Do NOT send POST requests with credential data to login endpoints
- Do NOT test for SQL injection, XSS, command injection, or any vulnerability
