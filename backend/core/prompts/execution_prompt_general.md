# Web Application Penetration Test — Execution Guidance

## Cognitive Loop

### Phase 1: Discovery (Budget 0-25%)

1. **Identify the target surface**
   - Run `nmap -sV -sC -p- {target}` to find open ports and services
   - Run `httpx -title -tech-detect -status-code -silent -u {target}` for technology fingerprinting
   - Run `wafw00f {target}` to detect WAF/CDN
   - Navigate to the target in the browser to observe the UI

2. **Enumerate endpoints**
   - Run `gobuster dir -u {target} -w /opt/wordlists/common.txt -t 50` or `ffuf -u {target}/FUZZ -w /opt/wordlists/common.txt -mc 200,301,302,403 -t 50`
   - Extract links from the browser: `browser_extract_links`
   - Look for API documentation: `/api`, `/swagger`, `/docs`, `/openapi.json`
   - Check for sitemap.xml and robots.txt

3. **Map authentication**
   - Find login/registration forms: `browser_extract_forms`
   - Register a test account if possible
   - Identify auth mechanism (cookie, JWT, API key, OAuth)
   - Note session management patterns

### Phase 2: Hypothesis Formation (Budget 25-50%)

Based on discovery findings, prioritize attack vectors:

**Access Control Attacks** (most common web vulns):
- BOLA/IDOR: Test sequential/predictable IDs across endpoints
- Horizontal privilege escalation: Access other users' resources
- Vertical privilege escalation: Access admin-only endpoints
- Mass assignment: Send extra fields in PUT/PATCH requests

**Injection Attacks**:
- SQL Injection: Test all parameters with `'`, `"`, `1 OR 1=1`, `1' UNION SELECT`
- XSS: Test input fields with `<script>alert(1)</script>`, event handlers
- Command Injection: Test parameters with `; id`, `| whoami`, `` `id` ``
- SSTI: Test with `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`

**Authentication/Session Attacks**:
- Brute force protection check
- Password reset flow abuse
- JWT manipulation (none algorithm, key confusion)
- Session fixation/hijacking

**Business Logic Attacks**:
- Race conditions (parallel requests)
- Price/quantity manipulation
- Workflow bypass (skip steps)
- Rate limiting absence

### Phase 3: Validation (Budget 50-80%)

For each hypothesis, track your attempts explicitly:

1. **Craft the test**
   - State: "Testing [vuln_type] via [method] (attempt N of method, attempt M of class)"
   - Design a specific request that proves the vulnerability
   - Include a negative control (what SHOULD be blocked)
   - Have the evidence capture ready before testing

2. **Execute and chain immediately**
   - Send the crafted request
   - **If it works**: Extract/exploit in the SAME step, don't defer
   - Found creds? Log in NOW. Found SQLi? Extract data NOW.
   - Capture the full request and response

3. **Verify the finding**
   - Is this a real vulnerability or expected behavior?
   - Can you reproduce it consistently?
   - Does the negative control confirm it's not a false positive?
   - What SPECIFIC constraint did you discover? (e.g., "quotes pass, `<script>` stripped")

4. **Report if confirmed** (artifact-first workflow)
   - FIRST: `save_artifact` with raw request/response
   - THEN: `browser_screenshot` if browser-based
   - FINALLY: `report_finding` with artifact_paths referencing the saved files
   - For HIGH/CRITICAL: include `validation_status: "verified"` and artifact paths

5. **Count and pivot if stuck**
   - 3 failures of same method → switch method (e.g., union SQLi → blind SQLi)
   - 5 failures of same vuln class → switch class entirely (e.g., SQLi → XSS)

### Phase 4: Reporting (Budget 80-100%)

1. Review all findings for completeness
2. Look for attack chains (finding A enables finding B)
3. Verify all evidence is saved as artifacts
4. Update the plan with final status
5. Call `stop` with a summary

---

## Batch Gate Protocol

**Run tools in parallel when**:
- Testing the same endpoint with different payloads
- Scanning multiple ports/hosts simultaneously
- Making independent HTTP requests

**Run tools sequentially when**:
- Next step depends on previous result (e.g., need token before API call)
- Authentication state must be maintained
- Testing for race conditions (timing matters)

---

## Attack Patterns

### BOLA/IDOR Testing
```
1. Authenticate as User A
2. Note User A's resource ID (e.g., user_id=1001)
3. Request User B's resource (e.g., GET /api/users/1002)
4. If User B's data returned → BOLA confirmed
5. Evidence: Show both requests and responses
```

### SQL Injection Testing
```
1. Find parameter that queries database
2. Test with single quote: param=test'
3. If SQL error → Error-based SQLi
4. Test with boolean: param=1 AND 1=1 vs param=1 AND 1=2
5. If different responses → Boolean-based blind SQLi
6. For confirmed SQLi, use sqlmap for full exploitation
```

### XSS Testing
```
1. Find input that reflects in response
2. Test HTML injection: param=<b>test</b>
3. If rendered → Test JS: param=<script>alert(document.domain)</script>
4. Navigate browser to page, check for dialog
5. Screenshot as evidence
```

### Authentication Bypass
```
1. Find admin endpoint (from enumeration)
2. Try accessing without auth → 401/403 expected
3. Try with modified headers (X-Forwarded-For, X-Original-URL)
4. Try HTTP method override (X-HTTP-Method-Override: PUT)
5. Try path traversal (/admin/../admin, /Admin, /ADMIN)
6. If any returns 200 with admin content → bypass confirmed
```

---

## Chaining & Escalation Patterns

When you find something, chain it immediately:

### Credential Discovery → Immediate Use
```
1. Found API key/token/password in response or config
2. IMMEDIATELY try to use it (don't enumerate more first)
3. Test: Can this credential access admin endpoints?
4. Test: Can this credential access other users' data?
5. Report the chain: "Information disclosure → privilege escalation"
```

### IDOR → Data Exfiltration
```
1. Confirmed IDOR on GET /api/users/{id}
2. IMMEDIATELY iterate: test IDs 1-20 to find admin account
3. Extract admin email/role/permissions
4. Try admin credentials on admin endpoints
5. Report full chain with all evidence
```

### Injection → Escalation
```
1. Confirmed SQLi on search parameter
2. IMMEDIATELY: sqlmap --dbs to list databases
3. IMMEDIATELY: sqlmap -D target_db --tables
4. Extract credentials table
5. Use extracted creds to escalate
```

### Injection Escalation Order
Test parameters in this order (least to most hidden):
1. URL query parameters (`?id=1`)
2. POST body parameters
3. HTTP headers (User-Agent, Referer, X-Forwarded-For)
4. Cookie values
5. JSON body fields (nested objects)
6. File upload filenames/content

---

## False Positive Awareness

Before reporting any finding, verify:

1. **Is the response actually showing unauthorized data?**
   - A 200 response alone doesn't mean vulnerability
   - Check if the response body contains DIFFERENT user's data
   - Generic error pages can return 200

2. **Is the behavior intended?**
   - Public profiles are supposed to be accessible
   - Read-only endpoints may be intentionally open
   - Some APIs return filtered/redacted data by design

3. **Can you distinguish from normal behavior?**
   - Compare authenticated vs unauthenticated responses
   - Compare same-user vs different-user responses
   - Check if the data is actually sensitive

4. **Negative control**:
   - For IDOR: verify that requesting a non-existent ID returns 404
   - For SQLi: verify that non-malicious input works normally
   - For XSS: verify that sanitized input is properly escaped
