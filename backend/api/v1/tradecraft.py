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
