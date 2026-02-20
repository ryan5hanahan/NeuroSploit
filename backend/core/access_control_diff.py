"""
sploit.ai - Access Control Differential Testing Engine

Compares HTTP responses across multiple authenticated contexts to detect:
  - BOLA (Broken Object Level Authorization)
  - BFLA (Broken Function Level Authorization)
  - Privilege escalation
  - Broken access control

Self-contained: no ORM or async dependencies.
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Roles ordered from least to most privileged
ROLE_HIERARCHY = {"guest": 0, "user": 1, "moderator": 2, "admin": 3}

# Fields whose presence in a response signals private data
PRIVATE_DATA_FIELDS = {
    "email", "phone", "ssn", "social_security", "password", "password_hash",
    "credit_card", "card_number", "cvv", "secret", "private_key", "api_key",
    "address", "date_of_birth", "dob", "salary", "bank_account",
}

# Fields whose presence signals admin-level data
ADMIN_DATA_FIELDS = {
    "is_admin", "permissions", "all_users", "user_list", "admin_panel",
    "role", "roles", "privileges", "internal_ip", "debug", "config",
    "secret_key", "database_url", "connection_string",
}


@dataclass
class ContextResponse:
    """Response captured for a single auth context against one endpoint."""
    label: str
    role: str
    status: int
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    latency_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class DiffResult:
    """A differential finding from comparing contexts."""
    endpoint: str
    method: str
    responses: List[Dict] = field(default_factory=list)  # Serialized ContextResponses
    finding_type: str = ""  # bola, bfla, privilege_escalation, status_diff
    severity: str = "medium"
    confidence: float = 0.0
    attacker_label: str = ""
    victim_label: str = ""
    evidence: str = ""
    delta_type: str = ""  # status_diff, body_diff, write_diff, private_data, admin_data


class AccessControlDiffEngine:
    """Compares responses across authenticated contexts to detect access control flaws."""

    def __init__(self, context_labels: List[Tuple[str, str]]):
        """
        Args:
            context_labels: list of (label, role) tuples, e.g.
                [("admin_ctx", "admin"), ("user_alice", "user"), ("guest_ctx", "guest")]
        """
        self.context_labels = context_labels
        self._label_to_role = {label: role for label, role in context_labels}

    def _role_level(self, role: str) -> int:
        return ROLE_HIERARCHY.get(role.lower(), 1)

    def compare(self, endpoint: str, method: str, responses: List[ContextResponse]) -> List[DiffResult]:
        """Compare responses from all contexts for one endpoint.

        Returns a list of DiffResults (may be empty if no issues found).
        """
        results: List[DiffResult] = []
        if len(responses) < 2:
            return results

        # Index by label
        by_label = {r.label: r for r in responses}

        # Check 1: Status code differential
        results.extend(self._check_status_diff(endpoint, method, responses, by_label))

        # Check 2: Body content differential
        results.extend(self._check_body_diff(endpoint, method, responses, by_label))

        # Check 3: Write operation differential
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            results.extend(self._check_write_diff(endpoint, method, responses, by_label))

        return results

    def _check_status_diff(
        self, endpoint: str, method: str,
        responses: List[ContextResponse], by_label: Dict[str, ContextResponse]
    ) -> List[DiffResult]:
        """Detect status code differentials suggesting access control bypass."""
        results = []
        # For each pair, check if a lower-privileged context gets 200 where
        # a higher-privileged one would expect exclusive access (403/401)
        for i, r1 in enumerate(responses):
            for r2 in responses[i + 1:]:
                level1 = self._role_level(r1.role)
                level2 = self._role_level(r2.role)

                # Determine attacker (lower role) and victim (higher role)
                if level1 < level2:
                    low, high = r1, r2
                elif level2 < level1:
                    low, high = r2, r1
                else:
                    # Same role level: check for BOLA (same status but different objects)
                    if r1.status == r2.status == 200 and r1.body != r2.body:
                        # Could be BOLA if they access each other's data
                        continue  # Handled by body diff check
                    continue

                # Lower-priv gets 200, higher-priv gets 403/401 → unusual but possible reverse
                # Lower-priv gets 200 when it should be denied → BFLA
                if low.status in (200, 201, 204) and high.status in (403, 401):
                    # This is actually expected: high priv should get 200.
                    # Reverse: if low gets access to something that the system
                    # tries to restrict... but that means the higher role was denied.
                    # Skip this — it's the expected behavior.
                    pass

                # The real signal: check if both get 200 when lower shouldn't
                # We look for endpoints where higher-priv gets 200 AND lower-priv also gets 200
                # when there's reason to expect lower should be denied.
                if high.status in (200, 201, 204) and low.status in (200, 201, 204):
                    # Both succeed — might be BFLA if the endpoint is admin-only
                    # (Body diff will handle the details)
                    pass

                # Lower-priv gets success where it shouldn't
                if low.status in (200, 201, 204) and high.status in (200, 201, 204):
                    # Need body analysis to determine if this is meaningful
                    pass

                # Explicit: lower priv gets 200, higher priv gets 403/401
                # This is reversed access control — definitely a bug
                if low.status in (200, 201, 204) and high.status in (401, 403):
                    results.append(DiffResult(
                        endpoint=endpoint,
                        method=method,
                        finding_type="bfla",
                        severity="high",
                        confidence=0.75,
                        attacker_label=low.label,
                        victim_label=high.label,
                        evidence=(
                            f"Lower-privilege context '{low.label}' ({low.role}) gets {low.status} "
                            f"while higher-privilege '{high.label}' ({high.role}) gets {high.status}. "
                            f"Reversed access control detected."
                        ),
                        delta_type="status_diff",
                    ))

        return results

    def _check_body_diff(
        self, endpoint: str, method: str,
        responses: List[ContextResponse], by_label: Dict[str, ContextResponse]
    ) -> List[DiffResult]:
        """Detect private/admin data leaking to lower-priv contexts."""
        results = []

        for i, r1 in enumerate(responses):
            for r2 in responses[i + 1:]:
                if r1.status != 200 or r2.status != 200:
                    continue

                level1 = self._role_level(r1.role)
                level2 = self._role_level(r2.role)

                if level1 == level2:
                    # Same role level: check for BOLA (cross-user data access)
                    bola = self._check_cross_user_data(endpoint, method, r1, r2)
                    if bola:
                        results.append(bola)
                    continue

                # Determine low/high privilege
                if level1 < level2:
                    low, high = r1, r2
                else:
                    low, high = r2, r1

                # Parse JSON bodies
                low_fields = self._extract_json_fields(low.body)
                high_fields = self._extract_json_fields(high.body)

                if not low_fields and not high_fields:
                    # Compare body lengths as heuristic
                    if len(low.body) > 0 and len(high.body) > 0:
                        ratio = len(low.body) / max(len(high.body), 1)
                        if ratio > 2.0 or (len(low.body) > len(high.body) * 2):
                            results.append(DiffResult(
                                endpoint=endpoint,
                                method=method,
                                finding_type="bola",
                                severity="medium",
                                confidence=0.45,
                                attacker_label=low.label,
                                victim_label=high.label,
                                evidence=(
                                    f"Lower-privilege response body ({len(low.body)} bytes) is >2x "
                                    f"the higher-privilege body ({len(high.body)} bytes). "
                                    f"Possible data over-exposure."
                                ),
                                delta_type="body_diff",
                            ))
                    continue

                # Check for private data fields visible to lower-priv
                low_private = low_fields & PRIVATE_DATA_FIELDS
                high_private = high_fields & PRIVATE_DATA_FIELDS
                leaked_private = low_private - high_private
                if low_private:
                    results.append(DiffResult(
                        endpoint=endpoint,
                        method=method,
                        finding_type="bola",
                        severity="high",
                        confidence=0.80,
                        attacker_label=low.label,
                        victim_label=high.label,
                        evidence=(
                            f"Private data fields visible to '{low.label}' ({low.role}): "
                            f"{', '.join(sorted(low_private))}. "
                            f"{'Fields unique to lower context: ' + ', '.join(sorted(leaked_private)) if leaked_private else ''}"
                        ),
                        delta_type="private_data",
                    ))

                # Check for admin data fields visible to non-admin
                if self._role_level(low.role) < ROLE_HIERARCHY.get("admin", 3):
                    low_admin = low_fields & ADMIN_DATA_FIELDS
                    if low_admin:
                        results.append(DiffResult(
                            endpoint=endpoint,
                            method=method,
                            finding_type="bfla",
                            severity="high",
                            confidence=0.85,
                            attacker_label=low.label,
                            victim_label=high.label,
                            evidence=(
                                f"Admin-level data fields visible to non-admin '{low.label}' ({low.role}): "
                                f"{', '.join(sorted(low_admin))}"
                            ),
                            delta_type="admin_data",
                        ))

        return results

    def _check_cross_user_data(
        self, endpoint: str, method: str,
        r1: ContextResponse, r2: ContextResponse
    ) -> Optional[DiffResult]:
        """Check for BOLA between same-role users (can one see the other's data)."""
        fields1 = self._extract_json_fields(r1.body)
        fields2 = self._extract_json_fields(r2.body)

        if not fields1 or not fields2:
            return None

        # If both responses contain the same private fields but with different values,
        # and the endpoint contains user-specific identifiers, it may be BOLA
        shared_private = (fields1 & PRIVATE_DATA_FIELDS) & (fields2 & PRIVATE_DATA_FIELDS)
        if shared_private and r1.body != r2.body:
            return DiffResult(
                endpoint=endpoint,
                method=method,
                finding_type="bola",
                severity="high",
                confidence=0.60,
                attacker_label=r1.label,
                victim_label=r2.label,
                evidence=(
                    f"Same-role users '{r1.label}' and '{r2.label}' both see private fields "
                    f"({', '.join(sorted(shared_private))}) but with different values — "
                    f"potential cross-user data access."
                ),
                delta_type="body_diff",
            )

        return None

    def _check_write_diff(
        self, endpoint: str, method: str,
        responses: List[ContextResponse], by_label: Dict[str, ContextResponse]
    ) -> List[DiffResult]:
        """Detect write operations succeeding for non-admin contexts."""
        results = []

        for resp in responses:
            if resp.status not in (200, 201, 204):
                continue
            if self._role_level(resp.role) >= ROLE_HIERARCHY.get("admin", 3):
                continue

            # Non-admin succeeded on a write endpoint
            # Check if any admin context also succeeded (confirming it's a real write endpoint)
            admin_success = any(
                r.status in (200, 201, 204)
                for r in responses
                if self._role_level(r.role) >= ROLE_HIERARCHY.get("admin", 3)
            )
            if admin_success:
                results.append(DiffResult(
                    endpoint=endpoint,
                    method=method,
                    finding_type="bfla",
                    severity="high",
                    confidence=0.70,
                    attacker_label=resp.label,
                    victim_label="admin",
                    evidence=(
                        f"Non-admin '{resp.label}' ({resp.role}) successfully performed "
                        f"{method.upper()} on {endpoint} (status {resp.status}). "
                        f"Admin context also succeeds — confirms this is a privileged operation."
                    ),
                    delta_type="write_diff",
                ))

        return results

    def _extract_json_fields(self, body: str) -> set:
        """Extract all field names from a JSON response body (recursive)."""
        if not body or not body.strip():
            return set()
        try:
            data = json.loads(body)
            return self._collect_keys(data)
        except (json.JSONDecodeError, ValueError):
            return set()

    def _collect_keys(self, obj, prefix: str = "") -> set:
        """Recursively collect all keys from a JSON structure."""
        keys = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.add(k.lower())
                keys.update(self._collect_keys(v, f"{prefix}{k}."))
        elif isinstance(obj, list):
            for item in obj[:5]:  # Limit list traversal
                keys.update(self._collect_keys(item, prefix))
        return keys

    def finding_to_dict(self, diff: DiffResult) -> dict:
        """Convert a DiffResult into a Finding-compatible dict."""
        return {
            "title": f"Access Control: {diff.finding_type.upper()} on {diff.endpoint}",
            "severity": diff.severity,
            "vulnerability_type": diff.finding_type,
            "affected_endpoint": diff.endpoint,
            "evidence": diff.evidence,
            "description": (
                f"Differential access control testing detected {diff.finding_type.upper()} "
                f"({diff.delta_type}) on {diff.method} {diff.endpoint}. "
                f"Attacker context: {diff.attacker_label}, Victim context: {diff.victim_label}."
            ),
            "confidence": diff.confidence,
            "credential_label": diff.attacker_label,
            "auth_context": {
                "finding_type": diff.finding_type,
                "delta_type": diff.delta_type,
                "attacker_label": diff.attacker_label,
                "attacker_role": self._label_to_role.get(diff.attacker_label, ""),
                "victim_label": diff.victim_label,
                "victim_role": self._label_to_role.get(diff.victim_label, ""),
                "method": diff.method,
            },
            "remediation": _remediation_for(diff.finding_type),
            "cwe_id": _cwe_for(diff.finding_type),
            "references": _references_for(diff.finding_type),
        }


def _remediation_for(finding_type: str) -> str:
    recs = {
        "bola": "Implement object-level authorization checks. Verify that the authenticated user owns or has access to the requested resource before returning data.",
        "bfla": "Implement function-level authorization checks. Verify the user's role/permissions before allowing access to administrative endpoints or operations.",
        "privilege_escalation": "Enforce strict role-based access control (RBAC). Never rely solely on client-side role checks.",
        "status_diff": "Review endpoint authorization logic to ensure consistent access control across all authentication contexts.",
    }
    return recs.get(finding_type, "Review and fix the access control logic for this endpoint.")


def _cwe_for(finding_type: str) -> str:
    cwes = {
        "bola": "CWE-639",
        "bfla": "CWE-285",
        "privilege_escalation": "CWE-269",
        "status_diff": "CWE-863",
    }
    return cwes.get(finding_type, "CWE-284")


def _references_for(finding_type: str) -> list:
    refs = {
        "bola": [
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        ],
        "bfla": [
            "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
        ],
    }
    return refs.get(finding_type, ["https://owasp.org/www-project-web-security-testing-guide/"])
