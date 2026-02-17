"""
NeuroSploit v3 - Persistent Cross-Session Memory

Records attack outcomes and builds cumulative target knowledge.
Provides priority payloads and context for agent prompts.
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.memory import AttackPatternMemory, TargetFingerprint, SuccessfulPayload

logger = logging.getLogger(__name__)


class PersistentMemory:
    """Cross-session learning engine backed by SQLite."""

    def __init__(self, db_session_factory):
        """
        Args:
            db_session_factory: async callable that returns an AsyncSession context manager
        """
        self._session_factory = db_session_factory

    # ------------------------------------------------------------------
    # Record outcomes
    # ------------------------------------------------------------------

    async def record_attack(
        self,
        domain: str,
        vuln_type: str,
        success: bool,
        payload: str = "",
        parameter: str = "",
        endpoint: str = "",
        tech_stack: Optional[List[str]] = None,
        confidence: float = 0.0,
        severity: str = "",
        notes: str = "",
    ):
        """Record an attack attempt outcome for cross-session learning."""
        async with self._session_factory() as db:
            # Record the pattern
            pattern = AttackPatternMemory(
                domain=domain,
                vuln_type=vuln_type,
                tech_stack=tech_stack or [],
                payload=payload,
                parameter=parameter,
                endpoint=endpoint,
                success=success,
                confidence=confidence,
                severity=severity,
                notes=notes,
            )
            db.add(pattern)

            # If successful, record/update the payload
            if success and payload:
                tag = self._tech_tag(tech_stack)
                await self._upsert_payload(
                    db, vuln_type, tag, payload, parameter, endpoint,
                    domain, confidence, severity,
                )

            # Update target fingerprint
            await self._update_fingerprint(
                db, domain, tech_stack, vuln_type, endpoint, severity, success,
            )

            await db.commit()

    async def _upsert_payload(
        self, db: AsyncSession, vuln_type: str, tech_tag: str,
        payload: str, parameter: str, endpoint: str,
        domain: str, confidence: float, severity: str,
    ):
        """Insert or increment a successful payload."""
        # Generalize endpoint pattern
        pattern = self._generalize_endpoint(endpoint)

        existing = (
            await db.execute(
                select(SuccessfulPayload).where(
                    SuccessfulPayload.vuln_type == vuln_type,
                    SuccessfulPayload.payload == payload,
                    SuccessfulPayload.tech_stack_tag == tech_tag,
                )
            )
        ).scalar_one_or_none()

        if existing:
            existing.success_count += 1
            existing.last_success_domain = domain
            existing.confidence = max(existing.confidence, confidence)
            existing.updated_at = datetime.utcnow()
        else:
            db.add(SuccessfulPayload(
                vuln_type=vuln_type,
                tech_stack_tag=tech_tag,
                payload=payload,
                parameter=parameter,
                endpoint_pattern=pattern,
                last_success_domain=domain,
                confidence=confidence,
                severity=severity,
            ))

    async def _update_fingerprint(
        self, db: AsyncSession, domain: str,
        tech_stack: Optional[List[str]], vuln_type: str,
        endpoint: str, severity: str, success: bool,
    ):
        """Update or create target fingerprint."""
        fp = (
            await db.execute(
                select(TargetFingerprint).where(TargetFingerprint.domain == domain)
            )
        ).scalar_one_or_none()

        if not fp:
            fp = TargetFingerprint(domain=domain, scan_count=1, last_scanned=datetime.utcnow())
            db.add(fp)
        else:
            fp.scan_count += 1
            fp.last_scanned = datetime.utcnow()

        if tech_stack:
            existing = set(fp.tech_stack or [])
            existing.update(tech_stack)
            fp.tech_stack = sorted(existing)

        if success and severity:
            vulns = list(fp.known_vulns or [])
            vulns.append({"type": vuln_type, "endpoint": endpoint, "severity": severity})
            # Keep last 100
            fp.known_vulns = vulns[-100:]

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    async def get_priority_payloads(
        self, vuln_type: str, tech_stack: Optional[List[str]] = None, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get highest-success payloads for a vuln type, optionally filtered by tech stack."""
        async with self._session_factory() as db:
            query = (
                select(SuccessfulPayload)
                .where(SuccessfulPayload.vuln_type == vuln_type)
                .order_by(desc(SuccessfulPayload.success_count), desc(SuccessfulPayload.confidence))
                .limit(limit)
            )

            if tech_stack:
                tag = self._tech_tag(tech_stack)
                query = query.where(SuccessfulPayload.tech_stack_tag == tag)

            rows = (await db.execute(query)).scalars().all()
            return [
                {
                    "payload": r.payload,
                    "parameter": r.parameter,
                    "endpoint_pattern": r.endpoint_pattern,
                    "success_count": r.success_count,
                    "confidence": r.confidence,
                    "severity": r.severity,
                }
                for r in rows
            ]

    async def get_target_fingerprint(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get cumulative knowledge about a target."""
        async with self._session_factory() as db:
            fp = (
                await db.execute(
                    select(TargetFingerprint).where(TargetFingerprint.domain == domain)
                )
            ).scalar_one_or_none()

            if not fp:
                return None
            return {
                "domain": fp.domain,
                "tech_stack": fp.tech_stack,
                "waf_detected": fp.waf_detected,
                "open_ports": fp.open_ports,
                "interesting_paths": fp.interesting_paths,
                "known_vulns": fp.known_vulns,
                "auth_type": fp.auth_type,
                "scan_count": fp.scan_count,
                "last_scanned": fp.last_scanned.isoformat() if fp.last_scanned else None,
            }

    async def update_target_fingerprint(self, domain: str, updates: Dict[str, Any]):
        """Update specific fields on a target fingerprint."""
        async with self._session_factory() as db:
            fp = (
                await db.execute(
                    select(TargetFingerprint).where(TargetFingerprint.domain == domain)
                )
            ).scalar_one_or_none()

            if not fp:
                fp = TargetFingerprint(domain=domain)
                db.add(fp)

            for key, value in updates.items():
                if hasattr(fp, key):
                    setattr(fp, key, value)

            await db.commit()

    async def get_priority_vuln_types(
        self, tech_stack: Optional[List[str]] = None, limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Get vuln types ranked by historical success rate."""
        async with self._session_factory() as db:
            query = (
                select(
                    AttackPatternMemory.vuln_type,
                    func.count().label("total"),
                    func.sum(AttackPatternMemory.success.cast(Integer)).label("successes"),
                )
                .group_by(AttackPatternMemory.vuln_type)
                .order_by(desc("successes"))
                .limit(limit)
            )
            rows = (await db.execute(query)).all()
            return [
                {
                    "vuln_type": r[0],
                    "total_attempts": r[1],
                    "successes": r[2] or 0,
                    "success_rate": round((r[2] or 0) / r[1] * 100, 1) if r[1] > 0 else 0,
                }
                for r in rows
            ]

    async def get_context_for_prompt(
        self, domain: str, vuln_type: Optional[str] = None
    ) -> str:
        """Build a context string to prepend to LLM prompts for cross-session learning."""
        parts = []

        # Target history
        fp = await self.get_target_fingerprint(domain)
        if fp:
            parts.append(f"Target {domain} has been scanned {fp['scan_count']} times.")
            if fp["tech_stack"]:
                parts.append(f"Known tech stack: {', '.join(fp['tech_stack'])}")
            if fp["waf_detected"]:
                parts.append(f"WAF detected: {fp['waf_detected']}")
            if fp["known_vulns"]:
                vuln_types = set(v["type"] for v in fp["known_vulns"])
                parts.append(f"Previously found vuln types: {', '.join(vuln_types)}")

        # Priority payloads for this vuln type
        if vuln_type:
            payloads = await self.get_priority_payloads(vuln_type, limit=5)
            if payloads:
                parts.append(f"\nPriority payloads for {vuln_type} (from cross-session memory):")
                for p in payloads:
                    parts.append(
                        f"  - {p['payload'][:100]} "
                        f"(success_count={p['success_count']}, confidence={p['confidence']})"
                    )

        return "\n".join(parts) if parts else ""

    async def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        async with self._session_factory() as db:
            patterns = (
                await db.execute(select(func.count()).select_from(AttackPatternMemory))
            ).scalar() or 0
            targets = (
                await db.execute(select(func.count()).select_from(TargetFingerprint))
            ).scalar() or 0
            payloads = (
                await db.execute(select(func.count()).select_from(SuccessfulPayload))
            ).scalar() or 0
            successes = (
                await db.execute(
                    select(func.count()).select_from(AttackPatternMemory)
                    .where(AttackPatternMemory.success == True)
                )
            ).scalar() or 0

            return {
                "attack_patterns": patterns,
                "target_fingerprints": targets,
                "successful_payloads": payloads,
                "total_successes": successes,
                "success_rate": round(successes / patterns * 100, 1) if patterns > 0 else 0,
            }

    async def clear(self):
        """Clear all persistent memory."""
        from sqlalchemy import delete
        async with self._session_factory() as db:
            await db.execute(delete(AttackPatternMemory))
            await db.execute(delete(TargetFingerprint))
            await db.execute(delete(SuccessfulPayload))
            await db.commit()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tech_tag(tech_stack: Optional[List[str]]) -> str:
        """Create a sorted, normalized tag from tech stack list."""
        if not tech_stack:
            return ""
        return "+".join(sorted(t.lower().strip() for t in tech_stack if t))

    @staticmethod
    def _generalize_endpoint(endpoint: str) -> str:
        """Generalize an endpoint by replacing IDs with placeholders."""
        if not endpoint:
            return ""
        # Replace numeric IDs
        pattern = re.sub(r'/\d+', '/{id}', endpoint)
        # Replace UUIDs
        pattern = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '/{uuid}', pattern, flags=re.IGNORECASE,
        )
        return pattern
