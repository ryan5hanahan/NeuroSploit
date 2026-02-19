"""
Vulnerability Enrichment Service.

Queue-based singleton that enriches Vulnerability records with CVE data from
NVD and known-exploit data from ExploitDB.  Processes items serially to
respect NVD rate limits.

Usage:
    svc = VulnEnrichmentService.get_instance()
    await svc.start()                     # call once at app startup
    await svc.enqueue(vuln_id, scan_id)   # after each Vulnerability flush
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import Optional

import aiohttp
from sqlalchemy import select

from backend.api.websocket import manager as ws_manager
from backend.core.osint.nvd_client import NVDClient
from backend.core.osint.exploitdb_client import ExploitDBClient
from backend.db.database import async_session_factory

logger = logging.getLogger(__name__)


class VulnEnrichmentService:
    _instance: Optional["VulnEnrichmentService"] = None

    def __init__(self):
        self._queue: asyncio.Queue = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None
        self._nvd: Optional[NVDClient] = None
        self._edb: Optional[ExploitDBClient] = None

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    @classmethod
    def get_instance(cls) -> "VulnEnrichmentService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def _enabled(self) -> bool:
        return os.getenv("ENABLE_VULN_ENRICHMENT", "true").lower() in ("true", "1", "yes")

    async def start(self):
        """Start the background enrichment worker (called once at app startup)."""
        if not self._enabled:
            logger.info("Vulnerability enrichment disabled (ENABLE_VULN_ENRICHMENT=false)")
            return

        nvd_key = os.getenv("NVD_API_KEY", "")
        self._nvd = NVDClient(api_key=nvd_key)
        self._edb = ExploitDBClient()

        self._worker_task = asyncio.create_task(self._worker_loop())
        logger.info("Vulnerability enrichment worker started")

    async def stop(self):
        """Gracefully stop the worker."""
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("Vulnerability enrichment worker stopped")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def enqueue(self, vuln_id: str, scan_id: str):
        """Add a vulnerability to the enrichment queue."""
        if not self._enabled:
            return
        await self._queue.put((vuln_id, scan_id))

    async def enrich_now(self, vuln_id: str) -> dict:
        """Immediately enrich a single vulnerability (manual trigger)."""
        async with aiohttp.ClientSession() as session:
            return await self._enrich_single(vuln_id, session)

    async def enrich_scan(self, scan_id: str) -> int:
        """Enqueue all pending vulns in a scan for enrichment.  Returns count."""
        from backend.models.vulnerability import Vulnerability

        async with async_session_factory() as db:
            stmt = (
                select(Vulnerability.id)
                .where(Vulnerability.scan_id == scan_id)
                .where(Vulnerability.enrichment_status.in_(["pending", "failed"]))
            )
            rows = (await db.execute(stmt)).scalars().all()
            for vid in rows:
                await self.enqueue(vid, scan_id)
            return len(rows)

    # ------------------------------------------------------------------
    # Background worker
    # ------------------------------------------------------------------

    async def _worker_loop(self):
        """Process enrichment queue serially."""
        async with aiohttp.ClientSession() as session:
            while True:
                try:
                    vuln_id, scan_id = await self._queue.get()
                    try:
                        await self._enrich_single(vuln_id, session)
                    except Exception as e:
                        logger.warning(f"Enrichment failed for vuln {vuln_id}: {e}")
                    finally:
                        self._queue.task_done()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Enrichment worker error: {e}")
                    await asyncio.sleep(1)

    # ------------------------------------------------------------------
    # Core enrichment logic
    # ------------------------------------------------------------------

    async def _enrich_single(
        self,
        vuln_id: str,
        http_session: aiohttp.ClientSession,
    ) -> dict:
        """Enrich one vulnerability.  Returns the enrichment data dict."""
        from backend.models.vulnerability import Vulnerability

        async with async_session_factory() as db:
            stmt = select(Vulnerability).where(Vulnerability.id == vuln_id)
            row = await db.execute(stmt)
            vuln = row.scalar_one_or_none()
            if not vuln:
                return {"error": "not_found"}

            # Skip if already enriched
            if vuln.enrichment_status == "complete":
                return {"status": "already_complete"}

            vuln.enrichment_status = "in_progress"
            await db.flush()

            try:
                enrichment: dict = {}
                cve_results = []
                exploit_results = []

                # Build search keyword from vulnerability type
                keyword = (vuln.vulnerability_type or "").replace("_", " ")

                # 1) Query NVD
                if self._nvd:
                    if vuln.cwe_id and keyword:
                        cve_results = await self._nvd.search_by_cwe(
                            vuln.cwe_id, keyword, http_session
                        )
                    elif keyword:
                        cve_results = await self._nvd.search_by_keyword(
                            keyword, http_session
                        )
                    enrichment["nvd"] = cve_results

                cve_ids = [c["cve_id"] for c in cve_results if c.get("cve_id")]

                # 2) Query ExploitDB by matched CVE IDs
                if self._edb and cve_ids:
                    for cve_id in cve_ids:
                        exploits = await self._edb.search_by_cve(cve_id, http_session)
                        exploit_results.extend(exploits)

                # Also try keyword search on ExploitDB
                if self._edb and keyword and not exploit_results:
                    exploit_results = await self._edb.search_by_keyword(
                        keyword, http_session, max_results=5
                    )

                enrichment["exploitdb"] = exploit_results

                # 3) Backfill CVSS from NVD if missing on vuln
                if cve_results and not vuln.cvss_score:
                    best = max(
                        (c for c in cve_results if c.get("cvss_score")),
                        key=lambda c: c["cvss_score"],
                        default=None,
                    )
                    if best:
                        vuln.cvss_score = best["cvss_score"]
                        vuln.cvss_vector = best.get("cvss_vector")

                # 4) Merge NVD references into vuln.references
                existing_refs = set(vuln.references or [])
                new_refs = []
                for cve in cve_results:
                    for ref in cve.get("references", []):
                        if ref and ref not in existing_refs:
                            new_refs.append(ref)
                            existing_refs.add(ref)
                if new_refs:
                    vuln.references = list(vuln.references or []) + new_refs

                # 5) Persist
                vuln.cve_ids = cve_ids
                vuln.known_exploits = [
                    {
                        "edb_id": e.get("edb_id", ""),
                        "title": e.get("title", ""),
                        "platform": e.get("platform", ""),
                        "type": e.get("type", ""),
                    }
                    for e in exploit_results
                ]
                vuln.enrichment_data = enrichment
                vuln.enriched_at = datetime.utcnow()

                if cve_results or exploit_results:
                    vuln.enrichment_status = "complete"
                else:
                    vuln.enrichment_status = "partial"

                await db.commit()

                # 6) Broadcast WebSocket event
                try:
                    await ws_manager.send_to_scan(vuln.scan_id, {
                        "type": "vuln_enriched",
                        "scan_id": vuln.scan_id,
                        "vulnerability_id": vuln.id,
                        "cve_ids": vuln.cve_ids,
                        "known_exploits": vuln.known_exploits,
                        "enrichment_status": vuln.enrichment_status,
                    })
                except Exception:
                    pass  # WS broadcast is best-effort

                return enrichment

            except Exception as e:
                vuln.enrichment_status = "failed"
                await db.commit()
                logger.warning(f"Enrichment error for vuln {vuln_id}: {e}")
                return {"error": str(e)}
