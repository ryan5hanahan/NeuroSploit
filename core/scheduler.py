#!/usr/bin/env python3
"""
Scan Scheduler - Recurring task orchestration for NeuroSploit.

Supports cron expressions and interval-based scheduling for:
- Reconnaissance scans
- Vulnerability validation
- Re-analysis of previous findings

Uses APScheduler with SQLite persistence so jobs survive restarts.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
    HAS_APSCHEDULER = True
except ImportError:
    HAS_APSCHEDULER = False
    logger.warning("APScheduler not installed. Scheduler disabled. Install with: pip install apscheduler>=3.10.0")


class ScanScheduler:
    """Manages recurring scan jobs via APScheduler."""

    def __init__(self, config: Dict, database_url: str = "sqlite:///./data/neurosploit_scheduler.db"):
        self.config = config
        self.scheduler_config = config.get('scheduler', {})
        self.enabled = self.scheduler_config.get('enabled', False)
        self.jobs_meta: Dict[str, Dict] = {}  # job_id -> metadata
        self._scan_callback = None

        if not HAS_APSCHEDULER:
            self.enabled = False
            self.scheduler = None
            return

        jobstores = {
            'default': SQLAlchemyJobStore(url=database_url)
        }
        self.scheduler = AsyncIOScheduler(jobstores=jobstores)

        # Load pre-configured jobs from config
        for job_config in self.scheduler_config.get('jobs', []):
            try:
                self.add_job(
                    job_id=job_config['id'],
                    target=job_config['target'],
                    scan_type=job_config.get('scan_type', 'quick'),
                    cron_expression=job_config.get('cron'),
                    interval_minutes=job_config.get('interval_minutes'),
                    agent_role=job_config.get('agent_role'),
                    llm_profile=job_config.get('llm_profile')
                )
            except Exception as e:
                logger.error(f"Failed to load scheduled job '{job_config.get('id', '?')}': {e}")

    def set_scan_callback(self, callback):
        """Set the callback function that executes scans.

        The callback signature should be:
            async def callback(target: str, scan_type: str,
                             agent_role: Optional[str], llm_profile: Optional[str]) -> Dict
        """
        self._scan_callback = callback

    def add_job(self, job_id: str, target: str, scan_type: str = "quick",
                cron_expression: Optional[str] = None,
                interval_minutes: Optional[int] = None,
                agent_role: Optional[str] = None,
                llm_profile: Optional[str] = None) -> Dict:
        """Schedule a recurring scan job.

        Args:
            job_id: Unique identifier for the job
            target: Target URL or IP
            scan_type: 'quick', 'full', 'recon', or 'analysis'
            cron_expression: Cron schedule (e.g., '0 */6 * * *' for every 6 hours)
            interval_minutes: Alternative to cron - run every N minutes
            agent_role: Optional agent role for AI analysis
            llm_profile: Optional LLM profile override
        """
        if not self.scheduler:
            return {"error": "Scheduler not available (APScheduler not installed)"}

        if cron_expression:
            trigger = CronTrigger.from_crontab(cron_expression)
            schedule_desc = f"cron: {cron_expression}"
        elif interval_minutes:
            trigger = IntervalTrigger(minutes=interval_minutes)
            schedule_desc = f"every {interval_minutes} minutes"
        else:
            return {"error": "Provide either cron_expression or interval_minutes"}

        self.scheduler.add_job(
            self._execute_scheduled_scan,
            trigger=trigger,
            id=job_id,
            args=[job_id, target, scan_type, agent_role, llm_profile],
            replace_existing=True,
            name=schedule_desc,
        )

        meta = {
            "id": job_id,
            "target": target,
            "scan_type": scan_type,
            "schedule": schedule_desc,
            "agent_role": agent_role,
            "llm_profile": llm_profile,
            "created_at": datetime.now().isoformat(),
            "last_run": None,
            "run_count": 0,
            "status": "active"
        }
        self.jobs_meta[job_id] = meta

        logger.info(f"Scheduled job '{job_id}': {target} ({scan_type}) - {schedule_desc}")
        return meta

    def remove_job(self, job_id: str) -> bool:
        """Remove a scheduled job."""
        if not self.scheduler:
            return False
        try:
            self.scheduler.remove_job(job_id)
            self.jobs_meta.pop(job_id, None)
            logger.info(f"Removed scheduled job: {job_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove job '{job_id}': {e}")
            return False

    def pause_job(self, job_id: str) -> bool:
        """Pause a scheduled job."""
        if not self.scheduler:
            return False
        try:
            self.scheduler.pause_job(job_id)
            if job_id in self.jobs_meta:
                self.jobs_meta[job_id]["status"] = "paused"
            return True
        except Exception as e:
            logger.error(f"Failed to pause job '{job_id}': {e}")
            return False

    def resume_job(self, job_id: str) -> bool:
        """Resume a paused job."""
        if not self.scheduler:
            return False
        try:
            self.scheduler.resume_job(job_id)
            if job_id in self.jobs_meta:
                self.jobs_meta[job_id]["status"] = "active"
            return True
        except Exception as e:
            logger.error(f"Failed to resume job '{job_id}': {e}")
            return False

    def list_jobs(self) -> List[Dict]:
        """List all scheduled jobs with metadata."""
        jobs = []
        if self.scheduler:
            for job in self.scheduler.get_jobs():
                meta = self.jobs_meta.get(job.id, {})
                jobs.append({
                    "id": job.id,
                    "name": job.name,
                    "next_run": str(job.next_run_time) if job.next_run_time else None,
                    "target": meta.get("target", "unknown"),
                    "scan_type": meta.get("scan_type", "unknown"),
                    "schedule": meta.get("schedule", "unknown"),
                    "status": meta.get("status", "active"),
                    "last_run": meta.get("last_run"),
                    "run_count": meta.get("run_count", 0),
                    "agent_role": meta.get("agent_role"),
                    "llm_profile": meta.get("llm_profile"),
                })
        return jobs

    async def _execute_scheduled_scan(self, job_id: str, target: str,
                                       scan_type: str,
                                       agent_role: Optional[str],
                                       llm_profile: Optional[str]):
        """Execute a scheduled scan. Called by APScheduler."""
        logger.info(f"Executing scheduled scan [{job_id}]: {target} ({scan_type})")

        if job_id in self.jobs_meta:
            self.jobs_meta[job_id]["last_run"] = datetime.now().isoformat()
            self.jobs_meta[job_id]["run_count"] += 1

        if self._scan_callback:
            try:
                result = await self._scan_callback(target, scan_type, agent_role, llm_profile)
                logger.info(f"Scheduled scan completed: {target} ({scan_type})")
                return result
            except Exception as e:
                logger.error(f"Scheduled scan failed for {target}: {e}")
        else:
            logger.warning("No scan callback registered. Scheduled scan skipped.")

    def _rehydrate_meta(self):
        """Reconstruct ``jobs_meta`` from APScheduler's persisted jobs.

        On startup the SQLite jobstore already contains previously added jobs,
        but the in-memory ``jobs_meta`` dict is empty.  Walk persisted jobs and
        rebuild metadata from the stored ``job.args`` and ``job.name`` (which
        stores the human-readable schedule description).
        """
        for job in self.scheduler.get_jobs():
            if job.id not in self.jobs_meta:
                args = job.args or []
                self.jobs_meta[job.id] = {
                    "id": job.id,
                    "target": args[1] if len(args) > 1 else "unknown",
                    "scan_type": args[2] if len(args) > 2 else "unknown",
                    "schedule": job.name or "unknown",
                    "agent_role": args[3] if len(args) > 3 else None,
                    "llm_profile": args[4] if len(args) > 4 else None,
                    "created_at": None,
                    "last_run": None,
                    "run_count": 0,
                    "status": "paused" if job.next_run_time is None else "active",
                }

    def start(self):
        """Start the scheduler.

        Always starts the APScheduler instance so pending jobs are flushed
        to the SQLite jobstore.  When ``self.enabled`` is False the scheduler
        starts in *paused* mode — jobs are persisted and visible via
        ``get_jobs()`` but triggers won't fire.
        """
        if self.scheduler:
            if self.enabled:
                self.scheduler.start()
            else:
                self.scheduler.start(paused=True)
            self._rehydrate_meta()
            logger.info(f"Scheduler started (enabled={self.enabled}) with {len(self.list_jobs())} jobs")

    def stop(self):
        """Stop the scheduler gracefully."""
        if self.scheduler and self.scheduler.running:
            self.scheduler.shutdown(wait=False)
            logger.info("Scheduler stopped")
