"""
Scan Registry - Central cancellation registry for running scans.

Maps scan_id -> ScanHandle so any code path (ScanService or Agent)
can be stopped immediately via registry.cancel(scan_id).
"""
import asyncio
import os
import signal
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class ScanHandle:
    scan_id: str
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    child_pids: Set[int] = field(default_factory=set)
    task: Optional[asyncio.Task] = None

    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()


_registry: Dict[str, ScanHandle] = {}


def register(scan_id: str, task: Optional[asyncio.Task] = None) -> ScanHandle:
    """Register a scan and return its handle."""
    handle = ScanHandle(scan_id=scan_id, task=task)
    _registry[scan_id] = handle
    logger.info("Registered scan %s", scan_id)
    return handle


def get(scan_id: str) -> Optional[ScanHandle]:
    """Get the handle for a scan, or None."""
    return _registry.get(scan_id)


def cancel(scan_id: str) -> bool:
    """Cancel a scan: set event, SIGTERM/SIGKILL children, cancel asyncio task."""
    handle = _registry.get(scan_id)
    if not handle:
        return False

    # 1. Cooperative flag
    handle.cancel_event.set()

    # 2. Kill tracked child processes (SIGTERM then SIGKILL)
    for pid in list(handle.child_pids):
        try:
            os.kill(pid, signal.SIGTERM)
            logger.info("Sent SIGTERM to PID %d (scan %s)", pid, scan_id)
        except OSError:
            pass

    # Schedule SIGKILL follow-up for any processes that ignore SIGTERM
    if handle.child_pids:
        pids_to_kill = list(handle.child_pids)

        async def _sigkill_followup():
            await asyncio.sleep(3)
            for pid in pids_to_kill:
                try:
                    os.kill(pid, signal.SIGKILL)
                    logger.info("Sent SIGKILL to PID %d (scan %s)", pid, scan_id)
                except OSError:
                    pass  # Process already exited

        try:
            asyncio.get_event_loop().create_task(_sigkill_followup())
        except RuntimeError:
            pass  # No running event loop

    # 3. Cancel the asyncio Task
    if handle.task and not handle.task.done():
        handle.task.cancel()
        logger.info("Cancelled asyncio task for scan %s", scan_id)

    return True


def unregister(scan_id: str) -> None:
    """Remove a scan from the registry."""
    _registry.pop(scan_id, None)
    logger.info("Unregistered scan %s", scan_id)


def track_pid(scan_id: str, pid: int) -> None:
    """Track a child process PID for a scan."""
    handle = _registry.get(scan_id)
    if handle:
        handle.child_pids.add(pid)


def untrack_pid(scan_id: str, pid: int) -> None:
    """Stop tracking a child process PID."""
    handle = _registry.get(scan_id)
    if handle:
        handle.child_pids.discard(pid)
