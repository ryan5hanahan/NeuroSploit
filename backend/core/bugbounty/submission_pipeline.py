"""Bug Bounty Submission Pipeline — finding -> format -> deduplicate -> draft -> review -> submit.

SAFETY: NEVER auto-submits without human approval.
"""
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from backend.core.bugbounty.duplicate_detector import DuplicateDetector
from backend.core.bugbounty.report_formatter import H1ReportFormatter

logger = logging.getLogger(__name__)


@dataclass
class SubmissionDraft:
    """A prepared bug bounty submission draft awaiting human review."""
    submission_id: str
    vulnerability_id: str
    program_handle: str
    status: str  # "draft", "approved", "submitted", "rejected"
    draft: Dict[str, Any]
    preview_markdown: str
    duplicate_check: Optional[Dict] = None
    created_at: str = ""
    approved_at: Optional[str] = None
    submitted_at: Optional[str] = None

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()


class SubmissionPipeline:
    """Manages the full lifecycle of bug bounty report submission.

    Pipeline stages:
    1. Format: Convert finding to platform-specific report format
    2. Deduplicate: Check against existing reports
    3. Draft: Create submission draft for human review
    4. Review: Human approves or rejects
    5. Submit: Send approved draft to platform (ONLY after human approval)
    """

    def __init__(
        self,
        hackerone_client=None,
        existing_reports: Optional[List[Dict]] = None,
    ):
        self.h1_client = hackerone_client
        self._duplicate_detector = DuplicateDetector(existing_reports or [])
        self._drafts: Dict[str, SubmissionDraft] = {}

    async def process_finding(
        self,
        finding: Dict[str, Any],
        program_handle: str,
    ) -> SubmissionDraft:
        """Process a finding through the submission pipeline.

        Returns a SubmissionDraft that MUST be approved by a human
        before submission.
        """
        submission_id = str(uuid.uuid4())

        # Stage 1: Format the finding
        draft = H1ReportFormatter.format_draft(finding)
        preview = H1ReportFormatter.format_preview_markdown(draft)

        # Stage 2: Check for duplicates
        duplicate = self._duplicate_detector.check_duplicate(
            title=draft.get("title", ""),
            vuln_type=finding.get("vulnerability_type", ""),
            endpoint=finding.get("affected_endpoint", ""),
            description=finding.get("description", ""),
        )

        # Stage 3: Create the draft
        submission = SubmissionDraft(
            submission_id=submission_id,
            vulnerability_id=finding.get("id", str(uuid.uuid4())),
            program_handle=program_handle,
            status="draft",
            draft=draft,
            preview_markdown=preview,
            duplicate_check=duplicate,
        )

        if duplicate:
            logger.warning(
                f"Potential duplicate detected for '{draft.get('title', '')}' "
                f"(score: {duplicate.get('duplicate_score', 0):.2f})"
            )

        self._drafts[submission_id] = submission
        logger.info(f"Submission draft created: {submission_id}")
        return submission

    async def approve_draft(self, submission_id: str) -> Optional[SubmissionDraft]:
        """Mark a draft as approved by a human reviewer."""
        draft = self._drafts.get(submission_id)
        if not draft:
            logger.warning(f"Draft not found: {submission_id}")
            return None

        draft.status = "approved"
        draft.approved_at = datetime.utcnow().isoformat()
        logger.info(f"Draft approved: {submission_id}")
        return draft

    async def reject_draft(self, submission_id: str, reason: str = "") -> Optional[SubmissionDraft]:
        """Mark a draft as rejected by a human reviewer."""
        draft = self._drafts.get(submission_id)
        if not draft:
            return None

        draft.status = "rejected"
        logger.info(f"Draft rejected: {submission_id} - {reason}")
        return draft

    async def submit_approved(
        self, submission_id: str, session=None
    ) -> Dict[str, Any]:
        """Submit an approved draft to the platform.

        SAFETY: Only submits drafts with status='approved'.
        """
        draft = self._drafts.get(submission_id)
        if not draft:
            return {"error": "Draft not found", "submission_id": submission_id}

        if draft.status != "approved":
            return {
                "error": f"Draft must be approved before submission (current status: {draft.status})",
                "submission_id": submission_id,
            }

        if not self.h1_client:
            return {"error": "HackerOne client not configured", "submission_id": submission_id}

        try:
            result = await self.h1_client.create_report(
                program_handle=draft.program_handle,
                report_data=draft.draft,
                session=session,
            )
            draft.status = "submitted"
            draft.submitted_at = datetime.utcnow().isoformat()
            logger.info(f"Report submitted: {submission_id}")
            return {"success": True, "submission_id": submission_id, "result": result}
        except Exception as e:
            logger.error(f"Submission failed: {submission_id} - {e}")
            return {"error": str(e), "submission_id": submission_id}

    def get_draft(self, submission_id: str) -> Optional[SubmissionDraft]:
        """Get a draft by ID."""
        return self._drafts.get(submission_id)

    def list_drafts(self, status: Optional[str] = None) -> List[SubmissionDraft]:
        """List all drafts, optionally filtered by status."""
        drafts = list(self._drafts.values())
        if status:
            drafts = [d for d in drafts if d.status == status]
        return sorted(drafts, key=lambda d: d.created_at, reverse=True)
