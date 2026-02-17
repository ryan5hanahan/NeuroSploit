"""
Bug Bounty Duplicate Detector — Compare findings against existing reports.
"""

import logging
import re
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DuplicateDetector:
    """Compares new findings against existing HackerOne reports for duplicate detection."""

    # Similarity threshold for considering a finding a potential duplicate
    TITLE_THRESHOLD = 0.65
    DETAIL_THRESHOLD = 0.50

    def __init__(self, existing_reports: List[Dict]):
        """
        Args:
            existing_reports: List of report dicts from HackerOneClient.get_reports()
        """
        self.reports = existing_reports
        self._normalized_titles = [
            self._normalize(r.get("title", "")) for r in existing_reports
        ]

    def check_duplicate(
        self,
        title: str,
        vuln_type: str = "",
        endpoint: str = "",
        description: str = "",
    ) -> Optional[Dict]:
        """Check if a finding is likely a duplicate of an existing report.

        Returns the matching report dict if duplicate detected, None otherwise.
        """
        if not self.reports:
            return None

        norm_title = self._normalize(title)
        norm_desc = self._normalize(description)

        best_match = None
        best_score = 0.0

        for i, report in enumerate(self.reports):
            score = self._compute_similarity(
                norm_title, norm_desc, vuln_type, endpoint,
                self._normalized_titles[i], report,
            )
            if score > best_score:
                best_score = score
                best_match = report

        if best_score >= self.TITLE_THRESHOLD and best_match:
            logger.info(
                f"Duplicate detected (score={best_score:.2f}): "
                f"'{title}' matches report #{best_match.get('id')} '{best_match.get('title')}'"
            )
            return {
                **best_match,
                "duplicate_score": round(best_score, 3),
            }

        return None

    def check_all(
        self, findings: List[Dict]
    ) -> List[Tuple[Dict, Optional[Dict]]]:
        """Check a batch of findings for duplicates.

        Returns list of (finding, duplicate_report_or_None) tuples.
        """
        results = []
        for finding in findings:
            dup = self.check_duplicate(
                title=finding.get("title", ""),
                vuln_type=finding.get("vulnerability_type", ""),
                endpoint=finding.get("affected_endpoint", ""),
                description=finding.get("description", ""),
            )
            results.append((finding, dup))
        return results

    def _compute_similarity(
        self,
        norm_title: str,
        norm_desc: str,
        vuln_type: str,
        endpoint: str,
        report_title: str,
        report: Dict,
    ) -> float:
        """Compute weighted similarity score between a finding and a report."""
        scores = []

        # Title similarity (weight: 0.4)
        title_sim = SequenceMatcher(None, norm_title, report_title).ratio()
        scores.append(("title", title_sim, 0.4))

        # Vulnerability type match (weight: 0.25)
        report_weakness = self._normalize(report.get("weakness", ""))
        norm_vuln = self._normalize(vuln_type)
        if norm_vuln and report_weakness:
            vuln_sim = SequenceMatcher(None, norm_vuln, report_weakness).ratio()
        elif norm_vuln and norm_vuln in report_title:
            vuln_sim = 0.8
        else:
            vuln_sim = 0.0
        scores.append(("vuln_type", vuln_sim, 0.25))

        # Endpoint overlap (weight: 0.2)
        report_info = self._normalize(report.get("vulnerability_information", ""))
        if endpoint and report_info:
            endpoint_norm = self._normalize(endpoint)
            endpoint_sim = 1.0 if endpoint_norm in report_info else 0.0
        else:
            endpoint_sim = 0.0
        scores.append(("endpoint", endpoint_sim, 0.2))

        # Description similarity (weight: 0.15)
        if norm_desc and report_info:
            desc_sim = SequenceMatcher(None, norm_desc[:500], report_info[:500]).ratio()
        else:
            desc_sim = 0.0
        scores.append(("description", desc_sim, 0.15))

        # Weighted total
        total = sum(score * weight for _, score, weight in scores)
        return total

    @staticmethod
    def _normalize(text: str) -> str:
        """Normalize text for comparison."""
        if not text:
            return ""
        text = text.lower().strip()
        text = re.sub(r'[^\w\s]', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        return text
