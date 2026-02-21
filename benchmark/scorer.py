"""Benchmark Scorer — compare agent findings against ground truth, compute metrics.

The scorer uses a weighted multi-factor matching strategy via difflib.SequenceMatcher:
  - Keyword overlap   (weight 0.40): ground-truth match_keywords in finding text
  - Vuln type match   (weight 0.25): SequenceMatcher on vuln_type strings
  - Endpoint match    (weight 0.20): substring or SequenceMatcher on endpoint
  - Description sim   (weight 0.15): SequenceMatcher on description/title

A finding is a True Positive when its best match score >= MATCH_THRESHOLD.
"""

import logging
import os
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set

import yaml

logger = logging.getLogger(__name__)

MATCH_THRESHOLD = 0.35  # Minimum combined score to accept a match


class Scorer:
    """Compare agent findings against ground truth vulnerabilities.

    Args:
        ground_truth: List of ground-truth vulnerability dicts, each with:
            id, vuln_type, severity, endpoint, parameter, match_keywords.
            Build this list via _load_ground_truth_from_yaml() if reading from disk.
    """

    def __init__(self, ground_truth: List[Dict[str, Any]]):
        self.ground_truth = ground_truth

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score_findings(
        self,
        findings: List[Dict[str, Any]],
        cost_usd: float = 0.0,
        steps_used: int = 0,
        duration_seconds: float = 0.0,
    ) -> Dict[str, Any]:
        """Score a list of agent findings against the loaded ground truth.

        Args:
            findings:          List of finding dicts from AgentResult.findings.
            cost_usd:          Total LLM spend for this run.
            steps_used:        Number of agent steps consumed.
            duration_seconds:  Wall-clock runtime of the agent.

        Returns:
            Dict with keys:
                true_positives   (int)
                false_positives  (int)
                false_negatives  (int)
                precision        (float, 0-1)
                recall           (float, 0-1)
                f1               (float, 0-1)
                cost_per_finding (float, USD per confirmed finding)
                cost_usd         (float)
                steps_used       (int)
                duration_seconds (float)
                matched_pairs    (list of {finding, truth, score})
                unmatched_findings (list — agent FPs)
                unmatched_truths   (list — ground-truth FNs)
        """
        matched_pairs: List[Dict[str, Any]] = []
        matched_truth_ids: Set[str] = set()
        matched_finding_indices: Set[int] = set()

        # For each ground-truth entry find the best unmatched agent finding
        for truth in self.ground_truth:
            best_score = 0.0
            best_idx: Optional[int] = None

            for idx, finding in enumerate(findings):
                if idx in matched_finding_indices:
                    continue
                score = self._match_finding(finding, truth)
                if score > best_score:
                    best_score = score
                    best_idx = idx

            if best_score >= MATCH_THRESHOLD and best_idx is not None:
                matched_pairs.append({
                    "finding": findings[best_idx],
                    "truth": truth,
                    "score": round(best_score, 4),
                })
                matched_truth_ids.add(truth["id"])
                matched_finding_indices.add(best_idx)

        true_positives = len(matched_pairs)
        false_negatives = len(self.ground_truth) - true_positives
        false_positives = len(findings) - true_positives

        precision = (
            true_positives / (true_positives + false_positives)
            if (true_positives + false_positives) > 0
            else 0.0
        )
        recall = (
            true_positives / (true_positives + false_negatives)
            if (true_positives + false_negatives) > 0
            else 0.0
        )
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        cost_per_finding = cost_usd / true_positives if true_positives > 0 else 0.0

        unmatched_findings = [
            f for idx, f in enumerate(findings) if idx not in matched_finding_indices
        ]
        unmatched_truths = [
            t for t in self.ground_truth if t["id"] not in matched_truth_ids
        ]

        return {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "cost_per_finding": round(cost_per_finding, 4),
            "cost_usd": round(cost_usd, 4),
            "steps_used": steps_used,
            "duration_seconds": round(duration_seconds, 2),
            "matched_pairs": matched_pairs,
            "unmatched_findings": unmatched_findings,
            "unmatched_truths": unmatched_truths,
        }

    def _match_finding(self, finding: Dict[str, Any], ground_truth: Dict[str, Any]) -> float:
        """Compute a similarity score between a single finding and a ground-truth entry.

        Uses difflib.SequenceMatcher for string similarity, combined with keyword
        overlap analysis.  Returns a float in [0, 1].

        Scoring weights:
            Keyword overlap   0.40
            Vuln type match   0.25
            Endpoint match    0.20
            Description sim   0.15
        """
        score = 0.0

        # --- Keyword overlap (weight 0.40) ---
        keywords: List[str] = ground_truth.get("match_keywords", [])
        if keywords:
            finding_text = " ".join(
                str(v).lower()
                for v in [
                    finding.get("title", ""),
                    finding.get("description", ""),
                    finding.get("vulnerability_type", ""),
                    finding.get("vuln_type", ""),
                    finding.get("type", ""),
                    finding.get("affected_endpoint", ""),
                    finding.get("endpoint", ""),
                    finding.get("evidence", ""),
                ]
            )
            hits = sum(1 for kw in keywords if kw.lower() in finding_text)
            score += (hits / len(keywords)) * 0.40

        # --- Vuln type match (weight 0.25) ---
        gt_type = ground_truth.get("vuln_type", "").lower()
        finding_type = (
            finding.get("vulnerability_type", "")
            or finding.get("vuln_type", "")
            or finding.get("type", "")
        ).lower()
        if gt_type and finding_type:
            type_sim = SequenceMatcher(None, gt_type, finding_type).ratio()
            score += type_sim * 0.25

        # --- Endpoint match (weight 0.20) ---
        gt_endpoint = ground_truth.get("endpoint", "").lower()
        finding_endpoint = (
            finding.get("affected_endpoint", "")
            or finding.get("endpoint", "")
            or finding.get("url", "")
        ).lower()
        if gt_endpoint and finding_endpoint:
            if gt_endpoint in finding_endpoint or finding_endpoint in gt_endpoint:
                score += 0.20
            else:
                endpoint_sim = SequenceMatcher(None, gt_endpoint, finding_endpoint).ratio()
                score += endpoint_sim * 0.20

        # --- Description / title similarity (weight 0.15) ---
        gt_desc = ground_truth.get("description", "").lower()
        finding_title = (finding.get("title", "") or finding.get("description", "")).lower()
        if gt_desc and finding_title:
            desc_sim = SequenceMatcher(None, gt_desc[:200], finding_title[:200]).ratio()
            score += desc_sim * 0.15

        return score

    # ------------------------------------------------------------------
    # Static helper (private by convention)
    # ------------------------------------------------------------------

    @staticmethod
    def _load_ground_truth_from_yaml(path: str) -> List[Dict[str, Any]]:
        """Load ground truth entries from a YAML file.

        Args:
            path: Absolute or project-relative path to the ground truth YAML.

        Returns:
            List of vulnerability dicts from the 'vulnerabilities' key.

        Raises:
            FileNotFoundError: If the file does not exist.
            KeyError:          If 'vulnerabilities' key is absent.
        """
        if not os.path.isabs(path):
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            path = os.path.join(project_root, path)

        if not os.path.exists(path):
            raise FileNotFoundError(f"Ground truth file not found: {path}")

        with open(path, "r") as fh:
            data = yaml.safe_load(fh)

        return data["vulnerabilities"]
