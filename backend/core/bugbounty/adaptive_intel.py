"""Adaptive Intelligence — learns from bug bounty outcomes to improve strategy.

Records submission outcomes and generates program-specific insights.
"""
import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AdaptiveIntelligence:
    """Records outcomes and generates program insights to adjust strategy."""

    def __init__(self):
        self._outcomes: List[Dict[str, Any]] = []
        self._program_stats: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "total_submissions": 0,
                "accepted": 0,
                "duplicates": 0,
                "rejected": 0,
                "not_applicable": 0,
                "total_payout": 0.0,
                "vuln_type_success": defaultdict(int),
                "vuln_type_failure": defaultdict(int),
                "avg_severity_accepted": [],
            }
        )

    def record_outcome(
        self,
        report_id: str,
        program_handle: str,
        outcome: str,  # "accepted", "duplicate", "rejected", "not_applicable"
        vuln_type: str = "",
        severity: str = "",
        payout: float = 0.0,
        feedback: str = "",
    ) -> None:
        """Record a submission outcome for learning."""
        record = {
            "report_id": report_id,
            "program_handle": program_handle,
            "outcome": outcome,
            "vuln_type": vuln_type,
            "severity": severity,
            "payout": payout,
            "feedback": feedback,
            "recorded_at": datetime.utcnow().isoformat(),
        }
        self._outcomes.append(record)

        # Update program stats
        stats = self._program_stats[program_handle]
        stats["total_submissions"] += 1

        if outcome == "accepted":
            stats["accepted"] += 1
            stats["total_payout"] += payout
            stats["vuln_type_success"][vuln_type] += 1
            if severity:
                stats["avg_severity_accepted"].append(severity)
        elif outcome == "duplicate":
            stats["duplicates"] += 1
            stats["vuln_type_failure"][vuln_type] += 1
        elif outcome == "rejected":
            stats["rejected"] += 1
            stats["vuln_type_failure"][vuln_type] += 1
        elif outcome == "not_applicable":
            stats["not_applicable"] += 1

        logger.info(f"Outcome recorded: {program_handle} - {outcome} ({vuln_type})")

    def get_program_insights(self, program_handle: str) -> Dict[str, Any]:
        """Generate insights for a specific program."""
        stats = self._program_stats.get(program_handle)
        if not stats or stats["total_submissions"] == 0:
            return {
                "program": program_handle,
                "has_data": False,
                "recommendation": "No historical data. Start with common vulnerability types.",
            }

        acceptance_rate = stats["accepted"] / stats["total_submissions"]
        duplicate_rate = stats["duplicates"] / stats["total_submissions"]

        # Find most successful vuln types
        successful_types = sorted(
            stats["vuln_type_success"].items(),
            key=lambda x: x[1],
            reverse=True,
        )

        # Find vuln types to avoid (high failure rate)
        avoid_types = []
        for vtype, failures in stats["vuln_type_failure"].items():
            successes = stats["vuln_type_success"].get(vtype, 0)
            if failures > 0 and successes == 0:
                avoid_types.append(vtype)

        # Generate recommendation
        recommendations = []
        if duplicate_rate > 0.5:
            recommendations.append(
                "High duplicate rate. Focus on novel attack vectors "
                "and less commonly reported vulnerability types."
            )
        if successful_types:
            top_types = [t[0] for t in successful_types[:3]]
            recommendations.append(
                f"Most successful vuln types: {', '.join(top_types)}. "
                f"Prioritize these in testing."
            )
        if avoid_types:
            recommendations.append(
                f"Avoid these vuln types (all rejected): {', '.join(avoid_types[:5])}"
            )

        return {
            "program": program_handle,
            "has_data": True,
            "total_submissions": stats["total_submissions"],
            "acceptance_rate": round(acceptance_rate, 2),
            "duplicate_rate": round(duplicate_rate, 2),
            "total_payout": stats["total_payout"],
            "successful_vuln_types": successful_types[:5],
            "avoid_vuln_types": avoid_types[:5],
            "recommendations": recommendations,
        }

    def get_strategy_adjustments(self, program_handle: str) -> Dict[str, Any]:
        """Get strategy adjustments based on historical data."""
        insights = self.get_program_insights(program_handle)

        if not insights.get("has_data"):
            return {"adjustments": [], "priority_vuln_types": [], "skip_vuln_types": []}

        adjustments = []
        priority_types = []
        skip_types = insights.get("avoid_vuln_types", [])

        if insights.get("duplicate_rate", 0) > 0.5:
            adjustments.append("increase_novelty")
            adjustments.append("deeper_exploitation")

        for vtype, count in insights.get("successful_vuln_types", []):
            if count >= 2:
                priority_types.append(vtype)

        if insights.get("acceptance_rate", 0) < 0.2:
            adjustments.append("improve_report_quality")
            adjustments.append("focus_on_severity")

        return {
            "adjustments": adjustments,
            "priority_vuln_types": priority_types,
            "skip_vuln_types": skip_types,
        }
