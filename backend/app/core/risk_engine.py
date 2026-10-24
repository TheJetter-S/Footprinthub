# =============================================================================
# FootprintHub — Risk Scoring Engine
# =============================================================================
# Calculates normalized 0-100 risk score from security findings,
# determines overall risk posture, severity breakdowns, and remediation priorities.
# =============================================================================

from dataclasses import dataclass
from typing import Any, Sequence


@dataclass
class RiskAssessment:
    """Consolidated risk assessment summary."""
    score: int                     # 0 - 100
    level: str                     # "low" | "medium" | "high" | "critical"
    grade: str                     # "A" | "B" | "C" | "D" | "F"
    summary: str
    total_findings: int
    counts: dict[str, int]
    score_breakdown: dict[str, int]


class RiskEngine:
    """
    Evaluates aggregated security findings across all recon modules
    to compute a deterministic, weighted risk score.
    """

    # Scoring weights and caps per severity
    WEIGHTS = {
        "critical": 25,
        "high": 10,
        "medium": 5,
        "low": 2,
        "info": 0,
    }

    CAPS = {
        "critical": 50,
        "high": 30,
        "medium": 15,
        "low": 5,
        "info": 0,
    }

    @classmethod
    def calculate_score(cls, findings: Sequence[Any]) -> RiskAssessment:
        """
        Calculate total risk score (0-100) from a list of findings or finding dicts.
        """
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for f in findings:
            sev = getattr(f, "severity", None)
            if sev is None and isinstance(f, dict):
                sev = f.get("severity")
            if hasattr(sev, "value"):
                sev = sev.value
            if isinstance(sev, str):
                sev = sev.lower()
            if sev in counts:
                counts[sev] += 1

        breakdown = {}
        for sev, count in counts.items():
            raw_contrib = count * cls.WEIGHTS[sev]
            capped_contrib = min(raw_contrib, cls.CAPS[sev])
            breakdown[sev] = capped_contrib

        total_score = min(100, sum(breakdown.values()))

        # Determine level and letter grade
        if total_score <= 20:
            level = "low"
            grade = "A" if total_score <= 10 else "B"
            summary = "Low security exposure. Standard hardening measures in place."
        elif total_score <= 50:
            level = "medium"
            grade = "C"
            summary = "Moderate risk exposure detected. Review recommended remediation actions."
        elif total_score <= 75:
            level = "high"
            grade = "D"
            summary = "Elevated risk profile. Multiple high-impact weaknesses identified."
        else:
            level = "critical"
            grade = "F"
            summary = "Critical security exposure. Immediate remediation required to prevent compromise."

        return RiskAssessment(
            score=total_score,
            level=level,
            grade=grade,
            summary=summary,
            total_findings=len(findings),
            counts=counts,
            score_breakdown=breakdown,
        )
