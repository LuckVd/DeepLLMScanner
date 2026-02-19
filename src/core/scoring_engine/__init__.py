"""Scoring Engine - Risk score calculation for vulnerabilities.

This module implements the standardized risk scoring formula:

    risk_score = severity_weight × confidence × reproducibility × impact_factor

The score ranges from 0-100 and is mapped to risk levels and priorities.
"""

from .scorer import (
    RiskScorer,
    RiskScore,
    RiskLevel,
    Priority,
    SEVERITY_WEIGHTS,
    DEFAULT_SEVERITY_WEIGHT,
    get_scorer,
    reset_scorer,
    calculate_risk_score,
)

__all__ = [
    "RiskScorer",
    "RiskScore",
    "RiskLevel",
    "Priority",
    "SEVERITY_WEIGHTS",
    "DEFAULT_SEVERITY_WEIGHT",
    "get_scorer",
    "reset_scorer",
    "calculate_risk_score",
]
