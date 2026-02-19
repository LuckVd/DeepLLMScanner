"""Detection Engine - LLM-based validation and email classification for detection results."""

from .llm_judge import LLMJudge, JudgeResult, get_judge, reset_judge
from .email_classifier import (
    EmailClassifier,
    EmailClassification,
    EmailClassifyResult,
    get_classifier,
    reset_classifier,
)

__all__ = [
    # LLM Judge
    "LLMJudge",
    "JudgeResult",
    "get_judge",
    "reset_judge",
    # Email Classifier
    "EmailClassifier",
    "EmailClassification",
    "EmailClassifyResult",
    "get_classifier",
    "reset_classifier",
]
