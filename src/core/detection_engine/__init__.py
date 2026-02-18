"""Detection Engine - LLM-based validation for detection results."""

from .llm_judge import LLMJudge, JudgeResult, get_judge, reset_judge

__all__ = [
    "LLMJudge",
    "JudgeResult",
    "get_judge",
    "reset_judge",
]
