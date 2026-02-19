"""Validation Engine - Vulnerability validation and confirmation.

This module provides independent validation logic to verify that
detected vulnerabilities are real and reproducible.
"""

from .validator import (
    VulnerabilityValidator,
    ValidationResult,
    ValidationStatus,
    ValidationMethod,
    get_validator,
    reset_validator,
)

__all__ = [
    "VulnerabilityValidator",
    "ValidationResult",
    "ValidationStatus",
    "ValidationMethod",
    "get_validator",
    "reset_validator",
]
