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
from .stability import (
    StabilityValidator,
    StabilityConfig,
    StabilityResult,
    StabilityLevel,
    ValidationStrategy,
    ValidationAttempt,
    get_stability_validator,
    reset_stability_validator,
)

__all__ = [
    # Original validator
    "VulnerabilityValidator",
    "ValidationResult",
    "ValidationStatus",
    "ValidationMethod",
    "get_validator",
    "reset_validator",
    # Stability validator
    "StabilityValidator",
    "StabilityConfig",
    "StabilityResult",
    "StabilityLevel",
    "ValidationStrategy",
    "ValidationAttempt",
    "get_stability_validator",
    "reset_stability_validator",
]
