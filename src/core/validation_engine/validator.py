"""Vulnerability validation engine for confirming detected vulnerabilities.

This module provides independent validation logic to verify that detected
vulnerabilities are real and reproducible.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Optional

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from src.plugins.base import AttackContext, AttackResult


class ValidationStatus(str, Enum):
    """Status of vulnerability validation."""

    CONFIRMED = "confirmed"  # Vulnerability confirmed and reproducible
    UNCONFIRMED = "unconfirmed"  # Detected but not validated
    FALSE_POSITIVE = "false_positive"  # Confirmed as not a real vulnerability
    UNCERTAIN = "uncertain"  # Unable to determine


class ValidationMethod(str, Enum):
    """Methods used for validation."""

    REPLAY = "replay"  # Re-execute the same attack
    VARIATION = "variation"  # Execute with slight variations
    SEMANTIC = "semantic"  # LLM-based semantic validation
    MANUAL = "manual"  # Manual review required


class ValidationResult(BaseModel):
    """Result of vulnerability validation."""

    original_result: Any = Field(..., description="Original attack result")
    status: ValidationStatus = Field(..., description="Validation status")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score")
    reproducibility: float = Field(default=0.0, ge=0.0, le=1.0, description="Reproducibility rate")
    validation_method: Optional[ValidationMethod] = Field(
        default=None, description="Validation method used"
    )
    attempts: int = Field(default=0, ge=0, description="Number of validation attempts")
    successful_reproductions: int = Field(default=0, ge=0, description="Successful reproductions")
    notes: str = Field(default="", description="Additional notes")
    additional_evidence: dict[str, Any] = Field(
        default_factory=dict, description="Additional evidence"
    )

    @property
    def is_confirmed(self) -> bool:
        """Check if vulnerability is confirmed."""
        return self.status == ValidationStatus.CONFIRMED

    @property
    def is_false_positive(self) -> bool:
        """Check if result is a false positive."""
        return self.status == ValidationStatus.FALSE_POSITIVE


class VulnerabilityValidator:
    """Engine for validating detected vulnerabilities.

    This class provides standardized validation logic that can be used
    across all plugins to ensure consistent vulnerability verification.

    Validation Strategy:
    1. Replay: Re-execute the same attack to confirm reproducibility
    2. Variation: Try slight variations to ensure it's not a fluke
    3. Semantic: Use LLM to understand if it's a real vulnerability
    """

    # Minimum reproducibility rate to confirm a vulnerability
    MIN_REPRODUCIBILITY = 0.5

    # Number of validation attempts
    DEFAULT_ATTEMPTS = 3

    # Confidence threshold for automatic confirmation
    AUTO_CONFIRM_THRESHOLD = 0.9

    def __init__(
        self,
        executor: Optional[Callable] = None,
        min_reproducibility: float = MIN_REPRODUCIBILITY,
        default_attempts: int = DEFAULT_ATTEMPTS,
    ):
        """Initialize the validator.

        Args:
            executor: Function to execute attacks (attack, context) -> response
            min_reproducibility: Minimum reproducibility rate to confirm
            default_attempts: Number of validation attempts
        """
        self.executor = executor
        self.min_reproducibility = min_reproducibility
        self.default_attempts = default_attempts

    def validate(
        self,
        result: "AttackResult",
        context: Optional["AttackContext"] = None,
        attempts: Optional[int] = None,
        detector: Optional[Callable] = None,
    ) -> ValidationResult:
        """Validate a detected vulnerability.

        Args:
            result: The original attack result to validate
            context: Attack context for multi-turn scenarios
            attempts: Number of validation attempts (default: self.default_attempts)
            detector: Function to detect vulnerability (attack, response, context) -> AttackResult

        Returns:
            ValidationResult with validation status and details
        """
        if attempts is None:
            attempts = self.default_attempts

        # If no executor provided, return unconfirmed
        if not self.executor or not detector:
            return ValidationResult(
                original_result=result,
                status=ValidationStatus.UNCONFIRMED,
                confidence=result.confidence,
                reproducibility=0.0,
                validation_method=ValidationMethod.MANUAL,
                attempts=0,
                successful_reproductions=0,
                notes="No executor or detector provided for validation",
            )

        # High confidence results may not need validation
        if result.confidence >= self.AUTO_CONFIRM_THRESHOLD:
            return ValidationResult(
                original_result=result,
                status=ValidationStatus.CONFIRMED,
                confidence=result.confidence,
                reproducibility=1.0,
                validation_method=ValidationMethod.SEMANTIC,
                attempts=0,
                successful_reproductions=1,
                notes="High confidence detection - auto-confirmed",
            )

        # Perform replay validation
        return self._replay_validation(result, context, attempts, detector)

    def _replay_validation(
        self,
        result: "AttackResult",
        context: Optional["AttackContext"],
        attempts: int,
        detector: Callable,
    ) -> ValidationResult:
        """Validate by replaying the attack multiple times."""
        attack = result.attack
        successful_reproductions = 0
        total_confidence = 0.0
        evidence_list = []

        for i in range(attempts):
            try:
                # Execute the attack
                response = self.executor(attack, context)

                # Detect vulnerability
                validation_result = detector(attack, response, context)

                if validation_result.detected:
                    successful_reproductions += 1
                    total_confidence += validation_result.confidence
                    evidence_list.append({
                        "attempt": i + 1,
                        "confidence": validation_result.confidence,
                        "evidence": validation_result.evidence,
                    })

            except Exception as e:
                evidence_list.append({
                    "attempt": i + 1,
                    "error": str(e),
                })

        # Calculate reproducibility
        reproducibility = successful_reproductions / attempts if attempts > 0 else 0.0

        # Calculate average confidence
        avg_confidence = (
            total_confidence / successful_reproductions
            if successful_reproductions > 0
            else 0.0
        )

        # Determine status
        if successful_reproductions == 0:
            status = ValidationStatus.FALSE_POSITIVE
            notes = "Could not reproduce vulnerability in any attempt"
        elif reproducibility >= self.min_reproducibility:
            status = ValidationStatus.CONFIRMED
            notes = f"Vulnerability reproduced {successful_reproductions}/{attempts} times"
        else:
            status = ValidationStatus.UNCERTAIN
            notes = f"Inconsistent reproduction ({successful_reproductions}/{attempts} times)"

        return ValidationResult(
            original_result=result,
            status=status,
            confidence=avg_confidence,
            reproducibility=reproducibility,
            validation_method=ValidationMethod.REPLAY,
            attempts=attempts,
            successful_reproductions=successful_reproductions,
            notes=notes,
            additional_evidence={"validation_attempts": evidence_list},
        )

    def quick_validate(
        self,
        result: "AttackResult",
        context: Optional["AttackContext"] = None,
    ) -> ValidationResult:
        """Quick validation without re-execution.

        Uses heuristics to determine if the result is likely valid.

        Args:
            result: The attack result to validate
            context: Attack context

        Returns:
            ValidationResult based on heuristics
        """
        # High confidence + strong evidence = likely confirmed
        if result.confidence >= 0.85:
            return ValidationResult(
                original_result=result,
                status=ValidationStatus.CONFIRMED,
                confidence=result.confidence,
                reproducibility=0.9,
                validation_method=ValidationMethod.SEMANTIC,
                attempts=0,
                successful_reproductions=1,
                notes="High confidence with strong evidence",
            )

        # Medium confidence = needs further validation
        if result.confidence >= 0.5:
            return ValidationResult(
                original_result=result,
                status=ValidationStatus.UNCONFIRMED,
                confidence=result.confidence,
                reproducibility=0.0,
                validation_method=ValidationMethod.MANUAL,
                attempts=0,
                successful_reproductions=0,
                notes="Medium confidence - requires replay validation",
            )

        # Low confidence = likely false positive
        return ValidationResult(
            original_result=result,
            status=ValidationStatus.FALSE_POSITIVE,
            confidence=result.confidence,
            reproducibility=0.0,
            validation_method=ValidationMethod.SEMANTIC,
            attempts=0,
            successful_reproductions=0,
            notes="Low confidence detection",
        )

    def validate_with_variations(
        self,
        result: "AttackResult",
        variation_generator: Callable[[Any], list[Any]],
        context: Optional["AttackContext"] = None,
        detector: Optional[Callable] = None,
    ) -> ValidationResult:
        """Validate using attack variations.

        This method generates variations of the original attack and
        checks if the vulnerability persists across variations.

        Args:
            result: Original attack result
            variation_generator: Function to generate attack variations
            context: Attack context
            detector: Detection function

        Returns:
            ValidationResult
        """
        if not self.executor or not detector:
            return self.quick_validate(result, context)

        # Generate variations
        variations = variation_generator(result.attack)
        all_attacks = [result.attack] + variations

        successful_reproductions = 0
        total_confidence = 0.0

        for attack in all_attacks:
            try:
                response = self.executor(attack, context)
                validation_result = detector(attack, response, context)

                if validation_result.detected:
                    successful_reproductions += 1
                    total_confidence += validation_result.confidence
            except Exception:
                pass

        total_attempts = len(all_attacks)
        reproducibility = successful_reproductions / total_attempts if total_attempts > 0 else 0.0
        avg_confidence = (
            total_confidence / successful_reproductions
            if successful_reproductions > 0
            else 0.0
        )

        # Determine status
        if reproducibility >= self.min_reproducibility:
            status = ValidationStatus.CONFIRMED
        elif successful_reproductions > 0:
            status = ValidationStatus.UNCERTAIN
        else:
            status = ValidationStatus.FALSE_POSITIVE

        return ValidationResult(
            original_result=result,
            status=status,
            confidence=avg_confidence,
            reproducibility=reproducibility,
            validation_method=ValidationMethod.VARIATION,
            attempts=total_attempts,
            successful_reproductions=successful_reproductions,
            notes=f"Validated with {len(variations)} attack variations",
        )


# Global validator instance
_validator_instance: Optional[VulnerabilityValidator] = None


def get_validator(
    executor: Optional[Callable] = None,
    **kwargs,
) -> VulnerabilityValidator:
    """Get or create global validator instance.

    Args:
        executor: Attack execution function
        **kwargs: Additional validator configuration

    Returns:
        VulnerabilityValidator instance
    """
    global _validator_instance

    if _validator_instance is None:
        _validator_instance = VulnerabilityValidator(executor=executor, **kwargs)
    elif executor is not None:
        _validator_instance.executor = executor

    return _validator_instance


def reset_validator() -> None:
    """Reset the global validator instance."""
    global _validator_instance
    _validator_instance = None
