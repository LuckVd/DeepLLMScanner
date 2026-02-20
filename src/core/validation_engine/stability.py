"""Stability Validator - Multi-attempt validation for vulnerability confirmation.

This module provides enhanced stability validation that performs multiple
validation attempts with configurable strategies to reduce false positives
and ensure vulnerabilities are reliably reproducible.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Optional

from pydantic import BaseModel, Field
from rich.console import Console

if TYPE_CHECKING:
    from src.plugins.base import AttackContext, AttackResult

console = Console()


class StabilityLevel(str, Enum):
    """Stability level of a detected vulnerability."""

    STABLE = "stable"  # Consistently reproducible (high confidence)
    UNSTABLE = "unstable"  # Inconsistently reproducible (medium confidence)
    FLAKY = "flaky"  # Rarely reproducible (low confidence)
    FALSE_POSITIVE = "false_positive"  # Not reproducible


class ValidationStrategy(str, Enum):
    """Strategy for multi-attempt validation."""

    REPLAY = "replay"  # Re-execute same attack
    VARIANT = "variant"  # Use attack variants
    HYBRID = "hybrid"  # Mix of replay and variant
    PROGRESSIVE = "progressive"  # Increase attempts if unstable


@dataclass
class ValidationAttempt:
    """Record of a single validation attempt."""

    attempt_number: int
    attack_used: Any  # The attack payload used
    response: Optional[str] = None
    detected: bool = False
    confidence: float = 0.0
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "attempt_number": self.attempt_number,
            "detected": self.detected,
            "confidence": self.confidence,
            "error": self.error,
            "timestamp": self.timestamp,
            "evidence": self.evidence,
        }


class StabilityConfig(BaseModel):
    """Configuration for stability validation."""

    enabled: bool = Field(default=True, description="Enable stability validation")
    min_validations: int = Field(default=2, ge=1, description="Minimum validation attempts")
    max_validations: int = Field(default=3, ge=1, description="Maximum validation attempts")
    required_consistency: float = Field(
        default=0.66, ge=0.0, le=1.0, description="Required consistency ratio (2/3)"
    )
    retry_delay: float = Field(default=0.5, ge=0.0, description="Delay between retries (seconds)")
    variant_on_retry: bool = Field(
        default=True, description="Use attack variants on retry"
    )
    strategy: ValidationStrategy = Field(
        default=ValidationStrategy.HYBRID, description="Validation strategy"
    )
    progressive_threshold: float = Field(
        default=0.5, ge=0.0, le=1.0,
        description="If consistency below this, add more attempts (progressive mode)"
    )
    max_progressive_attempts: int = Field(
        default=5, ge=1, description="Max attempts in progressive mode"
    )

    # Quick mode (minimal validation)
    quick_mode: bool = Field(default=False, description="Use minimal validation")
    quick_validations: int = Field(default=1, ge=1, description="Validations in quick mode")

    def get_attempts_for_mode(self, mode: str = "standard") -> int:
        """Get number of attempts based on scan mode.

        Args:
            mode: Scan mode (quick, standard, deep)

        Returns:
            Number of validation attempts
        """
        if self.quick_mode or mode == "quick":
            return self.quick_validations
        elif mode == "deep":
            return self.max_validations + 1
        else:  # standard
            return self.max_validations


class StabilityResult(BaseModel):
    """Result of stability validation."""

    is_stable: bool = Field(default=False, description="Whether vulnerability is stable")
    stability_level: StabilityLevel = Field(
        default=StabilityLevel.UNSTABLE, description="Stability classification"
    )
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score")
    consistency: float = Field(default=0.0, ge=0.0, le=1.0, description="Consistency ratio")
    validation_count: int = Field(default=0, ge=0, description="Total validation attempts")
    successful_count: int = Field(default=0, ge=0, description="Successful reproductions")
    failed_count: int = Field(default=0, ge=0, description="Failed reproductions")
    attempts: list[dict] = Field(default_factory=list, description="All validation attempts")
    strategy_used: ValidationStrategy = Field(
        default=ValidationStrategy.REPLAY, description="Strategy used"
    )
    notes: str = Field(default="", description="Additional notes")

    @property
    def is_false_positive(self) -> bool:
        """Check if result is confirmed as false positive."""
        return self.stability_level == StabilityLevel.FALSE_POSITIVE

    @property
    def needs_review(self) -> bool:
        """Check if result needs manual review."""
        return self.stability_level in (StabilityLevel.UNSTABLE, StabilityLevel.FLAKY)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "is_stable": self.is_stable,
            "stability_level": self.stability_level.value,
            "confidence": self.confidence,
            "consistency": self.consistency,
            "validation_count": self.validation_count,
            "successful_count": self.successful_count,
            "failed_count": self.failed_count,
            "strategy_used": self.strategy_used.value,
            "notes": self.notes,
        }


class StabilityValidator:
    """Enhanced validator with multi-attempt stability verification.

    This validator performs multiple validation attempts using configurable
    strategies to ensure vulnerabilities are reliably reproducible.

    Example:
        >>> config = StabilityConfig(min_validations=2, max_validations=3)
        >>> validator = StabilityValidator(config)
        >>> result = validator.validate_stability(
        ...     attack_result=original_result,
        ...     executor=execute_func,
        ...     detector=detect_func,
        ...     variant_generator=gen_variants
        ... )
        >>> if result.is_stable:
        ...     print(f"Stable vulnerability with {result.confidence:.0%} confidence")
    """

    def __init__(
        self,
        config: Optional[StabilityConfig] = None,
        executor: Optional[Callable] = None,
    ):
        """Initialize the stability validator.

        Args:
            config: Stability validation configuration
            executor: Function to execute attacks (attack, context) -> response
        """
        self.config = config or StabilityConfig()
        self.executor = executor

    def set_executor(self, executor: Callable) -> None:
        """Set the attack executor function.

        Args:
            executor: Function (attack, context) -> response
        """
        self.executor = executor

    def validate_stability(
        self,
        attack_result: "AttackResult",
        context: Optional["AttackContext"] = None,
        detector: Optional[Callable] = None,
        variant_generator: Optional[Callable[[Any], list[Any]]] = None,
        mode: str = "standard",
    ) -> StabilityResult:
        """Validate vulnerability stability with multiple attempts.

        Args:
            attack_result: Original attack result to validate
            context: Attack context for multi-turn scenarios
            detector: Function to detect vulnerability (attack, response, context) -> AttackResult
            variant_generator: Function to generate attack variants
            mode: Scan mode (quick, standard, deep)

        Returns:
            StabilityResult with stability classification and details
        """
        if not self.config.enabled:
            return StabilityResult(
                is_stable=True,
                stability_level=StabilityLevel.STABLE,
                confidence=attack_result.confidence,
                consistency=1.0,
                validation_count=0,
                successful_count=1,
                notes="Stability validation disabled",
            )

        if not self.executor or not detector:
            return StabilityResult(
                is_stable=False,
                stability_level=StabilityLevel.UNSTABLE,
                confidence=attack_result.confidence,
                consistency=0.0,
                validation_count=0,
                successful_count=0,
                notes="No executor or detector provided",
            )

        # Determine number of attempts based on strategy and mode
        num_attempts = self._get_attempt_count(mode)

        # Choose validation strategy
        if self.config.strategy == ValidationStrategy.PROGRESSIVE:
            return self._progressive_validation(
                attack_result, context, detector, variant_generator
            )
        elif self.config.strategy == ValidationStrategy.VARIANT and variant_generator:
            return self._variant_validation(
                attack_result, context, detector, variant_generator, num_attempts
            )
        elif self.config.strategy == ValidationStrategy.HYBRID:
            return self._hybrid_validation(
                attack_result, context, detector, variant_generator, num_attempts
            )
        else:
            return self._replay_validation(
                attack_result, context, detector, num_attempts
            )

    def _get_attempt_count(self, mode: str) -> int:
        """Get number of attempts for the given mode."""
        return self.config.get_attempts_for_mode(mode)

    def _replay_validation(
        self,
        attack_result: "AttackResult",
        context: Optional["AttackContext"],
        detector: Callable,
        num_attempts: int,
    ) -> StabilityResult:
        """Validate by replaying the same attack multiple times."""
        attack = attack_result.attack
        attempts: list[ValidationAttempt] = []
        successful = 0
        total_confidence = 0.0

        for i in range(num_attempts):
            attempt = self._execute_attempt(i + 1, attack, context, detector)
            attempts.append(attempt)

            if attempt.detected:
                successful += 1
                total_confidence += attempt.confidence

            # Delay between attempts
            if i < num_attempts - 1 and self.config.retry_delay > 0:
                time.sleep(self.config.retry_delay)

        return self._build_result(
            attempts, successful, total_confidence, ValidationStrategy.REPLAY
        )

    def _variant_validation(
        self,
        attack_result: "AttackResult",
        context: Optional["AttackContext"],
        detector: Callable,
        variant_generator: Callable,
        num_attempts: int,
    ) -> StabilityResult:
        """Validate using attack variants."""
        original_attack = attack_result.attack
        variants = variant_generator(original_attack)

        # Use original + variants up to num_attempts
        attacks_to_try = [original_attack] + variants[:num_attempts - 1]
        attempts: list[ValidationAttempt] = []
        successful = 0
        total_confidence = 0.0

        for i, attack in enumerate(attacks_to_try[:num_attempts]):
            attempt = self._execute_attempt(i + 1, attack, context, detector)
            attempts.append(attempt)

            if attempt.detected:
                successful += 1
                total_confidence += attempt.confidence

            if i < len(attacks_to_try) - 1 and self.config.retry_delay > 0:
                time.sleep(self.config.retry_delay)

        return self._build_result(
            attempts, successful, total_confidence, ValidationStrategy.VARIANT
        )

    def _hybrid_validation(
        self,
        attack_result: "AttackResult",
        context: Optional["AttackContext"],
        detector: Callable,
        variant_generator: Optional[Callable],
        num_attempts: int,
    ) -> StabilityResult:
        """Validate using mix of replay and variant strategies."""
        original_attack = attack_result.attack
        attempts: list[ValidationAttempt] = []
        successful = 0
        total_confidence = 0.0

        # First attempt: replay original
        attempt = self._execute_attempt(1, original_attack, context, detector)
        attempts.append(attempt)
        if attempt.detected:
            successful += 1
            total_confidence += attempt.confidence

        # Subsequent attempts: alternate between replay and variant
        if variant_generator and self.config.variant_on_retry:
            variants = variant_generator(original_attack)
            variant_idx = 0

            for i in range(1, num_attempts):
                if self.config.retry_delay > 0:
                    time.sleep(self.config.retry_delay)

                # Alternate: even = replay, odd = variant
                if i % 2 == 0 or variant_idx >= len(variants):
                    attack = original_attack
                else:
                    attack = variants[variant_idx]
                    variant_idx += 1

                attempt = self._execute_attempt(i + 1, attack, context, detector)
                attempts.append(attempt)

                if attempt.detected:
                    successful += 1
                    total_confidence += attempt.confidence
        else:
            # No variants, just replay
            for i in range(1, num_attempts):
                if self.config.retry_delay > 0:
                    time.sleep(self.config.retry_delay)

                attempt = self._execute_attempt(i + 1, original_attack, context, detector)
                attempts.append(attempt)

                if attempt.detected:
                    successful += 1
                    total_confidence += attempt.confidence

        return self._build_result(
            attempts, successful, total_confidence, ValidationStrategy.HYBRID
        )

    def _progressive_validation(
        self,
        attack_result: "AttackResult",
        context: Optional["AttackContext"],
        detector: Callable,
        variant_generator: Optional[Callable],
    ) -> StabilityResult:
        """Progressively increase attempts if vulnerability is unstable."""
        original_attack = attack_result.attack
        attempts: list[ValidationAttempt] = []
        successful = 0
        total_confidence = 0.0
        max_attempts = min(
            self.config.max_progressive_attempts,
            self.config.max_validations * 2
        )

        variants = []
        if variant_generator and self.config.variant_on_retry:
            variants = variant_generator(original_attack)

        attempt_num = 0
        while attempt_num < max_attempts:
            attempt_num += 1

            # Choose attack: replay or variant
            if attempt_num == 1:
                attack = original_attack
            elif variants and (attempt_num - 1) <= len(variants):
                attack = variants[attempt_num - 2]
            else:
                attack = original_attack

            attempt = self._execute_attempt(attempt_num, attack, context, detector)
            attempts.append(attempt)

            if attempt.detected:
                successful += 1
                total_confidence += attempt.confidence

            # Check if we have enough data and stable result
            if attempt_num >= self.config.min_validations:
                consistency = successful / attempt_num
                if consistency >= self.config.required_consistency:
                    # Stable enough, can stop early
                    break
                elif consistency < self.config.progressive_threshold:
                    # Too unstable, continue trying
                    if attempt_num < max_attempts:
                        if self.config.retry_delay > 0:
                            time.sleep(self.config.retry_delay)
                        continue

            if self.config.retry_delay > 0 and attempt_num < max_attempts:
                time.sleep(self.config.retry_delay)

        return self._build_result(
            attempts, successful, total_confidence, ValidationStrategy.PROGRESSIVE
        )

    def _execute_attempt(
        self,
        attempt_number: int,
        attack: Any,
        context: Optional["AttackContext"],
        detector: Callable,
    ) -> ValidationAttempt:
        """Execute a single validation attempt."""
        attempt = ValidationAttempt(
            attempt_number=attempt_number,
            attack_used=attack,
        )

        try:
            response = self.executor(attack, context)
            attempt.response = response

            result = detector(attack, response, context)
            attempt.detected = result.detected
            attempt.confidence = result.confidence
            attempt.evidence = {"evidence": result.evidence} if result.evidence else {}

        except Exception as e:
            attempt.error = str(e)

        return attempt

    def _build_result(
        self,
        attempts: list[ValidationAttempt],
        successful: int,
        total_confidence: float,
        strategy: ValidationStrategy,
    ) -> StabilityResult:
        """Build StabilityResult from validation attempts."""
        total = len(attempts)
        consistency = successful / total if total > 0 else 0.0
        avg_confidence = total_confidence / successful if successful > 0 else 0.0

        # Determine stability level
        if successful == 0:
            stability_level = StabilityLevel.FALSE_POSITIVE
            is_stable = False
            notes = "Could not reproduce vulnerability in any attempt"
        elif consistency >= self.config.required_consistency:
            stability_level = StabilityLevel.STABLE
            is_stable = True
            notes = f"Vulnerability consistently reproduced ({successful}/{total} times)"
        elif consistency >= 0.5:
            stability_level = StabilityLevel.UNSTABLE
            is_stable = False
            notes = f"Vulnerability inconsistently reproduced ({successful}/{total} times)"
        else:
            stability_level = StabilityLevel.FLAKY
            is_stable = False
            notes = f"Vulnerability rarely reproduced ({successful}/{total} times)"

        return StabilityResult(
            is_stable=is_stable,
            stability_level=stability_level,
            confidence=avg_confidence,
            consistency=consistency,
            validation_count=total,
            successful_count=successful,
            failed_count=total - successful,
            attempts=[a.to_dict() for a in attempts],
            strategy_used=strategy,
            notes=notes,
        )

    async def validate_stability_async(
        self,
        attack_result: "AttackResult",
        context: Optional["AttackContext"] = None,
        detector: Optional[Callable] = None,
        variant_generator: Optional[Callable[[Any], list[Any]]] = None,
        mode: str = "standard",
    ) -> StabilityResult:
        """Async version of validate_stability.

        Executes validation attempts concurrently where possible.
        """
        # For now, wrap synchronous version
        # In future, this could use asyncio.gather for parallel attempts
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.validate_stability(
                attack_result, context, detector, variant_generator, mode
            ),
        )


# Global stability validator instance
_stability_validator_instance: Optional[StabilityValidator] = None


def get_stability_validator(
    config: Optional[StabilityConfig] = None,
    executor: Optional[Callable] = None,
) -> StabilityValidator:
    """Get or create global stability validator instance.

    Args:
        config: Stability validation configuration
        executor: Attack execution function

    Returns:
        StabilityValidator instance
    """
    global _stability_validator_instance

    if _stability_validator_instance is None:
        _stability_validator_instance = StabilityValidator(config=config, executor=executor)
    elif executor is not None:
        _stability_validator_instance.set_executor(executor)
    if config is not None:
        _stability_validator_instance.config = config

    return _stability_validator_instance


def reset_stability_validator() -> None:
    """Reset the global stability validator instance."""
    global _stability_validator_instance
    _stability_validator_instance = None
