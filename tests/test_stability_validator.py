"""Tests for Stability Validator module."""

import pytest
from unittest.mock import MagicMock, patch
import time

from src.core.validation_engine.stability import (
    StabilityValidator,
    StabilityConfig,
    StabilityResult,
    StabilityLevel,
    ValidationStrategy,
    ValidationAttempt,
    get_stability_validator,
    reset_stability_validator,
)


# Fixtures
@pytest.fixture
def mock_attack_result():
    """Create a mock attack result."""
    result = MagicMock()
    result.attack = "test attack payload"
    result.confidence = 0.8
    result.detected = True
    result.evidence = {"matched": "pattern"}
    return result


@pytest.fixture
def mock_context():
    """Create a mock attack context."""
    return MagicMock()


@pytest.fixture
def mock_executor():
    """Create a mock executor that returns responses."""
    def execute(attack, context):
        return f"Response to: {attack}"
    return execute


@pytest.fixture
def mock_detector_always_detects():
    """Create a mock detector that always detects vulnerabilities."""
    def detect(attack, response, context):
        result = MagicMock()
        result.detected = True
        result.confidence = 0.9
        result.evidence = {"found": True}
        return result
    return detect


@pytest.fixture
def mock_detector_never_detects():
    """Create a mock detector that never detects vulnerabilities."""
    def detect(attack, response, context):
        result = MagicMock()
        result.detected = False
        result.confidence = 0.0
        result.evidence = {}
        return result
    return detect


@pytest.fixture
def mock_detector_flaky():
    """Create a flaky detector that alternates detection."""
    call_count = [0]
    def detect(attack, response, context):
        call_count[0] += 1
        result = MagicMock()
        result.detected = call_count[0] % 2 == 1  # Detect on odd calls
        result.confidence = 0.7 if result.detected else 0.0
        result.evidence = {}
        return result
    return detect


@pytest.fixture
def mock_variant_generator():
    """Create a mock variant generator."""
    def generate(attack):
        return [f"{attack} variant 1", f"{attack} variant 2", f"{attack} variant 3"]
    return generate


# StabilityConfig Tests
class TestStabilityConfig:
    """Tests for StabilityConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = StabilityConfig()
        assert config.enabled is True
        assert config.min_validations == 2
        assert config.max_validations == 3
        assert config.required_consistency == 0.66
        assert config.retry_delay == 0.5
        assert config.variant_on_retry is True
        assert config.strategy == ValidationStrategy.HYBRID

    def test_get_attempts_for_mode(self):
        """Test attempt count for different scan modes."""
        config = StabilityConfig()

        assert config.get_attempts_for_mode("quick") == 1
        assert config.get_attempts_for_mode("standard") == 3
        assert config.get_attempts_for_mode("deep") == 4

    def test_quick_mode(self):
        """Test quick mode configuration."""
        config = StabilityConfig(quick_mode=True)
        assert config.get_attempts_for_mode("standard") == 1

    def test_custom_config(self):
        """Test custom configuration."""
        config = StabilityConfig(
            min_validations=3,
            max_validations=5,
            required_consistency=0.8,
            strategy=ValidationStrategy.PROGRESSIVE,
        )
        assert config.min_validations == 3
        assert config.max_validations == 5
        assert config.required_consistency == 0.8
        assert config.strategy == ValidationStrategy.PROGRESSIVE


# ValidationAttempt Tests
class TestValidationAttempt:
    """Tests for ValidationAttempt."""

    def test_default_attempt(self):
        """Test default validation attempt."""
        attempt = ValidationAttempt(
            attempt_number=1,
            attack_used="test",
        )
        assert attempt.attempt_number == 1
        assert attempt.detected is False
        assert attempt.confidence == 0.0
        assert attempt.error is None

    def test_attempt_to_dict(self):
        """Test converting attempt to dictionary."""
        attempt = ValidationAttempt(
            attempt_number=2,
            attack_used="test attack",
            response="test response",
            detected=True,
            confidence=0.85,
            evidence={"key": "value"},
        )
        result = attempt.to_dict()

        assert result["attempt_number"] == 2
        assert result["detected"] is True
        assert result["confidence"] == 0.85


# StabilityResult Tests
class TestStabilityResult:
    """Tests for StabilityResult."""

    def test_is_false_positive(self):
        """Test false positive detection."""
        result = StabilityResult(
            stability_level=StabilityLevel.FALSE_POSITIVE,
        )
        assert result.is_false_positive is True
        assert result.is_stable is False

    def test_needs_review(self):
        """Test needs_review property."""
        unstable = StabilityResult(stability_level=StabilityLevel.UNSTABLE)
        flaky = StabilityResult(stability_level=StabilityLevel.FLAKY)
        stable = StabilityResult(stability_level=StabilityLevel.STABLE)

        assert unstable.needs_review is True
        assert flaky.needs_review is True
        assert stable.needs_review is False

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = StabilityResult(
            is_stable=True,
            stability_level=StabilityLevel.STABLE,
            confidence=0.9,
            consistency=1.0,
            validation_count=3,
            successful_count=3,
            strategy_used=ValidationStrategy.REPLAY,
        )
        d = result.to_dict()

        assert d["is_stable"] is True
        assert d["stability_level"] == "stable"
        assert d["confidence"] == 0.9
        assert d["strategy_used"] == "replay"


# StabilityValidator Tests
class TestStabilityValidator:
    """Tests for StabilityValidator."""

    def test_init_default_config(self):
        """Test validator initialization with default config."""
        validator = StabilityValidator()
        assert validator.config is not None
        assert validator.config.enabled is True

    def test_init_custom_config(self):
        """Test validator initialization with custom config."""
        config = StabilityConfig(min_validations=5)
        validator = StabilityValidator(config=config)
        assert validator.config.min_validations == 5

    def test_set_executor(self, mock_executor):
        """Test setting executor."""
        validator = StabilityValidator()
        validator.set_executor(mock_executor)
        assert validator.executor == mock_executor

    def test_validate_disabled(
        self, mock_attack_result, mock_context, mock_detector_always_detects
    ):
        """Test validation when disabled."""
        config = StabilityConfig(enabled=False)
        validator = StabilityValidator(config=config)

        result = validator.validate_stability(
            mock_attack_result, mock_context, mock_detector_always_detects
        )

        assert result.is_stable is True
        assert result.validation_count == 0

    def test_validate_no_executor(self, mock_attack_result, mock_context, mock_detector_always_detects):
        """Test validation without executor."""
        validator = StabilityValidator()

        result = validator.validate_stability(
            mock_attack_result, mock_context, mock_detector_always_detects
        )

        assert result.is_stable is False
        assert "No executor" in result.notes

    def test_validate_stable_vulnerability(
        self, mock_attack_result, mock_context, mock_executor, mock_detector_always_detects
    ):
        """Test validation of a stable vulnerability."""
        config = StabilityConfig(retry_delay=0)  # No delay for tests
        validator = StabilityValidator(config=config, executor=mock_executor)

        result = validator.validate_stability(
            mock_attack_result, mock_context, mock_detector_always_detects
        )

        assert result.is_stable is True
        assert result.stability_level == StabilityLevel.STABLE
        assert result.consistency == 1.0
        assert result.successful_count == result.validation_count

    def test_validate_false_positive(
        self, mock_attack_result, mock_context, mock_executor, mock_detector_never_detects
    ):
        """Test validation of a false positive."""
        config = StabilityConfig(retry_delay=0)
        validator = StabilityValidator(config=config, executor=mock_executor)

        result = validator.validate_stability(
            mock_attack_result, mock_context, mock_detector_never_detects
        )

        assert result.is_stable is False
        assert result.stability_level == StabilityLevel.FALSE_POSITIVE
        assert result.successful_count == 0

    def test_validate_unstable_vulnerability(
        self, mock_attack_result, mock_context, mock_executor, mock_detector_flaky
    ):
        """Test validation of an unstable vulnerability."""
        config = StabilityConfig(
            max_validations=4,
            required_consistency=0.66,
            retry_delay=0,
        )
        validator = StabilityValidator(config=config, executor=mock_executor)

        result = validator.validate_stability(
            mock_attack_result, mock_context, mock_detector_flaky
        )

        # Flaky detector: 50% success rate
        assert result.successful_count == 2
        assert result.failed_count == 2
        assert result.consistency == 0.5

    def test_validate_replay_strategy(
        self, mock_attack_result, mock_context, mock_executor, mock_detector_always_detects
    ):
        """Test replay validation strategy."""
        config = StabilityConfig(
            strategy=ValidationStrategy.REPLAY,
            max_validations=3,
            retry_delay=0,
        )
        validator = StabilityValidator(config=config, executor=mock_executor)

        result = validator.validate_stability(
            mock_attack_result, mock_context, mock_detector_always_detects
        )

        assert result.strategy_used == ValidationStrategy.REPLAY
        assert result.validation_count == 3

    def test_validate_variant_strategy(
        self,
        mock_attack_result,
        mock_context,
        mock_executor,
        mock_detector_always_detects,
        mock_variant_generator,
    ):
        """Test variant validation strategy."""
        config = StabilityConfig(
            strategy=ValidationStrategy.VARIANT,
            max_validations=3,
            retry_delay=0,
        )
        validator = StabilityValidator(config=config, executor=mock_executor)

        result = validator.validate_stability(
            mock_attack_result,
            mock_context,
            mock_detector_always_detects,
            variant_generator=mock_variant_generator,
        )

        assert result.strategy_used == ValidationStrategy.VARIANT
        assert result.is_stable is True

    def test_validate_hybrid_strategy(
        self,
        mock_attack_result,
        mock_context,
        mock_executor,
        mock_detector_always_detects,
        mock_variant_generator,
    ):
        """Test hybrid validation strategy."""
        config = StabilityConfig(
            strategy=ValidationStrategy.HYBRID,
            max_validations=4,
            retry_delay=0,
        )
        validator = StabilityValidator(config=config, executor=mock_executor)

        result = validator.validate_stability(
            mock_attack_result,
            mock_context,
            mock_detector_always_detects,
            variant_generator=mock_variant_generator,
        )

        assert result.strategy_used == ValidationStrategy.HYBRID
        assert result.validation_count == 4

    def test_validate_progressive_strategy_stable_early(
        self,
        mock_attack_result,
        mock_context,
        mock_executor,
        mock_detector_always_detects,
    ):
        """Test progressive strategy stops early when stable."""
        config = StabilityConfig(
            strategy=ValidationStrategy.PROGRESSIVE,
            min_validations=2,
            required_consistency=0.66,
            retry_delay=0,
        )
        validator = StabilityValidator(config=config, executor=mock_executor)

        result = validator.validate_stability(
            mock_attack_result, mock_context, mock_detector_always_detects
        )

        assert result.is_stable is True
        # Should stop at min_validations since 100% consistent
        assert result.validation_count >= config.min_validations

    def test_validate_quick_mode(
        self, mock_attack_result, mock_context, mock_executor, mock_detector_always_detects
    ):
        """Test quick mode validation."""
        config = StabilityConfig(quick_mode=True, retry_delay=0)
        validator = StabilityValidator(config=config, executor=mock_executor)

        result = validator.validate_stability(
            mock_attack_result, mock_context, mock_detector_always_detects, mode="standard"
        )

        assert result.validation_count == 1

    def test_validate_with_exception(
        self, mock_attack_result, mock_context, mock_detector_always_detects
    ):
        """Test validation handles exceptions gracefully."""
        def failing_executor(attack, context):
            raise RuntimeError("Network error")

        config = StabilityConfig(max_validations=2, retry_delay=0)
        validator = StabilityValidator(config=config, executor=failing_executor)

        result = validator.validate_stability(
            mock_attack_result, mock_context, mock_detector_always_detects
        )

        assert result.successful_count == 0
        # Check that error was recorded
        assert len(result.attempts) == 2
        assert result.attempts[0]["error"] is not None

    def test_confidence_calculation(
        self, mock_attack_result, mock_context, mock_executor
    ):
        """Test confidence is calculated correctly."""
        # Create detector with varying confidence
        call_count = [0]
        def varying_detector(attack, response, context):
            call_count[0] += 1
            result = MagicMock()
            result.detected = True
            result.confidence = 0.5 + (call_count[0] * 0.1)  # 0.6, 0.7, 0.8
            result.evidence = {}
            return result

        config = StabilityConfig(max_validations=3, retry_delay=0)
        validator = StabilityValidator(config=config, executor=mock_executor)

        result = validator.validate_stability(
            mock_attack_result, mock_context, varying_detector
        )

        # Average of 0.6, 0.7, 0.8 = 0.7
        assert result.confidence == pytest.approx(0.7, rel=0.01)


# Global instance tests
class TestGlobalStabilityValidator:
    """Tests for global stability validator functions."""

    def setup_method(self):
        """Reset global instance before each test."""
        reset_stability_validator()

    def teardown_method(self):
        """Reset global instance after each test."""
        reset_stability_validator()

    def test_get_stability_validator_creates_instance(self):
        """Test get_stability_validator creates new instance."""
        validator = get_stability_validator()
        assert validator is not None
        assert isinstance(validator, StabilityValidator)

    def test_get_stability_validator_returns_same_instance(self):
        """Test get_stability_validator returns same instance."""
        validator1 = get_stability_validator()
        validator2 = get_stability_validator()
        assert validator1 is validator2

    def test_get_stability_validator_sets_executor(self):
        """Test get_stability_validator sets executor."""
        def dummy_executor(attack, context):
            return "response"

        validator = get_stability_validator(executor=dummy_executor)
        assert validator.executor == dummy_executor

    def test_get_stability_validator_updates_config(self):
        """Test get_stability_validator updates config."""
        get_stability_validator()  # Create instance first
        config = StabilityConfig(min_validations=10)
        validator = get_stability_validator(config=config)

        assert validator.config.min_validations == 10

    def test_reset_stability_validator(self):
        """Test reset_stability_validator clears instance."""
        get_stability_validator()
        reset_stability_validator()

        # Should create new instance after reset
        validator = get_stability_validator()
        assert validator is not None


# Integration tests
class TestStabilityValidatorIntegration:
    """Integration tests for StabilityValidator."""

    def test_full_validation_workflow(
        self, mock_attack_result, mock_context, mock_executor, mock_detector_always_detects
    ):
        """Test complete validation workflow."""
        config = StabilityConfig(
            strategy=ValidationStrategy.HYBRID,
            min_validations=2,
            max_validations=3,
            required_consistency=0.66,
            retry_delay=0,
        )
        validator = StabilityValidator(config=config, executor=mock_executor)

        result = validator.validate_stability(
            mock_attack_result,
            mock_context,
            mock_detector_always_detects,
        )

        # Verify result structure
        assert result.is_stable is True
        assert result.stability_level == StabilityLevel.STABLE
        assert result.confidence > 0
        assert result.consistency == 1.0
        assert result.validation_count >= config.min_validations
        assert result.successful_count == result.validation_count
        assert result.failed_count == 0
        assert len(result.attempts) == result.validation_count
        assert result.strategy_used == ValidationStrategy.HYBRID

    def test_scan_mode_affects_attempts(
        self, mock_attack_result, mock_context, mock_executor, mock_detector_always_detects
    ):
        """Test that scan mode affects number of attempts."""
        config = StabilityConfig(retry_delay=0)
        validator = StabilityValidator(config=config, executor=mock_executor)

        # Quick mode
        result_quick = validator.validate_stability(
            mock_attack_result, mock_context, mock_detector_always_detects, mode="quick"
        )
        assert result_quick.validation_count == 1

        # Standard mode
        result_standard = validator.validate_stability(
            mock_attack_result, mock_context, mock_detector_always_detects, mode="standard"
        )
        assert result_standard.validation_count == 3

        # Deep mode
        result_deep = validator.validate_stability(
            mock_attack_result, mock_context, mock_detector_always_detects, mode="deep"
        )
        assert result_deep.validation_count == 4
