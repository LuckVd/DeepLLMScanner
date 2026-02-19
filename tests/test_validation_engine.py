"""Unit tests for ValidationEngine."""

import pytest

from src.core.attack_engine import AttackCategory, AttackSeverity, GeneratedAttack
from src.core.validation_engine import (
    VulnerabilityValidator,
    ValidationResult,
    ValidationStatus,
    ValidationMethod,
    get_validator,
    reset_validator,
)
from src.plugins.base import AttackResult


def create_attack(
    id: str,
    category: AttackCategory,
    severity: AttackSeverity,
) -> GeneratedAttack:
    """Helper to create GeneratedAttack with required fields."""
    return GeneratedAttack(
        id=id,
        category=category,
        payload=f"Test payload for {id}",
        severity=severity,
        template_id=f"template-{id}",
        template_name=f"Test Template {id}",
    )


class TestValidationStatus:
    """Tests for ValidationStatus enum."""

    def test_status_values(self):
        """Test validation status values."""
        assert ValidationStatus.CONFIRMED.value == "confirmed"
        assert ValidationStatus.UNCONFIRMED.value == "unconfirmed"
        assert ValidationStatus.FALSE_POSITIVE.value == "false_positive"
        assert ValidationStatus.UNCERTAIN.value == "uncertain"


class TestValidationMethod:
    """Tests for ValidationMethod enum."""

    def test_method_values(self):
        """Test validation method values."""
        assert ValidationMethod.REPLAY.value == "replay"
        assert ValidationMethod.VARIATION.value == "variation"
        assert ValidationMethod.SEMANTIC.value == "semantic"
        assert ValidationMethod.MANUAL.value == "manual"


class TestValidationResult:
    """Tests for ValidationResult model."""

    @pytest.fixture
    def sample_result(self):
        """Create sample attack result for testing."""
        attack = create_attack(
            id="test-001",
            category=AttackCategory.LLM01_PROMPT_INJECTION,
            severity=AttackSeverity.HIGH,
        )
        return AttackResult(
            attack=attack,
            success=True,
            response="Test response",
            detected=True,
            confidence=0.85,
        )

    def test_validation_result_creation(self, sample_result):
        """Test creating a validation result."""
        result = ValidationResult(
            original_result=sample_result,
            status=ValidationStatus.CONFIRMED,
            confidence=0.9,
            reproducibility=0.8,
            validation_method=ValidationMethod.REPLAY,
            attempts=3,
            successful_reproductions=2,
            notes="Test validation",
        )

        assert result.status == ValidationStatus.CONFIRMED
        assert result.confidence == 0.9
        assert result.reproducibility == 0.8
        assert result.validation_method == ValidationMethod.REPLAY
        assert result.attempts == 3
        assert result.successful_reproductions == 2
        assert result.notes == "Test validation"

    def test_is_confirmed(self, sample_result):
        """Test is_confirmed property."""
        confirmed = ValidationResult(
            original_result=sample_result,
            status=ValidationStatus.CONFIRMED,
            confidence=0.9,
            reproducibility=0.8,
        )
        assert confirmed.is_confirmed is True

        unconfirmed = ValidationResult(
            original_result=sample_result,
            status=ValidationStatus.UNCONFIRMED,
            confidence=0.5,
            reproducibility=0.0,
        )
        assert unconfirmed.is_confirmed is False

    def test_is_false_positive(self, sample_result):
        """Test is_false_positive property."""
        fp = ValidationResult(
            original_result=sample_result,
            status=ValidationStatus.FALSE_POSITIVE,
            confidence=0.1,
            reproducibility=0.0,
        )
        assert fp.is_false_positive is True

        confirmed = ValidationResult(
            original_result=sample_result,
            status=ValidationStatus.CONFIRMED,
            confidence=0.9,
            reproducibility=0.8,
        )
        assert confirmed.is_false_positive is False


class TestVulnerabilityValidator:
    """Tests for VulnerabilityValidator class."""

    @pytest.fixture
    def sample_attack_result(self):
        """Create sample attack result for testing."""
        attack = create_attack(
            id="test-001",
            category=AttackCategory.LLM02_DATA_LEAK,
            severity=AttackSeverity.HIGH,
        )
        return AttackResult(
            attack=attack,
            success=True,
            response="Test response",
            detected=True,
            confidence=0.85,
        )

    @pytest.fixture
    def validator(self):
        """Create validator without executor."""
        return VulnerabilityValidator()

    def test_validator_initialization(self, validator):
        """Test validator initialization."""
        assert validator.executor is None
        assert validator.min_reproducibility == 0.5
        assert validator.default_attempts == 3

    def test_validator_custom_config(self):
        """Test validator with custom configuration."""
        validator = VulnerabilityValidator(
            min_reproducibility=0.7,
            default_attempts=5,
        )
        assert validator.min_reproducibility == 0.7
        assert validator.default_attempts == 5

    def test_validate_without_executor(self, validator, sample_attack_result):
        """Test validation without executor returns unconfirmed."""
        result = validator.validate(sample_attack_result)

        assert result.status == ValidationStatus.UNCONFIRMED
        assert result.validation_method == ValidationMethod.MANUAL
        assert result.attempts == 0

    def test_quick_validate_high_confidence(self, validator, sample_attack_result):
        """Test quick validation with high confidence."""
        result = validator.quick_validate(sample_attack_result)

        assert result.status == ValidationStatus.CONFIRMED
        assert result.reproducibility == 0.9
        assert result.validation_method == ValidationMethod.SEMANTIC

    def test_quick_validate_medium_confidence(self, validator):
        """Test quick validation with medium confidence."""
        attack = create_attack(
            id="test-002",
            category=AttackCategory.LLM01_PROMPT_INJECTION,
            severity=AttackSeverity.MEDIUM,
        )
        result = AttackResult(
            attack=attack,
            success=True,
            response="Response",
            detected=True,
            confidence=0.6,
        )

        validation = validator.quick_validate(result)

        assert validation.status == ValidationStatus.UNCONFIRMED
        assert validation.reproducibility == 0.0

    def test_quick_validate_low_confidence(self, validator):
        """Test quick validation with low confidence."""
        attack = create_attack(
            id="test-003",
            category=AttackCategory.LLM01_PROMPT_INJECTION,
            severity=AttackSeverity.LOW,
        )
        result = AttackResult(
            attack=attack,
            success=True,
            response="Response",
            detected=True,
            confidence=0.3,
        )

        validation = validator.quick_validate(result)

        assert validation.status == ValidationStatus.FALSE_POSITIVE


class TestGlobalFunctions:
    """Tests for global validator functions."""

    def test_get_validator_singleton(self):
        """Test get_validator returns singleton."""
        reset_validator()

        validator1 = get_validator()
        validator2 = get_validator()

        assert validator1 is validator2

        reset_validator()

    def test_reset_validator(self):
        """Test reset_validator creates new instance."""
        reset_validator()
        validator1 = get_validator()

        reset_validator()
        validator2 = get_validator()

        assert validator1 is not validator2
        reset_validator()
