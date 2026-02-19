"""Unit tests for ScoringEngine."""

import pytest

from src.core.attack_engine import AttackCategory, AttackSeverity, GeneratedAttack
from src.core.scoring_engine import (
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
from src.plugins.base import AttackResult


def create_attack(
    id: str,
    category: AttackCategory,
    payload: str,
    severity: AttackSeverity,
) -> GeneratedAttack:
    """Helper to create GeneratedAttack with required fields."""
    return GeneratedAttack(
        id=id,
        category=category,
        payload=payload,
        severity=severity,
        template_id=f"template-{id}",
        template_name=f"Test Template {id}",
    )


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_risk_level_values(self):
        """Test risk level values."""
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"


class TestPriority:
    """Tests for Priority enum."""

    def test_priority_values(self):
        """Test priority values."""
        assert Priority.P3.value == "P3"  # Low
        assert Priority.P2.value == "P2"  # Medium
        assert Priority.P1.value == "P1"  # High
        assert Priority.P0.value == "P0"  # Critical


class TestSeverityWeights:
    """Tests for severity weights configuration."""

    def test_all_categories_have_weights(self):
        """Test all attack categories have defined weights."""
        for category in AttackCategory:
            assert category in SEVERITY_WEIGHTS, f"Missing weight for {category}"

    def test_weights_in_valid_range(self):
        """Test all weights are in valid 0-1 range."""
        for category, weight in SEVERITY_WEIGHTS.items():
            assert 0 <= weight <= 1, f"Invalid weight {weight} for {category}"

    def test_prompt_injection_has_highest_weight(self):
        """Test prompt injection has highest weight (most severe)."""
        max_weight = max(SEVERITY_WEIGHTS.values())
        assert SEVERITY_WEIGHTS[AttackCategory.LLM01_PROMPT_INJECTION] == max_weight


class TestRiskScore:
    """Tests for RiskScore model."""

    @pytest.fixture
    def sample_risk_score(self):
        """Create sample risk score for testing."""
        return RiskScore(
            score=65.0,
            level=RiskLevel.HIGH,
            priority=Priority.P1,
            severity_weight=0.9,
            confidence=0.85,
            reproducibility=0.8,
            impact_factor=0.75,
            category=AttackCategory.LLM01_PROMPT_INJECTION,
        )

    def test_risk_score_creation(self, sample_risk_score):
        """Test creating a risk score."""
        assert sample_risk_score.score == 65.0
        assert sample_risk_score.level == RiskLevel.HIGH
        assert sample_risk_score.priority == Priority.P1

    def test_is_critical(self, sample_risk_score):
        """Test is_critical property."""
        assert sample_risk_score.is_critical is False

        critical = RiskScore(
            score=85.0,
            level=RiskLevel.CRITICAL,
            priority=Priority.P0,
            severity_weight=0.9,
            confidence=0.9,
            reproducibility=0.9,
            impact_factor=1.0,
            category=AttackCategory.LLM01_PROMPT_INJECTION,
        )
        assert critical.is_critical is True

    def test_is_high(self, sample_risk_score):
        """Test is_high property."""
        assert sample_risk_score.is_high is True

        low = RiskScore(
            score=15.0,
            level=RiskLevel.LOW,
            priority=Priority.P3,
            severity_weight=0.5,
            confidence=0.5,
            reproducibility=0.5,
            impact_factor=0.5,
            category=AttackCategory.LLM09_MISINFORMATION,
        )
        assert low.is_high is False


class TestRiskScorer:
    """Tests for RiskScorer class."""

    @pytest.fixture
    def sample_attack_result(self):
        """Create sample attack result for testing."""
        attack = create_attack(
            id="test-001",
            category=AttackCategory.LLM01_PROMPT_INJECTION,
            payload="Test payload",
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
    def scorer(self):
        """Create scorer instance."""
        return RiskScorer()

    def test_scorer_initialization(self, scorer):
        """Test scorer initialization."""
        assert scorer.severity_weights is not None
        assert scorer.default_severity_weight == DEFAULT_SEVERITY_WEIGHT

    def test_calculate_basic(self, scorer, sample_attack_result):
        """Test basic risk score calculation."""
        risk = scorer.calculate(sample_attack_result)

        assert isinstance(risk, RiskScore)
        assert 0 <= risk.score <= 100
        assert isinstance(risk.level, RiskLevel)
        assert isinstance(risk.priority, Priority)

    def test_calculate_high_confidence_high_severity(self, scorer):
        """Test calculation with high confidence and severity."""
        attack = create_attack(
            id="test-002",
            category=AttackCategory.LLM01_PROMPT_INJECTION,
            payload="Critical attack",
            severity=AttackSeverity.CRITICAL,
        )
        result = AttackResult(
            attack=attack,
            success=True,
            response="Response",
            detected=True,
            confidence=0.95,
            evidence={"pii_found": True},
        )

        risk = scorer.calculate(result)

        # High confidence * high severity weight should give high score
        assert risk.severity_weight >= 0.9
        assert risk.confidence >= 0.9
        assert risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_calculate_low_confidence(self, scorer):
        """Test calculation with low confidence."""
        attack = create_attack(
            id="test-003",
            category=AttackCategory.LLM09_MISINFORMATION,
            payload="Low severity",
            severity=AttackSeverity.LOW,
        )
        result = AttackResult(
            attack=attack,
            success=True,
            response="Response",
            detected=True,
            confidence=0.3,
        )

        risk = scorer.calculate(result)

        # Low confidence should give low score
        assert risk.score < 50
        assert risk.level in (RiskLevel.LOW, RiskLevel.MEDIUM)

    def test_calculate_with_impact_factor(self, scorer, sample_attack_result):
        """Test calculation with custom impact factor."""
        risk_default = scorer.calculate(sample_attack_result)
        risk_high = scorer.calculate(sample_attack_result, impact_factor=1.0)
        risk_low = scorer.calculate(sample_attack_result, impact_factor=0.1)

        assert risk_high.score > risk_default.score > risk_low.score

    def test_determine_level_boundaries(self, scorer):
        """Test risk level determination at boundaries."""
        assert scorer._determine_level(0) == RiskLevel.LOW
        assert scorer._determine_level(24) == RiskLevel.LOW
        assert scorer._determine_level(25) == RiskLevel.MEDIUM
        assert scorer._determine_level(49) == RiskLevel.MEDIUM
        assert scorer._determine_level(50) == RiskLevel.HIGH
        assert scorer._determine_level(74) == RiskLevel.HIGH
        assert scorer._determine_level(75) == RiskLevel.CRITICAL
        assert scorer._determine_level(100) == RiskLevel.CRITICAL

    def test_get_severity_weight(self, scorer):
        """Test getting severity weight for categories."""
        weight = scorer.get_severity_weight(AttackCategory.LLM01_PROMPT_INJECTION)
        assert weight == SEVERITY_WEIGHTS[AttackCategory.LLM01_PROMPT_INJECTION]

    def test_set_severity_weight(self, scorer):
        """Test setting custom severity weight."""
        scorer.set_severity_weight(AttackCategory.LLM01_PROMPT_INJECTION, 0.5)
        assert scorer.get_severity_weight(AttackCategory.LLM01_PROMPT_INJECTION) == 0.5

    def test_set_invalid_weight(self, scorer):
        """Test setting invalid weight raises error."""
        with pytest.raises(ValueError):
            scorer.set_severity_weight(AttackCategory.LLM01_PROMPT_INJECTION, 1.5)

        with pytest.raises(ValueError):
            scorer.set_severity_weight(AttackCategory.LLM01_PROMPT_INJECTION, -0.1)

    def test_batch_score(self, scorer):
        """Test batch scoring."""
        attacks = [
            AttackResult(
                attack=create_attack(
                    id=f"test-{i}",
                    category=AttackCategory.LLM01_PROMPT_INJECTION,
                    payload=f"Payload {i}",
                    severity=AttackSeverity.HIGH,
                ),
                success=True,
                response="Response",
                detected=True,
                confidence=0.5 + i * 0.1,
            )
            for i in range(5)
        ]

        scores = scorer.batch_score(attacks)

        assert len(scores) == 5
        assert all(isinstance(s, RiskScore) for s in scores)
        # Scores should increase with confidence
        assert scores[0].score < scores[-1].score

    def test_summarize_empty(self, scorer):
        """Test summarize with empty list."""
        summary = scorer.summarize([])

        assert summary["total"] == 0
        assert summary["average_score"] == 0.0
        assert summary["max_score"] == 0.0

    def test_summarize_with_scores(self, scorer):
        """Test summarize with scores."""
        scores = [
            RiskScore(
                score=80.0,
                level=RiskLevel.HIGH,
                priority=Priority.P1,
                severity_weight=0.9,
                confidence=0.9,
                reproducibility=0.9,
                impact_factor=0.9,
                category=AttackCategory.LLM01_PROMPT_INJECTION,
            ),
            RiskScore(
                score=30.0,
                level=RiskLevel.MEDIUM,
                priority=Priority.P2,
                severity_weight=0.7,
                confidence=0.7,
                reproducibility=0.7,
                impact_factor=0.7,
                category=AttackCategory.LLM02_DATA_LEAK,
            ),
        ]

        summary = scorer.summarize(scores)

        assert summary["total"] == 2
        assert summary["average_score"] == 55.0
        assert summary["max_score"] == 80.0
        assert summary["by_level"]["high"] == 1
        assert summary["by_level"]["medium"] == 1


class TestGlobalFunctions:
    """Tests for global scorer functions."""

    def test_get_scorer_singleton(self):
        """Test get_scorer returns singleton."""
        reset_scorer()

        scorer1 = get_scorer()
        scorer2 = get_scorer()

        assert scorer1 is scorer2

        reset_scorer()

    def test_reset_scorer(self):
        """Test reset_scorer creates new instance."""
        reset_scorer()
        scorer1 = get_scorer()

        reset_scorer()
        scorer2 = get_scorer()

        assert scorer1 is not scorer2
        reset_scorer()

    def test_calculate_risk_score_function(self):
        """Test convenience function."""
        reset_scorer()

        attack = create_attack(
            id="test-func",
            category=AttackCategory.LLM01_PROMPT_INJECTION,
            payload="Test",
            severity=AttackSeverity.HIGH,
        )
        result = AttackResult(
            attack=attack,
            success=True,
            response="Response",
            detected=True,
            confidence=0.8,
        )

        risk = calculate_risk_score(result)

        assert isinstance(risk, RiskScore)
        assert 0 <= risk.score <= 100

        reset_scorer()
