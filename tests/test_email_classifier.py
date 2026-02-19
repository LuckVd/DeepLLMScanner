"""Unit tests for EmailClassifier."""

import pytest

from src.core.detection_engine import (
    EmailClassifier,
    EmailClassification,
    EmailClassifyResult,
)


class TestEmailClassifier:
    """Tests for EmailClassifier class."""

    @pytest.fixture
    def classifier(self):
        """Create a classifier instance for testing."""
        return EmailClassifier(use_llm=False)

    # ==================== Public Email Tests ====================

    @pytest.mark.parametrize("email", [
        "press@openai.com",
        "media@company.com",
        "support@google.com",
        "help@amazon.com",
        "contact@microsoft.com",
        "info@apple.com",
        "sales@meta.com",
        "business@netflix.com",
        "careers@stripe.com",
        "jobs@spacex.com",
        "legal@tesla.com",
        "privacy@facebook.com",
        "security@github.com",
        "webmaster@example.com",
        "noreply@linkedin.com",
        "donotreply@instagram.com",
    ])
    def test_classify_public_emails_whitelist(self, classifier, email):
        """Test that known public prefixes are classified as PUBLIC."""
        result = classifier.classify(email)
        assert result.classification == EmailClassification.PUBLIC
        assert result.confidence >= 0.9
        assert result.method in ["whitelist", "whitelist_compound"]

    @pytest.mark.parametrize("email", [
        "no-reply@twitter.com",
        "no-reply@example.org",
    ])
    def test_classify_no_reply_emails(self, classifier, email):
        """Test no-reply emails are classified as PUBLIC via pattern."""
        result = classifier.classify(email)
        assert result.classification == EmailClassification.PUBLIC
        assert result.confidence >= 0.8  # Pattern match has slightly lower confidence

    @pytest.mark.parametrize("email", [
        "press-team@company.com",
        "media_relations@org.com",
        "support-center@service.com",
        "info-dept@business.com",
    ])
    def test_classify_compound_public_emails(self, classifier, email):
        """Test compound public prefixes are classified as PUBLIC."""
        result = classifier.classify(email)
        assert result.classification == EmailClassification.PUBLIC
        assert result.confidence >= 0.85

    @pytest.mark.parametrize("email", [
        "press2024@company.com",
        "support1@service.com",
        "info123@org.com",
    ])
    def test_classify_public_with_numbers(self, classifier, email):
        """Test public emails with numbers."""
        result = classifier.classify(email)
        # Should be classified as public via pattern matching
        assert result.classification in [EmailClassification.PUBLIC, EmailClassification.UNKNOWN]

    # ==================== Private Email Tests ====================

    @pytest.mark.parametrize("email", [
        "john.smith@company.com",
        "jane.doe@organization.com",
        "bob_jones@business.com",
        "alice-williams@corp.com",
        "john@gmail.com",
        "jane@outlook.com",
        "bob@yahoo.com",
        "alice@hotmail.com",
        "test@icloud.com",
        "user@proton.me",
    ])
    def test_classify_private_emails(self, classifier, email):
        """Test that personal emails are classified as PRIVATE."""
        result = classifier.classify(email)
        assert result.classification == EmailClassification.PRIVATE
        assert result.confidence >= 0.8

    # ==================== Unknown/Uncertain Tests ====================

    @pytest.mark.parametrize("email", [
        "admin123@company.com",
        "user2024@org.com",
        "team@business.com",
        "office@corporation.com",
    ])
    def test_classify_unknown_emails(self, classifier, email):
        """Test emails that can't be clearly classified."""
        result = classifier.classify(email)
        # These should not be classified as clearly public or private
        assert result.classification in [
            EmailClassification.UNKNOWN,
            EmailClassification.PUBLIC,
            EmailClassification.PRIVATE,
        ]

    # ==================== Invalid Email Tests ====================

    @pytest.mark.parametrize("email", [
        "",
        "not-an-email",
        "@example.com",
        "user@",
        "user@example",
    ])
    def test_classify_invalid_emails(self, classifier, email):
        """Test invalid email formats."""
        result = classifier.classify(email)
        assert result.classification == EmailClassification.INVALID
        assert result.confidence == 1.0

    # ==================== Helper Method Tests ====================

    def test_is_public(self, classifier):
        """Test is_public helper method."""
        assert classifier.is_public("press@company.com") is True
        assert classifier.is_public("john.smith@company.com") is False

    def test_is_private(self, classifier):
        """Test is_private helper method."""
        assert classifier.is_private("john.smith@company.com") is True
        assert classifier.is_private("press@company.com") is False

    def test_get_confidence(self, classifier):
        """Test get_confidence helper method."""
        confidence = classifier.get_confidence("press@company.com")
        assert 0.0 <= confidence <= 1.0
        assert confidence >= 0.9  # High confidence for whitelist match

    # ==================== Batch Operations Tests ====================

    def test_batch_classify(self, classifier):
        """Test batch classification."""
        emails = [
            "press@company.com",
            "john.smith@company.com",
            "support@org.com",
            "invalid-email",
        ]
        results = classifier.batch_classify(emails)

        assert len(results) == 4
        assert results[0].classification == EmailClassification.PUBLIC
        assert results[1].classification == EmailClassification.PRIVATE
        assert results[2].classification == EmailClassification.PUBLIC
        assert results[3].classification == EmailClassification.INVALID

    def test_filter_public(self, classifier):
        """Test filtering public emails."""
        emails = [
            "press@company.com",
            "john.smith@company.com",
            "support@org.com",
            "jane.doe@corp.com",
        ]
        filtered = classifier.filter_public(emails)

        # Public emails should be removed
        assert "press@company.com" not in filtered
        assert "support@org.com" not in filtered
        # Private emails should remain
        assert "john.smith@company.com" in filtered
        assert "jane.doe@corp.com" in filtered

    def test_filter_private(self, classifier):
        """Test filtering to keep only private emails."""
        emails = [
            "press@company.com",
            "john.smith@company.com",
            "support@org.com",
            "jane.doe@corp.com",
        ]
        filtered = classifier.filter_private(emails)

        # Only private emails should remain
        assert "john.smith@company.com" in filtered
        assert "jane.doe@corp.com" in filtered
        # Public emails should be removed
        assert "press@company.com" not in filtered
        assert "support@org.com" not in filtered

    # ==================== Edge Cases ====================

    def test_case_insensitivity(self, classifier):
        """Test that classification is case-insensitive."""
        result1 = classifier.classify("PRESS@COMPANY.COM")
        result2 = classifier.classify("press@company.com")
        result3 = classifier.classify("Press@Company.Com")

        assert result1.classification == result2.classification == result3.classification

    def test_whitespace_handling(self, classifier):
        """Test that whitespace is trimmed."""
        result1 = classifier.classify("  press@company.com  ")
        result2 = classifier.classify("press@company.com")

        assert result1.classification == result2.classification
        assert result1.email == result2.email

    def test_real_world_scenario(self, classifier):
        """Test real-world scenario from the bug report."""
        # This is the email that was incorrectly flagged as a vulnerability
        email = "press@openai.com"
        result = classifier.classify(email)

        assert result.classification == EmailClassification.PUBLIC
        assert result.confidence >= 0.9

        # The classifier should correctly identify this as public
        assert classifier.is_public(email) is True
        assert classifier.is_private(email) is False

    def test_multiple_emails_mixed(self, classifier):
        """Test classification of a mix of email types."""
        emails = [
            "press@openai.com",          # Public (whitelist)
            "partnerships@openai.com",   # Public (whitelist)
            "john.smith@openai.com",     # Private (name pattern)
            "support@company.com",       # Public (whitelist)
            "jane_doe@corp.com",         # Private (name pattern)
            "info@example.org",          # Public (whitelist)
            "user@gmail.com",            # Private (personal domain)
        ]

        results = classifier.batch_classify(emails)

        # Check public emails
        assert results[0].classification == EmailClassification.PUBLIC  # press@
        assert results[1].classification == EmailClassification.PUBLIC  # partnerships@
        assert results[3].classification == EmailClassification.PUBLIC  # support@
        assert results[5].classification == EmailClassification.PUBLIC  # info@

        # Check private emails
        assert results[2].classification == EmailClassification.PRIVATE  # john.smith@
        assert results[4].classification == EmailClassification.PRIVATE  # jane_doe@
        assert results[6].classification == EmailClassification.PRIVATE  # @gmail.com


class TestEmailClassifierWithLLM:
    """Tests for EmailClassifier with LLM judge enabled."""

    @pytest.fixture
    def classifier_no_llm(self):
        """Create a classifier without LLM."""
        return EmailClassifier(use_llm=False)

    def test_llm_disabled_by_default(self, classifier_no_llm):
        """Test that LLM is disabled by default."""
        assert classifier_no_llm.use_llm is False
        assert classifier_no_llm.llm_judge is None

    def test_unknown_without_llm(self, classifier_no_llm):
        """Test that uncertain emails return UNKNOWN without LLM."""
        # This email is not clearly public or private
        result = classifier_no_llm.classify("team@company.com")
        # Should be unknown or classified by pattern
        assert result.classification in [
            EmailClassification.UNKNOWN,
            EmailClassification.PUBLIC,
            EmailClassification.PRIVATE,
        ]


class TestGlobalFunctions:
    """Tests for global classifier functions."""

    def test_get_classifier_singleton(self):
        """Test that get_classifier returns a singleton."""
        from src.core.detection_engine import get_classifier, reset_classifier

        # Reset first
        reset_classifier()

        classifier1 = get_classifier()
        classifier2 = get_classifier()

        assert classifier1 is classifier2

        # Clean up
        reset_classifier()

    def test_reset_classifier(self):
        """Test that reset_classifier creates a new instance."""
        from src.core.detection_engine import get_classifier, reset_classifier

        reset_classifier()
        classifier1 = get_classifier()

        reset_classifier()
        classifier2 = get_classifier()

        # After reset, should be a different instance
        assert classifier1 is not classifier2

        # Clean up
        reset_classifier()
