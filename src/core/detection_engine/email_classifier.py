"""Email classifier for distinguishing public vs private email addresses.

This module implements a multi-tier approach to email classification:
- Method C: Whitelist matching for known public email prefixes
- Method D: Pattern matching for email structure characteristics
- Method B: LLM judge for uncertain cases (optional)

The goal is to reduce false positives by correctly identifying public
business emails (like press@company.com) that should not be reported
as sensitive data leaks.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class EmailClassification(Enum):
    """Classification result for an email address."""

    PUBLIC = "public"  # Known public email (press@, support@, etc.)
    PRIVATE = "private"  # Likely private/personal email
    UNKNOWN = "unknown"  # Cannot determine
    INVALID = "invalid"  # Not a valid email format


@dataclass
class EmailClassifyResult:
    """Result from email classification."""

    email: str
    classification: EmailClassification
    confidence: float
    method: str  # Which method made the determination
    reason: str


class EmailClassifier:
    """Multi-tier email classifier for distinguishing public vs private emails.

    Classification flow:
    1. Method C (Whitelist): Check if prefix matches known public prefixes
    2. Method D (Pattern): Use regex patterns to identify email structure
    3. Method B (LLM Judge): Optional LLM validation for uncertain cases
    """

    # Method C: Public email prefix whitelist
    # These are known to be public-facing business emails
    PUBLIC_PREFIXES = {
        # Media/PR
        "press",
        "media",
        "pr",
        "public",
        "publicrelations",
        "communications",
        # Support/Service
        "support",
        "help",
        "service",
        "customer",
        "customerservice",
        "helpdesk",
        # Contact/Info
        "contact",
        "info",
        "information",
        "inquiries",
        "enquiries",
        "hello",
        # Business/Sales
        "sales",
        "business",
        "partnerships",
        "partners",
        "bizdev",
        "enterprise",
        # HR/Careers
        "careers",
        "jobs",
        "hr",
        "recruiting",
        "recruitment",
        "talent",
        # Legal/Compliance
        "legal",
        "privacy",
        "compliance",
        "dpo",
        "gdpr",
        # Security
        "security",
        "abuse",
        "report",
        # Technical/System
        "webmaster",
        "admin",
        "administrator",
        "hostmaster",
        "postmaster",
        "noreply",
        "no-reply",
        "donotreply",
        "notifications",
        "alerts",
        # Marketing
        "marketing",
        "newsletter",
        "subscribe",
        "unsubscribe",
    }

    # Method D: Public email patterns (regex)
    PUBLIC_PATTERNS = [
        # Functional prefixes with optional numbers
        r"^(press|media|support|help|info|contact|sales|careers)\d*@",
        # System emails
        r"^(noreply|no-?reply|donotreply|notifications?)@",
        # Team/department emails
        r"^(media|pr|legal|hr|it|finance|marketing)team@",
        # Office/region specific public emails
        r"^(info|contact|sales|support)[-_](us|uk|eu|asia|emea)@",
    ]

    # Method D: Private email patterns (regex)
    PRIVATE_PATTERNS = [
        # First.Last format (very common for personal corporate emails)
        r"^[a-z]+\.[a-z]+@",
        # First_Last format
        r"^[a-z]+_[a-z]+@",
        # First-Last format
        r"^[a-z]+-[a-z]+@",
        # FirstLast format (no separator, both capitalized in source)
        r"^[a-z]{3,15}[a-z]{3,15}@",
        # Initial + lastname (jsmith@)
        r"^[a-z][a-z]{2,}@",
        # firstname + numbers (john123@)
        r"^[a-z]{3,}\d{2,}@",
    ]

    # Private email domains (personal email providers)
    PRIVATE_DOMAINS = {
        "gmail.com",
        "outlook.com",
        "hotmail.com",
        "yahoo.com",
        "icloud.com",
        "proton.me",
        "protonmail.com",
        "aol.com",
        "mail.com",
        "zoho.com",
        "yandex.com",
        "gmx.com",
        "live.com",
        "msn.com",
        "me.com",
        "mac.com",
        "inbox.com",
        "email.com",
    }

    def __init__(self, use_llm: bool = False, llm_judge=None):
        """Initialize the email classifier.

        Args:
            use_llm: Whether to use LLM judge for uncertain cases
            llm_judge: Optional LLM judge instance
        """
        self.use_llm = use_llm
        self.llm_judge = llm_judge

        # Compile patterns for efficiency
        self._public_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.PUBLIC_PATTERNS
        ]
        self._private_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.PRIVATE_PATTERNS
        ]

    def classify(self, email: str) -> EmailClassifyResult:
        """Classify an email address using multi-tier approach.

        Args:
            email: Email address to classify

        Returns:
            EmailClassifyResult with classification and confidence
        """
        if not email or "@" not in email:
            return EmailClassifyResult(
                email=email,
                classification=EmailClassification.INVALID,
                confidence=1.0,
                method="validation",
                reason="Invalid email format",
            )

        email = email.lower().strip()

        # Check for valid email structure
        parts = email.rsplit("@", 1)
        if len(parts) != 2:
            return EmailClassifyResult(
                email=email,
                classification=EmailClassification.INVALID,
                confidence=1.0,
                method="validation",
                reason="Invalid email format",
            )

        local_part, domain = parts

        # Validate local part and domain
        if not local_part or not domain:
            return EmailClassifyResult(
                email=email,
                classification=EmailClassification.INVALID,
                confidence=1.0,
                method="validation",
                reason="Missing local part or domain",
            )

        # Check domain has at least one dot (valid TLD)
        if "." not in domain:
            return EmailClassifyResult(
                email=email,
                classification=EmailClassification.INVALID,
                confidence=1.0,
                method="validation",
                reason="Invalid domain format",
            )

        # Step 1: Method C - Whitelist matching
        result = self._classify_by_whitelist(email, local_part)
        if result:
            return result

        # Step 2: Method D - Pattern matching
        result = self._classify_by_pattern(email, local_part, domain)
        if result:
            return result

        # Step 3: Check domain for private providers
        if domain in self.PRIVATE_DOMAINS:
            return EmailClassifyResult(
                email=email,
                classification=EmailClassification.PRIVATE,
                confidence=0.85,
                method="domain_check",
                reason=f"Private email provider: {domain}",
            )

        # Step 4: If LLM enabled and uncertain, use LLM judge
        if self.use_llm and self.llm_judge:
            return self._classify_by_llm(email)

        # Default: Unknown
        return EmailClassifyResult(
            email=email,
            classification=EmailClassification.UNKNOWN,
            confidence=0.5,
            method="default",
            reason="Unable to determine classification",
        )

    def _classify_by_whitelist(
        self, email: str, local_part: str
    ) -> Optional[EmailClassifyResult]:
        """Method C: Check if email prefix matches known public prefixes."""
        # Get the base prefix (before any numbers or special chars)
        base_prefix = re.split(r"[\d._-]", local_part)[0]

        if base_prefix in self.PUBLIC_PREFIXES:
            return EmailClassifyResult(
                email=email,
                classification=EmailClassification.PUBLIC,
                confidence=0.95,
                method="whitelist",
                reason=f"Known public prefix: {base_prefix}",
            )

        # Check for compound prefixes like "press-team"
        for prefix in self.PUBLIC_PREFIXES:
            if local_part.startswith(prefix + "-") or local_part.startswith(prefix + "_"):
                return EmailClassifyResult(
                    email=email,
                    classification=EmailClassification.PUBLIC,
                    confidence=0.90,
                    method="whitelist_compound",
                    reason=f"Compound public prefix: {local_part}",
                )

        return None

    def _classify_by_pattern(
        self, email: str, local_part: str, domain: str
    ) -> Optional[EmailClassifyResult]:
        """Method D: Use regex patterns to classify email structure."""

        # Check public patterns
        for pattern in self._public_patterns:
            if pattern.match(email):
                return EmailClassifyResult(
                    email=email,
                    classification=EmailClassification.PUBLIC,
                    confidence=0.85,
                    method="pattern_public",
                    reason=f"Matches public pattern",
                )

        # Check private patterns
        for pattern in self._private_patterns:
            if pattern.match(email):
                return EmailClassifyResult(
                    email=email,
                    classification=EmailClassification.PRIVATE,
                    confidence=0.80,
                    method="pattern_private",
                    reason="Matches personal name pattern",
                )

        return None

    def _classify_by_llm(self, email: str) -> EmailClassifyResult:
        """Method B: Use LLM judge for uncertain cases."""
        if not self.llm_judge or not self.llm_judge.is_enabled():
            return EmailClassifyResult(
                email=email,
                classification=EmailClassification.UNKNOWN,
                confidence=0.5,
                method="llm_unavailable",
                reason="LLM judge not available",
            )

        try:
            prompt = f"""Is this email address public or private?

Email: {email}

A PUBLIC email is:
- A general business contact (press@, support@, info@)
- Listed on the company's public website
- Intended for anyone to use

A PRIVATE email is:
- A specific person's email (john.smith@company.com)
- Not publicly listed
- Contains personal identifiers

Answer with only "PUBLIC" or "PRIVATE" followed by a brief reason.
Example: "PUBLIC - This is a general support email"
"""

            result = self.llm_judge._inference.generate(prompt, max_tokens=100)
            response = result.text.strip().upper()

            if "PUBLIC" in response and "PRIVATE" not in response:
                return EmailClassifyResult(
                    email=email,
                    classification=EmailClassification.PUBLIC,
                    confidence=0.80,
                    method="llm",
                    reason=f"LLM classified as public",
                )
            elif "PRIVATE" in response:
                return EmailClassifyResult(
                    email=email,
                    classification=EmailClassification.PRIVATE,
                    confidence=0.80,
                    method="llm",
                    reason=f"LLM classified as private",
                )
            else:
                return EmailClassifyResult(
                    email=email,
                    classification=EmailClassification.UNKNOWN,
                    confidence=0.5,
                    method="llm_uncertain",
                    reason="LLM response unclear",
                )

        except Exception as e:
            return EmailClassifyResult(
                email=email,
                classification=EmailClassification.UNKNOWN,
                confidence=0.5,
                method="llm_error",
                reason=f"LLM error: {str(e)[:50]}",
            )

    def is_public(self, email: str) -> bool:
        """Quick check if email is likely public.

        Args:
            email: Email address to check

        Returns:
            True if email is classified as public
        """
        result = self.classify(email)
        return result.classification == EmailClassification.PUBLIC

    def is_private(self, email: str) -> bool:
        """Quick check if email is likely private/personal.

        Args:
            email: Email address to check

        Returns:
            True if email is classified as private
        """
        result = self.classify(email)
        return result.classification == EmailClassification.PRIVATE

    def get_confidence(self, email: str) -> float:
        """Get confidence score for email classification.

        Args:
            email: Email address to check

        Returns:
            Confidence score (0.0 to 1.0)
        """
        result = self.classify(email)
        return result.confidence

    def batch_classify(self, emails: list[str]) -> list[EmailClassifyResult]:
        """Classify multiple emails at once.

        Args:
            emails: List of email addresses

        Returns:
            List of classification results
        """
        return [self.classify(email) for email in emails]

    def filter_public(self, emails: list[str]) -> list[str]:
        """Filter out public emails from a list.

        Args:
            emails: List of email addresses

        Returns:
            List with public emails removed
        """
        return [e for e in emails if not self.is_public(e)]

    def filter_private(self, emails: list[str]) -> list[str]:
        """Keep only private emails from a list.

        Args:
            emails: List of email addresses

        Returns:
            List containing only private emails
        """
        return [e for e in emails if self.is_private(e)]


# Global classifier instance
_classifier_instance: Optional[EmailClassifier] = None


def get_classifier(use_llm: bool = False, llm_judge=None) -> EmailClassifier:
    """Get or create global email classifier instance.

    Args:
        use_llm: Whether to use LLM judge
        llm_judge: Optional LLM judge instance

    Returns:
        EmailClassifier instance
    """
    global _classifier_instance

    if _classifier_instance is None:
        _classifier_instance = EmailClassifier(use_llm=use_llm, llm_judge=llm_judge)

    return _classifier_instance


def reset_classifier() -> None:
    """Reset the global classifier instance."""
    global _classifier_instance
    _classifier_instance = None
