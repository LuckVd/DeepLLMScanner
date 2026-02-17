"""Data models for the attack engine."""

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AttackCategory(str, Enum):
    """OWASP LLM Top 10 attack categories."""

    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_DATA_LEAK = "LLM02"
    LLM03_SUPPLY_CHAIN = "LLM03"
    LLM04_DATA_POISONING = "LLM04"
    LLM05_IMPROPER_OUTPUT = "LLM05"
    LLM06_EXCESSIVE_AGENCY = "LLM06"
    LLM07_SYSTEM_PROMPT_LEAK = "LLM07"
    LLM08_VECTOR_DB_POISONING = "LLM08"
    LLM09_MISINFORMATION = "LLM09"
    LLM10_UNLIMITED_INPUT = "LLM10"

    @property
    def description(self) -> str:
        """Get category description."""
        descriptions = {
            AttackCategory.LLM01_PROMPT_INJECTION: "Prompt Injection",
            AttackCategory.LLM02_DATA_LEAK: "Sensitive Information Disclosure",
            AttackCategory.LLM03_SUPPLY_CHAIN: "Supply Chain Vulnerabilities",
            AttackCategory.LLM04_DATA_POISONING: "Data and Model Poisoning",
            AttackCategory.LLM05_IMPROPER_OUTPUT: "Improper Output Handling",
            AttackCategory.LLM06_EXCESSIVE_AGENCY: "Excessive Agency",
            AttackCategory.LLM07_SYSTEM_PROMPT_LEAK: "System Prompt Leakage",
            AttackCategory.LLM08_VECTOR_DB_POISONING: "Vector and Embedding Weaknesses",
            AttackCategory.LLM09_MISINFORMATION: "Misinformation",
            AttackCategory.LLM10_UNLIMITED_INPUT: "Unlimited Consumption",
        }
        return descriptions.get(self, "Unknown")


class AttackSeverity(str, Enum):
    """Attack severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackPayload(BaseModel):
    """A single attack payload with metadata."""

    id: str = Field(..., description="Unique payload identifier")
    content: str = Field(..., description="The actual attack payload text")
    name: str = Field(..., description="Human-readable payload name")
    category: AttackCategory = Field(..., description="OWASP LLM category")
    severity: AttackSeverity = Field(default=AttackSeverity.MEDIUM, description="Severity level")
    description: Optional[str] = Field(default=None, description="Payload description")
    tags: list[str] = Field(default_factory=list, description="Tags for classification")
    variables: dict[str, str] = Field(default_factory=dict, description="Variables to substitute")
    source: Optional[str] = Field(default=None, description="Source of the payload")
    references: list[str] = Field(default_factory=list, description="Reference URLs")


class AttackTemplate(BaseModel):
    """A template for generating attack payloads."""

    id: str = Field(..., description="Template identifier")
    name: str = Field(..., description="Template name")
    category: AttackCategory = Field(..., description="OWASP LLM category")
    description: str = Field(default="", description="Template description")
    severity: AttackSeverity = Field(default=AttackSeverity.MEDIUM, description="Default severity")
    tags: list[str] = Field(default_factory=list, description="Classification tags")

    # Template content with optional variables like {{variable}}
    templates: list[str] = Field(..., description="List of template strings")
    variables: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Variable definitions with possible values"
    )

    # Metadata
    source: Optional[str] = Field(default=None, description="Original source")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    author: Optional[str] = Field(default=None, description="Template author")
    version: str = Field(default="1.0", description="Template version")

    def get_variable_defaults(self) -> dict[str, str]:
        """Get default values for all variables."""
        return {k: v[0] if v else "" for k, v in self.variables.items()}


class GeneratedAttack(BaseModel):
    """A generated attack ready to be sent to the target."""

    id: str = Field(..., description="Generated attack ID")
    payload: str = Field(..., description="The final attack payload")
    template_id: str = Field(..., description="Source template ID")
    template_name: str = Field(..., description="Source template name")
    category: AttackCategory = Field(..., description="OWASP LLM category")
    severity: AttackSeverity = Field(..., description="Attack severity")
    tags: list[str] = Field(default_factory=list, description="Classification tags")
    variables_used: dict[str, str] = Field(
        default_factory=dict,
        description="Variables and their values used"
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class AttackResult(BaseModel):
    """Result of executing an attack against a target."""

    attack: GeneratedAttack = Field(..., description="The attack that was executed")
    success: bool = Field(..., description="Whether the attack succeeded")
    response: Optional[str] = Field(default=None, description="Target response")
    detected: bool = Field(default=False, description="Whether vulnerability was detected")
    confidence: float = Field(default=0.0, description="Confidence score 0-1")
    latency_ms: float = Field(default=0.0, description="Request latency")
    error: Optional[str] = Field(default=None, description="Error message if any")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Evidence of vulnerability")
