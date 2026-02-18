"""Base plugin interface for OWASP LLM risk modules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator, Optional

from pydantic import BaseModel, Field

from src.core.attack_engine import (
    AttackCategory,
    AttackGenerator,
    AttackSeverity,
    GeneratedAttack,
)


class PluginPriority(str, Enum):
    """Plugin execution priority."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class PluginStatus(str, Enum):
    """Plugin status."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class PluginInfo:
    """Plugin metadata information."""

    id: str
    name: str
    category: AttackCategory
    description: str = ""
    version: str = "1.0.0"
    author: str = ""
    priority: PluginPriority = PluginPriority.NORMAL
    tags: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


class PluginConfig(BaseModel):
    """Configuration for a plugin."""

    enabled: bool = Field(default=True, description="Whether plugin is enabled")
    max_attacks: int = Field(default=100, description="Maximum attacks to generate")
    timeout_seconds: float = Field(default=30.0, description="Timeout for plugin execution")
    confidence_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Minimum confidence to report vulnerability (0.0-1.0)"
    )
    use_llm_judge: bool = Field(
        default=False,
        description="Use LLM judge for secondary validation"
    )
    severity_override: Optional[AttackSeverity] = Field(
        default=None, description="Override default severity"
    )
    custom_settings: dict[str, Any] = Field(
        default_factory=dict, description="Plugin-specific settings"
    )


class AttackContext(BaseModel):
    """Context for attack execution."""

    conversation_history: list[dict[str, str]] = Field(
        default_factory=list,
        description="Previous conversation messages"
    )
    turn_number: int = Field(default=1, description="Current turn in conversation")
    previous_success: bool = Field(default=False, description="Whether previous attack succeeded")
    target_info: dict[str, Any] = Field(
        default_factory=dict,
        description="Information about the target"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context metadata"
    )


class AttackResult(BaseModel):
    """Result of executing a single attack."""

    attack: GeneratedAttack = Field(..., description="The attack that was executed")
    success: bool = Field(..., description="Whether the attack succeeded")
    response: Optional[str] = Field(default=None, description="Target response")
    detected: bool = Field(default=False, description="Whether vulnerability was detected")
    confidence: float = Field(default=0.0, description="Detection confidence (0-1)")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Evidence of vulnerability")
    error: Optional[str] = Field(default=None, description="Error message if any")


class ScanResult(BaseModel):
    """Result of a complete plugin scan."""

    plugin_id: str = Field(..., description="Plugin identifier")
    category: AttackCategory = Field(..., description="OWASP LLM category")
    total_attacks: int = Field(default=0, description="Total attacks executed")
    successful_attacks: int = Field(default=0, description="Successful attacks count")
    vulnerabilities_found: int = Field(default=0, description="Vulnerabilities found")
    results: list[AttackResult] = Field(default_factory=list, description="Individual results")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    @property
    def success_rate(self) -> float:
        """Calculate attack success rate."""
        if self.total_attacks == 0:
            return 0.0
        return self.successful_attacks / self.total_attacks


class BasePlugin(ABC):
    """Abstract base class for all OWASP LLM risk plugins."""

    # Plugin metadata (to be overridden by subclasses)
    info: PluginInfo

    def __init__(self, config: Optional[PluginConfig] = None):
        """Initialize the plugin.

        Args:
            config: Plugin configuration. Uses defaults if not provided.
        """
        self.config = config or PluginConfig()
        self._generator: Optional[AttackGenerator] = None
        self._status = PluginStatus.ENABLED if self.config.enabled else PluginStatus.DISABLED

    @property
    def id(self) -> str:
        """Get plugin ID."""
        return self.info.id

    @property
    def name(self) -> str:
        """Get plugin name."""
        return self.info.name

    @property
    def category(self) -> AttackCategory:
        """Get OWASP LLM category."""
        return self.info.category

    @property
    def status(self) -> PluginStatus:
        """Get plugin status."""
        return self._status

    def enable(self) -> None:
        """Enable the plugin."""
        self.config.enabled = True
        self._status = PluginStatus.ENABLED

    def disable(self) -> None:
        """Disable the plugin."""
        self.config.enabled = False
        self._status = PluginStatus.DISABLED

    def set_error(self, error_message: str) -> None:
        """Set plugin to error state."""
        self._status = PluginStatus.ERROR

    @abstractmethod
    def generate_attacks(
        self,
        context: Optional[AttackContext] = None,
    ) -> Iterator[GeneratedAttack]:
        """Generate attacks for this plugin.

        Args:
            context: Optional attack context for multi-turn attacks.

        Yields:
            GeneratedAttack instances ready for execution.
        """
        pass

    @abstractmethod
    def detect_vulnerability(
        self,
        attack: GeneratedAttack,
        response: str,
        context: Optional[AttackContext] = None,
    ) -> AttackResult:
        """Detect if vulnerability exists in the response.

        Args:
            attack: The attack that was executed.
            response: Target response to analyze.
            context: Optional attack context.

        Returns:
            AttackResult with detection information.
        """
        pass

    def validate_vulnerability(
        self,
        result: AttackResult,
        context: Optional[AttackContext] = None,
    ) -> bool:
        """Validate that the detected vulnerability is real.

        This method can be overridden to implement replay validation.

        Args:
            result: The attack result to validate.
            context: Optional attack context.

        Returns:
            True if vulnerability is validated, False otherwise.
        """
        # Default implementation - trust the detection
        return result.detected and result.confidence >= 0.7

    def calculate_severity(
        self,
        result: AttackResult,
        context: Optional[AttackContext] = None,
    ) -> AttackSeverity:
        """Calculate severity for a detected vulnerability.

        Args:
            result: The attack result.
            context: Optional attack context.

        Returns:
            Calculated severity level.
        """
        if self.config.severity_override:
            return self.config.severity_override

        # Default severity based on confidence
        if result.confidence >= 0.9:
            return AttackSeverity.CRITICAL
        elif result.confidence >= 0.7:
            return AttackSeverity.HIGH
        elif result.confidence >= 0.5:
            return AttackSeverity.MEDIUM
        return AttackSeverity.LOW

    def on_attack_success(
        self,
        result: AttackResult,
        context: Optional[AttackContext] = None,
    ) -> None:
        """Hook called when an attack succeeds.

        Override this to implement adaptive attack strategies.

        Args:
            result: The successful attack result.
            context: Optional attack context.
        """
        pass

    def on_attack_failure(
        self,
        result: AttackResult,
        context: Optional[AttackContext] = None,
    ) -> None:
        """Hook called when an attack fails.

        Override this to implement fallback strategies.

        Args:
            result: The failed attack result.
            context: Optional attack context.
        """
        pass

    def get_template_ids(self) -> list[str]:
        """Get template IDs used by this plugin.

        Override this to specify which attack templates to use.

        Returns:
            List of template IDs.
        """
        return []

    def _get_generator(self) -> AttackGenerator:
        """Get or create attack generator.

        Returns:
            AttackGenerator instance.
        """
        if self._generator is None:
            self._generator = AttackGenerator()
        return self._generator

    def __repr__(self) -> str:
        """String representation of the plugin."""
        return f"<{self.__class__.__name__} id={self.id} status={self.status.value}>"
