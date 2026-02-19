"""Base classes for report generation."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class RiskLevel(str, Enum):
    """Risk level enumeration."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class VulnerabilityRecord:
    """Single vulnerability record for reporting."""

    id: str
    plugin_id: str
    category: str
    payload: str
    response: str
    confidence: float
    evidence: dict[str, Any]
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    priority: Optional[str] = None
    detected_at: Optional[str] = None
    validation_passed: Optional[bool] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "plugin_id": self.plugin_id,
            "category": self.category,
            "payload": self.payload,
            "response": self.response,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "priority": self.priority,
            "detected_at": self.detected_at,
            "validation_passed": self.validation_passed,
        }


@dataclass
class PluginSummary:
    """Summary for a single plugin."""

    plugin_id: str
    category: str
    total_attacks: int
    vulnerabilities_found: int
    success_rate: float
    risk_summary: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "plugin_id": self.plugin_id,
            "category": self.category,
            "total_attacks": self.total_attacks,
            "vulnerabilities_found": self.vulnerabilities_found,
            "success_rate": self.success_rate,
            "risk_summary": self.risk_summary,
        }


@dataclass
class ReportData:
    """Complete scan report data."""

    scan_id: str
    target_url: str
    model: str
    scan_mode: str
    start_time: datetime
    end_time: datetime
    vulnerabilities: list[VulnerabilityRecord] = field(default_factory=list)
    plugin_summaries: list[PluginSummary] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    local_llm: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        """Calculate scan duration in seconds."""
        return (self.end_time - self.start_time).total_seconds()

    @property
    def total_attacks(self) -> int:
        """Total number of attacks executed."""
        return sum(p.total_attacks for p in self.plugin_summaries)

    @property
    def total_vulnerabilities(self) -> int:
        """Total number of vulnerabilities found."""
        return len(self.vulnerabilities)

    @property
    def success_rate(self) -> float:
        """Overall success rate (vulnerabilities / attacks)."""
        if self.total_attacks == 0:
            return 0.0
        return self.total_vulnerabilities / self.total_attacks

    @property
    def risk_distribution(self) -> dict[str, int]:
        """Distribution of vulnerabilities by risk level."""
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in self.vulnerabilities:
            level = vuln.risk_level or "info"
            if level in distribution:
                distribution[level] += 1
        return distribution

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "model": self.model,
            "scan_mode": self.scan_mode,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration_seconds,
            "config": self.config,
            "local_llm": self.local_llm,
            "summary": {
                "total_attacks": self.total_attacks,
                "vulnerabilities_found": self.total_vulnerabilities,
                "success_rate": round(self.success_rate, 2),
                "risk_distribution": self.risk_distribution,
            },
            "plugins": [p.to_dict() for p in self.plugin_summaries],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


class BaseReporter(ABC):
    """Abstract base class for report generators."""

    def __init__(self, template_dir: Optional[str] = None):
        """Initialize reporter.

        Args:
            template_dir: Directory containing templates (for HTML reporter)
        """
        self.template_dir = template_dir

    @abstractmethod
    def generate(self, data: ReportData, output_path: str) -> bool:
        """Generate report from scan data.

        Args:
            data: Report data containing scan results
            output_path: Path to write the report

        Returns:
            True if report was generated successfully
        """
        pass

    @abstractmethod
    def generate_to_string(self, data: ReportData) -> str:
        """Generate report as string.

        Args:
            data: Report data containing scan results

        Returns:
            Report content as string
        """
        pass

    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"

    def _format_timestamp(self, dt: datetime) -> str:
        """Format timestamp for display."""
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    def _truncate_text(self, text: str, max_length: int = 200) -> str:
        """Truncate text with ellipsis."""
        if len(text) <= max_length:
            return text
        return text[:max_length - 3] + "..."
