"""Execution context for tracking scan state and progress."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    """Status of a scan execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ExecutionPhase(str, Enum):
    """Phases of attack execution."""

    INITIALIZATION = "initialization"
    ATTACK_GENERATION = "attack_generation"
    REQUEST_EXECUTION = "request_execution"
    DETECTION = "detection"
    VALIDATION = "validation"
    REPORTING = "reporting"


@dataclass
class ExecutionContext:
    """Context for a single scan execution.

    Tracks the state, progress, and results of a vulnerability scan.
    """

    # Identification
    scan_id: str = field(default_factory=lambda: str(uuid4())[:8])
    target_url: str = ""

    # Configuration
    plugin_ids: list[str] = field(default_factory=list)
    scan_mode: str = "quick"  # quick, standard, deep
    max_attacks_per_plugin: int = 100

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # State
    status: ScanStatus = ScanStatus.PENDING
    current_phase: ExecutionPhase = ExecutionPhase.INITIALIZATION
    current_plugin: Optional[str] = None
    current_attack: int = 0

    # Progress tracking
    total_attacks: int = 0
    executed_attacks: int = 0
    successful_attacks: int = 0
    vulnerabilities_found: int = 0

    # Error tracking
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def start(self) -> None:
        """Mark the scan as started."""
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.now()
        self.current_phase = ExecutionPhase.ATTACK_GENERATION

    def complete(self) -> None:
        """Mark the scan as completed."""
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.now()
        self.current_phase = ExecutionPhase.REPORTING

    def fail(self, error: str) -> None:
        """Mark the scan as failed."""
        self.status = ScanStatus.FAILED
        self.completed_at = datetime.now()
        self.errors.append(error)

    def cancel(self) -> None:
        """Mark the scan as cancelled."""
        self.status = ScanStatus.CANCELLED
        self.completed_at = datetime.now()

    def set_phase(self, phase: ExecutionPhase) -> None:
        """Set the current execution phase."""
        self.current_phase = phase

    def set_plugin(self, plugin_id: Optional[str]) -> None:
        """Set the currently executing plugin."""
        self.current_plugin = plugin_id
        self.current_attack = 0

    def increment_attack(self, success: bool = False, vulnerability: bool = False) -> None:
        """Increment attack counters."""
        self.executed_attacks += 1
        self.current_attack += 1
        if success:
            self.successful_attacks += 1
        if vulnerability:
            self.vulnerabilities_found += 1

    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)

    def add_warning(self, warning: str) -> None:
        """Add a warning message."""
        self.warnings.append(warning)

    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate scan duration in seconds."""
        if not self.started_at:
            return None
        end = self.completed_at or datetime.now()
        return (end - self.started_at).total_seconds()

    @property
    def progress_percent(self) -> float:
        """Calculate progress percentage."""
        if self.total_attacks == 0:
            return 0.0
        return (self.executed_attacks / self.total_attacks) * 100

    @property
    def success_rate(self) -> float:
        """Calculate attack success rate."""
        if self.executed_attacks == 0:
            return 0.0
        return self.successful_attacks / self.executed_attacks

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary."""
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "status": self.status.value,
            "current_phase": self.current_phase.value,
            "current_plugin": self.current_plugin,
            "total_attacks": self.total_attacks,
            "executed_attacks": self.executed_attacks,
            "successful_attacks": self.successful_attacks,
            "vulnerabilities_found": self.vulnerabilities_found,
            "progress_percent": round(self.progress_percent, 2),
            "success_rate": round(self.success_rate, 2),
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class AttackExecutionRecord(BaseModel):
    """Record of a single attack execution."""

    # Identification
    attack_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    plugin_id: str = ""
    template_id: str = ""

    # Attack details
    payload: str = ""
    category: str = ""

    # Request/Response
    request_url: str = ""
    request_method: str = "POST"
    response_status: Optional[int] = None
    response_body: Optional[str] = None
    response_latency_ms: float = 0.0

    # Detection results
    detected: bool = False
    confidence: float = 0.0
    severity: str = "low"
    validated: bool = False

    # Evidence
    evidence: dict[str, Any] = Field(default_factory=dict)

    # Error handling
    error: Optional[str] = None

    # Timing
    executed_at: datetime = Field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert record to dictionary."""
        return {
            "attack_id": self.attack_id,
            "plugin_id": self.plugin_id,
            "template_id": self.template_id,
            "category": self.category,
            "detected": self.detected,
            "confidence": self.confidence,
            "severity": self.severity,
            "validated": self.validated,
            "response_status": self.response_status,
            "response_latency_ms": self.response_latency_ms,
            "error": self.error,
        }
