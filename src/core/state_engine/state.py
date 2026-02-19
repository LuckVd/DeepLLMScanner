"""State machine for multi-turn attack orchestration."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional


class AttackState(str, Enum):
    """States in the attack lifecycle."""

    # Initial states
    IDLE = "idle"                    # Waiting to start
    INITIALIZING = "initializing"    # Setting up attack

    # Active attack states
    ENGAGING = "engaging"            # Building rapport/context
    ATTACKING = "attacking"          # Executing attack payload
    PROBING = "probing"              # Testing for vulnerabilities
    ESCALATING = "escalating"        # Increasing attack intensity

    # Completion states
    VALIDATING = "validating"        # Confirming vulnerability
    COMPLETED = "completed"          # Attack finished
    FAILED = "failed"               # Attack failed

    # Special states
    PAUSED = "paused"               # Attack paused
    DETECTED = "detected"           # Attack detected by target


class StateTransition:
    """Defines a valid state transition."""

    def __init__(
        self,
        from_state: AttackState,
        to_state: AttackState,
        condition: Optional[Callable[[], bool]] = None,
        action: Optional[Callable[[], None]] = None,
    ):
        """Initialize transition.

        Args:
            from_state: Source state
            to_state: Target state
            condition: Optional condition function
            action: Optional action to execute on transition
        """
        self.from_state = from_state
        self.to_state = to_state
        self.condition = condition
        self.action = action


@dataclass
class StateHistory:
    """Record of state changes."""

    from_state: AttackState
    to_state: AttackState
    timestamp: datetime
    reason: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class StateMachine:
    """State machine for orchestrating multi-turn attacks.

    Manages attack lifecycle with configurable transitions
    and hooks for custom behavior.
    """

    # Default valid transitions
    DEFAULT_TRANSITIONS = {
        AttackState.IDLE: [AttackState.INITIALIZING],
        AttackState.INITIALIZING: [AttackState.ENGAGING, AttackState.ATTACKING, AttackState.FAILED],
        AttackState.ENGAGING: [AttackState.ATTACKING, AttackState.PROBING, AttackState.PAUSED],
        AttackState.ATTACKING: [AttackState.PROBING, AttackState.ESCALATING, AttackState.VALIDATING, AttackState.COMPLETED, AttackState.DETECTED, AttackState.FAILED],
        AttackState.PROBING: [AttackState.ATTACKING, AttackState.ESCALATING, AttackState.VALIDATING, AttackState.COMPLETED, AttackState.FAILED],
        AttackState.ESCALATING: [AttackState.VALIDATING, AttackState.COMPLETED, AttackState.DETECTED, AttackState.FAILED],
        AttackState.VALIDATING: [AttackState.COMPLETED, AttackState.FAILED, AttackState.ATTACKING],
        AttackState.PAUSED: [AttackState.ENGAGING, AttackState.ATTACKING, AttackState.FAILED],
        AttackState.DETECTED: [AttackState.ENGAGING, AttackState.FAILED, AttackState.COMPLETED],
        AttackState.COMPLETED: [AttackState.IDLE],
        AttackState.FAILED: [AttackState.IDLE],
    }

    def __init__(
        self,
        initial_state: AttackState = AttackState.IDLE,
        custom_transitions: Optional[dict[AttackState, list[AttackState]]] = None,
    ):
        """Initialize state machine.

        Args:
            initial_state: Starting state
            custom_transitions: Override default transitions
        """
        self._state = initial_state
        self._transitions = custom_transitions or self.DEFAULT_TRANSITIONS.copy()
        self._history: list[StateHistory] = []
        self._on_state_change: Optional[Callable[[AttackState, AttackState], None]] = None
        self._metadata: dict[str, Any] = {}

    @property
    def state(self) -> AttackState:
        """Current state."""
        return self._state

    @property
    def history(self) -> list[StateHistory]:
        """State change history."""
        return self._history.copy()

    @property
    def is_terminal(self) -> bool:
        """Check if in terminal state."""
        return self._state in (AttackState.COMPLETED, AttackState.FAILED)

    @property
    def is_active(self) -> bool:
        """Check if attack is active."""
        return self._state in (
            AttackState.INITIALIZING,
            AttackState.ENGAGING,
            AttackState.ATTACKING,
            AttackState.PROBING,
            AttackState.ESCALATING,
            AttackState.VALIDATING,
        )

    def can_transition_to(self, target: AttackState) -> bool:
        """Check if transition is valid.

        Args:
            target: Target state

        Returns:
            True if transition is allowed
        """
        valid_targets = self._transitions.get(self._state, [])
        return target in valid_targets

    def transition(
        self,
        target: AttackState,
        reason: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> bool:
        """Transition to new state.

        Args:
            target: Target state
            reason: Reason for transition
            metadata: Additional metadata

        Returns:
            True if transition succeeded
        """
        if not self.can_transition_to(target):
            return False

        old_state = self._state
        self._state = target

        # Record history
        self._history.append(StateHistory(
            from_state=old_state,
            to_state=target,
            timestamp=datetime.now(),
            reason=reason,
            metadata=metadata or {},
        ))

        # Call hook if set
        if self._on_state_change:
            self._on_state_change(old_state, target)

        return True

    def force_state(self, state: AttackState, reason: Optional[str] = None) -> None:
        """Force state change without validation.

        Args:
            state: Target state
            reason: Reason for forced change
        """
        old_state = self._state
        self._state = state

        self._history.append(StateHistory(
            from_state=old_state,
            to_state=state,
            timestamp=datetime.now(),
            reason=f"FORCED: {reason}",
        ))

    def reset(self) -> None:
        """Reset to initial state."""
        self._state = AttackState.IDLE
        self._history.clear()
        self._metadata.clear()

    def set_on_state_change(self, callback: Callable[[AttackState, AttackState], None]) -> None:
        """Set callback for state changes.

        Args:
            callback: Function(old_state, new_state)
        """
        self._on_state_change = callback

    def get_valid_transitions(self) -> list[AttackState]:
        """Get list of valid target states.

        Returns:
            List of states that can be transitioned to
        """
        return self._transitions.get(self._state, [])

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "state": self._state.value,
            "is_terminal": self.is_terminal,
            "is_active": self.is_active,
            "valid_transitions": [s.value for s in self.get_valid_transitions()],
            "history": [
                {
                    "from": h.from_state.value,
                    "to": h.to_state.value,
                    "timestamp": h.timestamp.isoformat(),
                    "reason": h.reason,
                }
                for h in self._history
            ],
        }


class MultiTurnAttackStrategy:
    """Defines a multi-turn attack strategy."""

    def __init__(
        self,
        name: str,
        description: str = "",
        max_turns: int = 5,
    ):
        """Initialize strategy.

        Args:
            name: Strategy name
            description: Strategy description
            max_turns: Maximum turns for this strategy
        """
        self.name = name
        self.description = description
        self.max_turns = max_turns
        self._turn_plans: list[dict[str, Any]] = []

    def add_turn_plan(
        self,
        turn_number: int,
        payload_template: str,
        expected_state: AttackState = AttackState.ATTACKING,
        success_indicators: Optional[list[str]] = None,
        failure_indicators: Optional[list[str]] = None,
    ) -> "MultiTurnAttackStrategy":
        """Add a plan for a specific turn.

        Args:
            turn_number: Turn number (1-indexed)
            payload_template: Template for payload
            expected_state: Expected state after this turn
            success_indicators: Patterns indicating success
            failure_indicators: Patterns indicating failure

        Returns:
            Self for chaining
        """
        self._turn_plans.append({
            "turn": turn_number,
            "payload_template": payload_template,
            "expected_state": expected_state,
            "success_indicators": success_indicators or [],
            "failure_indicators": failure_indicators or [],
        })
        return self

    def get_turn_plan(self, turn_number: int) -> Optional[dict[str, Any]]:
        """Get plan for a specific turn.

        Args:
            turn_number: Turn number

        Returns:
            Turn plan or None
        """
        for plan in self._turn_plans:
            if plan["turn"] == turn_number:
                return plan
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "max_turns": self.max_turns,
            "turn_plans": self._turn_plans,
        }
