"""State Manager - Orchestrates multi-turn attacks."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Iterator
import uuid

from src.core.state_engine.conversation import Conversation, ConversationBuilder
from src.core.state_engine.state import (
    AttackState,
    StateMachine,
    MultiTurnAttackStrategy,
)


@dataclass
class AttackSession:
    """Represents an active multi-turn attack session."""

    id: str
    conversation: Conversation
    state_machine: StateMachine
    strategy: Optional[MultiTurnAttackStrategy] = None
    created_at: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def current_turn(self) -> int:
        """Current turn number."""
        return self.conversation.turn_count // 2 + 1  # Each turn = user + assistant

    @property
    def is_complete(self) -> bool:
        """Check if session is complete."""
        return self.state_machine.is_terminal

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "conversation": self.conversation.to_dict(),
            "state": self.state_machine.to_dict(),
            "strategy": self.strategy.to_dict() if self.strategy else None,
            "current_turn": self.current_turn,
            "is_complete": self.is_complete,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }


class StateManager:
    """Manages multi-turn attack sessions.

    Provides high-level API for:
    - Creating and tracking attack sessions
    - Executing multi-turn attack sequences
    - Managing conversation state
    """

    def __init__(self, max_sessions: int = 100):
        """Initialize state manager.

        Args:
            max_sessions: Maximum concurrent sessions
        """
        self._sessions: dict[str, AttackSession] = {}
        self._max_sessions = max_sessions

    def create_session(
        self,
        strategy: Optional[MultiTurnAttackStrategy] = None,
        system_prompt: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> AttackSession:
        """Create a new attack session.

        Args:
            strategy: Optional attack strategy
            system_prompt: Optional system prompt
            metadata: Optional metadata

        Returns:
            New attack session
        """
        if len(self._sessions) >= self._max_sessions:
            # Remove oldest completed session
            self._cleanup_completed_sessions()

        session_id = str(uuid.uuid4())[:8]

        # Create conversation
        builder = ConversationBuilder(
            max_turns=strategy.max_turns * 2 if strategy else 20
        )
        if system_prompt:
            builder.with_system_prompt(system_prompt)
        conversation = builder.build()

        # Create state machine
        state_machine = StateMachine()

        session = AttackSession(
            id=session_id,
            conversation=conversation,
            state_machine=state_machine,
            strategy=strategy,
            metadata=metadata or {},
        )

        self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[AttackSession]:
        """Get session by ID.

        Args:
            session_id: Session ID

        Returns:
            Session or None
        """
        return self._sessions.get(session_id)

    def execute_turn(
        self,
        session_id: str,
        user_message: str,
        assistant_response: str,
        transition_state: Optional[AttackState] = None,
        reason: Optional[str] = None,
    ) -> bool:
        """Execute a conversation turn.

        Args:
            session_id: Session ID
            user_message: User attack message
            assistant_response: Target response
            transition_state: Optional state to transition to
            reason: Reason for state transition

        Returns:
            True if successful
        """
        session = self._sessions.get(session_id)
        if not session:
            return False

        # Add messages to conversation
        session.conversation.add_user_message(user_message)
        session.conversation.add_assistant_response(assistant_response)

        # Update state if specified
        if transition_state:
            session.state_machine.transition(transition_state, reason)

        return True

    def evaluate_response(
        self,
        session_id: str,
        response: str,
        success_patterns: Optional[list[str]] = None,
        failure_patterns: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Evaluate response against patterns.

        Args:
            session_id: Session ID
            response: Response to evaluate
            success_patterns: Patterns indicating success
            failure_patterns: Patterns indicating failure

        Returns:
            Evaluation result
        """
        import re

        session = self._sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        result = {
            "success": False,
            "matched_patterns": [],
            "state": session.state_machine.state.value,
        }

        # Check success patterns
        if success_patterns:
            for pattern in success_patterns:
                if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
                    result["matched_patterns"].append(("success", pattern))
                    result["success"] = True

        # Check failure patterns
        if failure_patterns:
            for pattern in failure_patterns:
                if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
                    result["matched_patterns"].append(("failure", pattern))
                    result["success"] = False

        return result

    def complete_session(
        self,
        session_id: str,
        success: bool,
        reason: Optional[str] = None,
    ) -> bool:
        """Mark session as complete.

        Args:
            session_id: Session ID
            success: Whether attack succeeded
            reason: Reason for completion

        Returns:
            True if successful
        """
        session = self._sessions.get(session_id)
        if not session:
            return False

        target_state = AttackState.COMPLETED if success else AttackState.FAILED
        session.state_machine.transition(target_state, reason)
        return True

    def list_active_sessions(self) -> list[AttackSession]:
        """List all active (non-terminal) sessions.

        Returns:
            List of active sessions
        """
        return [s for s in self._sessions.values() if not s.is_complete]

    def list_all_sessions(self) -> list[AttackSession]:
        """List all sessions.

        Returns:
            List of all sessions
        """
        return list(self._sessions.values())

    def delete_session(self, session_id: str) -> bool:
        """Delete a session.

        Args:
            session_id: Session ID

        Returns:
            True if deleted
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def _cleanup_completed_sessions(self) -> int:
        """Remove completed sessions to make room.

        Returns:
            Number of sessions removed
        """
        to_remove = [
            sid for sid, session in self._sessions.items()
            if session.is_complete
        ]
        for sid in to_remove:
            del self._sessions[sid]
        return len(to_remove)

    def create_delayed_attack_strategy(
        self,
        initial_context: str,
        attack_payload: str,
        trigger_phrase: str = "now",
        max_turns: int = 5,
    ) -> MultiTurnAttackStrategy:
        """Create a delayed/latent attack strategy.

        This creates a multi-turn attack where:
        1. First turns build context/trust
        2. Attack payload is delivered later
        3. Trigger phrase activates the attack

        Args:
            initial_context: Context building message
            attack_payload: Actual attack payload
            trigger_phrase: Phrase that triggers attack
            max_turns: Maximum turns

        Returns:
            Configured strategy
        """
        strategy = MultiTurnAttackStrategy(
            name="delayed_attack",
            description="Build context before delivering attack",
            max_turns=max_turns,
        )

        # Turn 1: Build rapport
        strategy.add_turn_plan(
            turn_number=1,
            payload_template=initial_context,
            expected_state=AttackState.ENGAGING,
            success_indicators=["help", "assist", "sure", "of course"],
        )

        # Turn 2-4: Continue engagement
        for turn in range(2, max_turns):
            strategy.add_turn_plan(
                turn_number=turn,
                payload_template=f"Thank you. {trigger_phrase}, {attack_payload}" if turn == max_turns - 1 else "Can you help me understand more?",
                expected_state=AttackState.ATTACKING if turn == max_turns - 1 else AttackState.ENGAGING,
            )

        return strategy

    def create_progressive_attack_strategy(
        self,
        initial_probe: str,
        escalation_payloads: list[str],
        max_turns: int = 5,
    ) -> MultiTurnAttackStrategy:
        """Create a progressive escalation strategy.

        Gradually increases attack intensity.

        Args:
            initial_probe: Initial probing message
            escalation_payloads: Escalating attack payloads
            max_turns: Maximum turns

        Returns:
            Configured strategy
        """
        strategy = MultiTurnAttackStrategy(
            name="progressive_escalation",
            description="Gradually increase attack intensity",
            max_turns=max_turns,
        )

        # Turn 1: Initial probe
        strategy.add_turn_plan(
            turn_number=1,
            payload_template=initial_probe,
            expected_state=AttackState.PROBING,
        )

        # Subsequent turns: Escalation
        for i, payload in enumerate(escalation_payloads[:max_turns - 1]):
            strategy.add_turn_plan(
                turn_number=i + 2,
                payload_template=payload,
                expected_state=AttackState.ESCALATING,
            )

        return strategy


# Global instance for convenience
_manager_instance: Optional[StateManager] = None


def get_state_manager() -> StateManager:
    """Get global state manager instance."""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = StateManager()
    return _manager_instance


def reset_state_manager() -> None:
    """Reset global state manager."""
    global _manager_instance
    _manager_instance = None
