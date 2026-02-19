"""Conversation management for multi-turn attacks."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import uuid


class ConversationRole(str, Enum):
    """Role in conversation."""

    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


@dataclass
class ConversationTurn:
    """Single turn in a conversation."""

    role: ConversationRole
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_message(self) -> dict[str, str]:
        """Convert to API message format."""
        return {"role": self.role.value, "content": self.content}

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "role": self.role.value,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class Conversation:
    """Multi-turn conversation with attack context.

    Manages conversation history and provides utilities for
    building multi-turn attack scenarios.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    turns: list[ConversationTurn] = field(default_factory=list)
    max_turns: int = 20
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def turn_count(self) -> int:
        """Number of turns in conversation."""
        return len(self.turns)

    @property
    def last_turn(self) -> Optional[ConversationTurn]:
        """Get the last turn."""
        return self.turns[-1] if self.turns else None

    @property
    def last_response(self) -> Optional[str]:
        """Get the last assistant response."""
        for turn in reversed(self.turns):
            if turn.role == ConversationRole.ASSISTANT:
                return turn.content
        return None

    def add_user_message(self, content: str, metadata: Optional[dict] = None) -> ConversationTurn:
        """Add a user message.

        Args:
            content: Message content
            metadata: Optional metadata

        Returns:
            The created turn
        """
        if self.turn_count >= self.max_turns:
            raise ValueError(f"Conversation exceeded max turns ({self.max_turns})")

        turn = ConversationTurn(
            role=ConversationRole.USER,
            content=content,
            metadata=metadata or {},
        )
        self.turns.append(turn)
        return turn

    def add_assistant_response(self, content: str, metadata: Optional[dict] = None) -> ConversationTurn:
        """Add an assistant response.

        Args:
            content: Response content
            metadata: Optional metadata

        Returns:
            The created turn
        """
        turn = ConversationTurn(
            role=ConversationRole.ASSISTANT,
            content=content,
            metadata=metadata or {},
        )
        self.turns.append(turn)
        return turn

    def add_system_message(self, content: str, metadata: Optional[dict] = None) -> ConversationTurn:
        """Add a system message.

        Args:
            content: Message content
            metadata: Optional metadata

        Returns:
            The created turn
        """
        turn = ConversationTurn(
            role=ConversationRole.SYSTEM,
            content=content,
            metadata=metadata or {},
        )
        self.turns.append(turn)
        return turn

    def get_messages(self, include_system: bool = False) -> list[dict[str, str]]:
        """Get all messages in API format.

        Args:
            include_system: Whether to include system messages

        Returns:
            List of message dicts
        """
        messages = []
        for turn in self.turns:
            if turn.role == ConversationRole.SYSTEM and not include_system:
                continue
            messages.append(turn.to_message())
        return messages

    def get_context_window(self, last_n: int = 10) -> list[dict[str, str]]:
        """Get the last N turns as context.

        Args:
            last_n: Number of recent turns to include

        Returns:
            List of message dicts
        """
        recent_turns = self.turns[-last_n:] if len(self.turns) > last_n else self.turns
        return [t.to_message() for t in recent_turns if t.role != ConversationRole.SYSTEM]

    def clear(self) -> None:
        """Clear the conversation history."""
        self.turns.clear()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "turns": [t.to_dict() for t in self.turns],
            "turn_count": self.turn_count,
            "max_turns": self.max_turns,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Conversation":
        """Create from dictionary."""
        conv = cls(
            id=data.get("id", str(uuid.uuid4())[:8]),
            max_turns=data.get("max_turns", 20),
            metadata=data.get("metadata", {}),
        )

        for turn_data in data.get("turns", []):
            turn = ConversationTurn(
                role=ConversationRole(turn_data["role"]),
                content=turn_data["content"],
                timestamp=datetime.fromisoformat(turn_data["timestamp"]) if "timestamp" in turn_data else datetime.now(),
                metadata=turn_data.get("metadata", {}),
            )
            conv.turns.append(turn)

        return conv


class ConversationBuilder:
    """Builder for creating attack conversations."""

    def __init__(self, max_turns: int = 20):
        """Initialize builder.

        Args:
            max_turns: Maximum turns allowed
        """
        self.conversation = Conversation(max_turns=max_turns)

    def with_system_prompt(self, prompt: str) -> "ConversationBuilder":
        """Add system prompt.

        Args:
            prompt: System prompt content

        Returns:
            Self for chaining
        """
        self.conversation.add_system_message(prompt)
        return self

    def with_user_message(self, content: str, metadata: Optional[dict] = None) -> "ConversationBuilder":
        """Add user message.

        Args:
            content: Message content
            metadata: Optional metadata

        Returns:
            Self for chaining
        """
        self.conversation.add_user_message(content, metadata)
        return self

    def with_assistant_response(self, content: str, metadata: Optional[dict] = None) -> "ConversationBuilder":
        """Add assistant response.

        Args:
            content: Response content
            metadata: Optional metadata

        Returns:
            Self for chaining
        """
        self.conversation.add_assistant_response(content, metadata)
        return self

    def build(self) -> Conversation:
        """Build the conversation.

        Returns:
            The built conversation
        """
        return self.conversation
