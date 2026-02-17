"""Data models for execution engine."""

from typing import Any, Optional

from pydantic import BaseModel, Field


class RequestConfig(BaseModel):
    """Configuration for HTTP requests."""

    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    retry_delay: float = Field(default=1.0, description="Delay between retries")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")


class RequestResult(BaseModel):
    """Result of an HTTP request."""

    success: bool
    status_code: Optional[int] = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    error: Optional[str] = None
    latency_ms: float = 0.0
    request_id: Optional[str] = None


class LLMRequest(BaseModel):
    """Request to an LLM API."""

    url: str
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any] = Field(default_factory=dict)
    api_key: Optional[str] = None

    def to_httpx_kwargs(self) -> dict[str, Any]:
        """Convert to httpx request kwargs."""
        headers = dict(self.headers)
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        return {
            "method": self.method,
            "url": self.url,
            "headers": headers,
            "json": self.body,
        }


class LLMResponse(BaseModel):
    """Response from an LLM API."""

    content: str
    model: Optional[str] = None
    usage: dict[str, int] = Field(default_factory=dict)
    raw_response: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_openai_format(cls, data: dict[str, Any]) -> "LLMResponse":
        """Parse OpenAI-compatible response format."""
        choices = data.get("choices", [])
        content = ""
        if choices:
            message = choices[0].get("message", {})
            content = message.get("content", "")

        return cls(
            content=content,
            model=data.get("model"),
            usage=data.get("usage", {}),
            raw_response=data,
        )
