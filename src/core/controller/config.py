"""Scan configuration models."""

from typing import Literal, Optional

from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    """Configuration for a scan."""

    target_url: str = Field(
        ...,
        description="Target LLM API endpoint URL"
    )
    api_key: Optional[str] = Field(
        default=None,
        description="API key for authentication"
    )
    model: str = Field(
        default="gpt-3.5-turbo",
        description="Target model name"
    )

    # Local model settings
    llm_model_path: Optional[str] = Field(
        default=None,
        description="Path to local GGUF model for enhanced detection"
    )
    llm_n_ctx: int = Field(
        default=4096,
        description="Context window size for local model"
    )
    llm_n_threads: int = Field(
        default=8,
        description="Number of CPU threads for local model"
    )

    # Scan settings
    scan_mode: Literal["quick", "standard", "deep"] = Field(
        default="quick",
        description="Scan mode"
    )
    plugins: Optional[list[str]] = Field(
        default=None,
        description="List of plugin IDs to run (None = all)"
    )
    max_attacks_per_plugin: int = Field(
        default=10,
        description="Maximum attacks per plugin"
    )
    max_requests: int = Field(
        default=50,
        description="Maximum number of requests"
    )
    timeout: float = Field(
        default=30.0,
        description="Request timeout in seconds"
    )
    concurrency: int = Field(
        default=1,
        description="Number of concurrent requests"
    )

    # Output settings
    output_format: Literal["json", "html"] = Field(
        default="json",
        description="Output format"
    )
    output_path: Optional[str] = Field(
        default=None,
        description="Output file path"
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose output"
    )

    model_config = {"env_prefix": "SCAN_"}
