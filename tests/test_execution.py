"""Tests for Execution Engine."""

import pytest


class TestExecutionClient:
    """Tests for ExecutionClient."""

    def test_config_defaults(self):
        """Test default configuration values."""
        from src.core.execution_engine.models import RequestConfig

        config = RequestConfig()
        assert config.timeout == 30.0
        assert config.max_retries == 3

    def test_stats_initial(self):
        """Test initial statistics."""
        from src.core.execution_engine import ExecutionClient

        client = ExecutionClient()
        stats = client.get_stats()

        assert stats["total_requests"] == 0
        assert stats["successful_requests"] == 0
        assert stats["failed_requests"] == 0

        client.close()

    def test_context_manager(self):
        """Test context manager usage."""
        from src.core.execution_engine import ExecutionClient

        with ExecutionClient() as client:
            stats = client.get_stats()
            assert stats is not None


class TestModels:
    """Tests for execution models."""

    def test_request_result(self):
        """Test RequestResult model."""
        from src.core.execution_engine.models import RequestResult

        result = RequestResult(
            success=True,
            status_code=200,
            body='{"test": "data"}',
            latency_ms=100.5,
        )

        assert result.success is True
        assert result.status_code == 200
        assert result.latency_ms == 100.5

    def test_llm_request_to_kwargs(self):
        """Test LLMRequest conversion."""
        from src.core.execution_engine.models import LLMRequest

        request = LLMRequest(
            url="https://api.example.com/v1/chat/completions",
            api_key="test-key",
            body={"model": "gpt-4", "messages": []},
        )

        kwargs = request.to_httpx_kwargs()

        assert kwargs["url"] == request.url
        assert "Bearer test-key" in kwargs["headers"]["Authorization"]
        assert kwargs["json"]["model"] == "gpt-4"
