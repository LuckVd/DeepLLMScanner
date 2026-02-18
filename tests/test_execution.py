"""Tests for Execution Engine."""

import pytest
from datetime import datetime

from src.core.execution_engine import (
    AttackExecutor,
    AttackExecutionRecord,
    ExecutionClient,
    ExecutionContext,
    ExecutionPhase,
    LLMRequest,
    LLMResponse,
    RequestConfig,
    RequestResult,
    ScanStatus,
)


class TestRequestConfig:
    """Tests for RequestConfig model."""

    def test_default_values(self):
        """Test default configuration values."""
        config = RequestConfig()
        assert config.timeout == 30.0
        assert config.max_retries == 3
        assert config.retry_delay == 1.0
        assert config.verify_ssl is True

    def test_custom_values(self):
        """Test custom configuration values."""
        config = RequestConfig(
            timeout=60.0,
            max_retries=5,
            retry_delay=2.0,
            verify_ssl=False,
        )
        assert config.timeout == 60.0
        assert config.max_retries == 5
        assert config.retry_delay == 2.0
        assert config.verify_ssl is False


class TestRequestResult:
    """Tests for RequestResult model."""

    def test_success_result(self):
        """Test successful request result."""
        result = RequestResult(
            success=True,
            status_code=200,
            body='{"test": "data"}',
            latency_ms=100.5,
            request_id="abc123",
        )
        assert result.success is True
        assert result.status_code == 200
        assert result.body == '{"test": "data"}'
        assert result.latency_ms == 100.5
        assert result.error is None

    def test_failure_result(self):
        """Test failed request result."""
        result = RequestResult(
            success=False,
            error="Connection timeout",
            latency_ms=30000.0,
        )
        assert result.success is False
        assert result.status_code is None
        assert result.error == "Connection timeout"


class TestLLMRequest:
    """Tests for LLMRequest model."""

    def test_basic_request(self):
        """Test basic LLM request."""
        request = LLMRequest(
            url="https://api.example.com/v1/chat/completions",
            body={"model": "gpt-4", "messages": []},
        )
        assert request.url == "https://api.example.com/v1/chat/completions"
        assert request.method == "POST"
        assert request.api_key is None

    def test_to_httpx_kwargs_without_api_key(self):
        """Test conversion to httpx kwargs without API key."""
        request = LLMRequest(
            url="https://api.example.com/v1/chat/completions",
            body={"model": "gpt-4", "messages": []},
        )
        kwargs = request.to_httpx_kwargs()

        assert kwargs["url"] == request.url
        assert kwargs["method"] == "POST"
        assert kwargs["json"]["model"] == "gpt-4"
        assert "Authorization" not in kwargs["headers"]

    def test_to_httpx_kwargs_with_api_key(self):
        """Test conversion to httpx kwargs with API key."""
        request = LLMRequest(
            url="https://api.example.com/v1/chat/completions",
            api_key="test-key-123",
            body={"model": "gpt-4", "messages": []},
        )
        kwargs = request.to_httpx_kwargs()

        assert "Bearer test-key-123" in kwargs["headers"]["Authorization"]

    def test_custom_headers(self):
        """Test custom headers."""
        request = LLMRequest(
            url="https://api.example.com/v1/chat/completions",
            headers={"X-Custom-Header": "value"},
            body={"model": "gpt-4", "messages": []},
        )
        kwargs = request.to_httpx_kwargs()

        assert kwargs["headers"]["X-Custom-Header"] == "value"


class TestLLMResponse:
    """Tests for LLMResponse model."""

    def test_from_openai_format(self):
        """Test parsing OpenAI-compatible response."""
        data = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Hello, world!",
                    }
                }
            ],
            "model": "gpt-4",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
        response = LLMResponse.from_openai_format(data)

        assert response.content == "Hello, world!"
        assert response.model == "gpt-4"
        assert response.usage["prompt_tokens"] == 10

    def test_from_openai_format_empty(self):
        """Test parsing empty OpenAI response."""
        data = {}
        response = LLMResponse.from_openai_format(data)

        assert response.content == ""
        assert response.model is None


class TestExecutionContext:
    """Tests for ExecutionContext."""

    def test_default_values(self):
        """Test default context values."""
        ctx = ExecutionContext()

        assert ctx.status == ScanStatus.PENDING
        assert ctx.current_phase == ExecutionPhase.INITIALIZATION
        assert ctx.scan_id != ""
        assert ctx.total_attacks == 0

    def test_start(self):
        """Test starting a scan."""
        ctx = ExecutionContext()
        ctx.start()

        assert ctx.status == ScanStatus.RUNNING
        assert ctx.started_at is not None
        assert ctx.current_phase == ExecutionPhase.ATTACK_GENERATION

    def test_complete(self):
        """Test completing a scan."""
        ctx = ExecutionContext()
        ctx.start()
        ctx.complete()

        assert ctx.status == ScanStatus.COMPLETED
        assert ctx.completed_at is not None
        assert ctx.current_phase == ExecutionPhase.REPORTING

    def test_fail(self):
        """Test failing a scan."""
        ctx = ExecutionContext()
        ctx.start()
        ctx.fail("Test error")

        assert ctx.status == ScanStatus.FAILED
        assert "Test error" in ctx.errors

    def test_cancel(self):
        """Test cancelling a scan."""
        ctx = ExecutionContext()
        ctx.start()
        ctx.cancel()

        assert ctx.status == ScanStatus.CANCELLED

    def test_increment_attack(self):
        """Test attack counter increment."""
        ctx = ExecutionContext()

        ctx.increment_attack()
        assert ctx.executed_attacks == 1

        ctx.increment_attack(success=True, vulnerability=True)
        assert ctx.executed_attacks == 2
        assert ctx.successful_attacks == 1
        assert ctx.vulnerabilities_found == 1

    def test_progress_percent(self):
        """Test progress calculation."""
        ctx = ExecutionContext(total_attacks=10, executed_attacks=5)

        assert ctx.progress_percent == 50.0

    def test_progress_percent_zero_total(self):
        """Test progress with zero total."""
        ctx = ExecutionContext(total_attacks=0)

        assert ctx.progress_percent == 0.0

    def test_success_rate(self):
        """Test success rate calculation."""
        ctx = ExecutionContext(
            executed_attacks=10,
            successful_attacks=3,
        )

        assert ctx.success_rate == 0.3

    def test_to_dict(self):
        """Test context serialization."""
        ctx = ExecutionContext(
            target_url="https://example.com",
            total_attacks=10,
            executed_attacks=5,
        )
        data = ctx.to_dict()

        assert data["target_url"] == "https://example.com"
        assert data["total_attacks"] == 10
        assert data["progress_percent"] == 50.0


class TestAttackExecutionRecord:
    """Tests for AttackExecutionRecord."""

    def test_default_values(self):
        """Test default record values."""
        record = AttackExecutionRecord()

        assert record.attack_id != ""
        assert record.detected is False
        assert record.confidence == 0.0
        assert record.severity == "low"

    def test_custom_values(self):
        """Test custom record values."""
        record = AttackExecutionRecord(
            plugin_id="test_plugin",
            template_id="test_template",
            payload="test payload",
            category="LLM01",
            detected=True,
            confidence=0.85,
            severity="high",
        )

        assert record.plugin_id == "test_plugin"
        assert record.detected is True
        assert record.confidence == 0.85
        assert record.severity == "high"

    def test_to_dict(self):
        """Test record serialization."""
        record = AttackExecutionRecord(
            plugin_id="test_plugin",
            detected=True,
            confidence=0.9,
        )
        data = record.to_dict()

        assert data["plugin_id"] == "test_plugin"
        assert data["detected"] is True
        assert data["confidence"] == 0.9


class TestExecutionClient:
    """Tests for ExecutionClient."""

    def test_stats_initial(self):
        """Test initial statistics."""
        client = ExecutionClient()
        stats = client.get_stats()

        assert stats["total_requests"] == 0
        assert stats["successful_requests"] == 0
        assert stats["failed_requests"] == 0

        client.close()

    def test_reset_stats(self):
        """Test statistics reset."""
        client = ExecutionClient()
        client._stats["total_requests"] = 10
        client.reset_stats()

        stats = client.get_stats()
        assert stats["total_requests"] == 0

        client.close()

    def test_context_manager(self):
        """Test context manager usage."""
        with ExecutionClient() as client:
            stats = client.get_stats()
            assert stats is not None


class TestAttackExecutor:
    """Tests for AttackExecutor."""

    def test_init(self):
        """Test executor initialization."""
        executor = AttackExecutor(
            target_url="https://api.example.com/v1/chat/completions",
            api_key="test-key",
        )

        assert executor.target_url == "https://api.example.com/v1/chat/completions"
        assert executor.api_key == "test-key"

        executor.close()

    def test_context_manager(self):
        """Test executor context manager."""
        with AttackExecutor(target_url="https://example.com") as executor:
            assert executor.target_url == "https://example.com"

    def test_list_plugins_empty(self):
        """Test listing plugins when none registered."""
        with AttackExecutor(target_url="https://example.com") as executor:
            assert executor.list_plugins() == []

    def test_create_context(self):
        """Test context creation."""
        with AttackExecutor(target_url="https://example.com") as executor:
            ctx = executor.create_context(
                plugin_ids=["test1", "test2"],
                scan_mode="quick",
                max_attacks_per_plugin=50,
            )

            assert ctx.target_url == "https://example.com"
            assert ctx.plugin_ids == ["test1", "test2"]
            assert ctx.scan_mode == "quick"
            assert ctx.max_attacks_per_plugin == 50

    def test_get_execution_records_empty(self):
        """Test getting records when none exist."""
        with AttackExecutor(target_url="https://example.com") as executor:
            records = executor.get_execution_records()
            assert records == []


class TestEnums:
    """Tests for enum values."""

    def test_scan_status_values(self):
        """Test ScanStatus enum values."""
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        assert ScanStatus.CANCELLED.value == "cancelled"

    def test_execution_phase_values(self):
        """Test ExecutionPhase enum values."""
        assert ExecutionPhase.INITIALIZATION.value == "initialization"
        assert ExecutionPhase.ATTACK_GENERATION.value == "attack_generation"
        assert ExecutionPhase.REQUEST_EXECUTION.value == "request_execution"
        assert ExecutionPhase.DETECTION.value == "detection"
        assert ExecutionPhase.VALIDATION.value == "validation"
        assert ExecutionPhase.REPORTING.value == "reporting"
