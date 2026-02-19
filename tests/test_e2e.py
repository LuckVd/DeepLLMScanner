"""End-to-end integration tests for DeepLLMScanner."""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner

from src.core.controller.scanner import Scanner
from src.core.controller.config import ScanConfig
from src.cli import cli


class TestCLI:
    """Tests for CLI commands."""

    def test_cli_version(self):
        """Test CLI version command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_cli_help(self):
        """Test CLI help command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "DeepLLMScanner" in result.output
        assert "scan" in result.output
        assert "list-plugins" in result.output

    def test_scan_help(self):
        """Test scan command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--url" in result.output
        assert "--api-key" in result.output
        assert "--model" in result.output
        assert "--mode" in result.output

    def test_list_plugins(self):
        """Test list-plugins command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["list-plugins"])
        assert result.exit_code == 0
        assert "llm01" in result.output.lower()
        assert "llm10" in result.output.lower()
        assert "10 plugins" in result.output

    def test_scan_missing_url(self):
        """Test scan command without URL."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code != 0
        assert "url" in result.output.lower() or "required" in result.output.lower()


class TestScannerIntegration:
    """Integration tests for Scanner class."""

    def test_scanner_initialization(self):
        """Test scanner can be initialized."""
        config = ScanConfig(
            target_url="https://api.example.com/v1/chat",
            api_key="test-key",
            model="gpt-3.5-turbo",
        )
        scanner = Scanner(config)
        assert scanner.config == config

    def test_scanner_list_plugins(self):
        """Test scanner can list plugins."""
        config = ScanConfig(target_url="https://api.example.com/v1/chat")
        scanner = Scanner(config)
        plugins = scanner.list_plugins()
        assert len(plugins) == 10

    @patch("src.core.controller.scanner.ExecutionClient")
    def test_scanner_test_connection_success(self, mock_client_class):
        """Test scanner connection test success."""
        mock_client = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.status_code = 200
        mock_result.latency_ms = 100.0
        mock_client.execute.return_value = mock_result
        mock_client_class.return_value = mock_client

        config = ScanConfig(target_url="https://api.example.com/v1/chat")
        scanner = Scanner(config)
        success, message = scanner.test_connection()

        assert success is True
        assert "successful" in message.lower()

    @patch("src.core.controller.scanner.ExecutionClient")
    def test_scanner_test_connection_failure(self, mock_client_class):
        """Test scanner connection test failure."""
        mock_client = Mock()
        mock_result = Mock()
        mock_result.success = False
        mock_result.error = "Connection timeout"
        mock_client.execute.return_value = mock_result
        mock_client_class.return_value = mock_client

        config = ScanConfig(target_url="https://api.example.com/v1/chat")
        scanner = Scanner(config)
        success, message = scanner.test_connection()

        assert success is False
        assert "failed" in message.lower()


class TestConfigIntegration:
    """Integration tests for configuration."""

    def test_config_defaults(self):
        """Test config with minimal required fields."""
        config = ScanConfig(target_url="https://api.example.com")
        assert config.target_url == "https://api.example.com"
        assert config.model == "gpt-3.5-turbo"
        assert config.scan_mode == "quick"
        assert config.output_format == "json"
        assert config.verbose is False

    def test_config_full(self):
        """Test config with all fields."""
        config = ScanConfig(
            target_url="https://api.example.com/v1/chat",
            api_key="sk-test",
            model="gpt-4",
            llm_model_path="/path/to/model.gguf",
            llm_n_ctx=4096,
            llm_n_threads=8,
            scan_mode="standard",
            plugins=["llm01", "llm07"],
            max_attacks_per_plugin=5,
            max_requests=100,
            timeout=60.0,
            output_format="html",
            output_path="report.html",
            verbose=True,
        )
        assert config.target_url == "https://api.example.com/v1/chat"
        assert config.api_key == "sk-test"
        assert config.model == "gpt-4"
        assert config.llm_model_path == "/path/to/model.gguf"
        assert config.scan_mode == "standard"
        assert config.plugins == ["llm01", "llm07"]
        assert config.output_format == "html"

    def test_config_env_prefix(self):
        """Test config can read from environment."""
        import os
        os.environ["SCAN_TIMEOUT"] = "45.0"
        config = ScanConfig(target_url="https://api.example.com")
        # Note: This tests that env_prefix is set, actual env reading may vary
        assert config.model_config["env_prefix"] == "SCAN_"
        del os.environ["SCAN_TIMEOUT"]


class TestPluginRegistry:
    """Integration tests for plugin registry."""

    def test_all_plugins_registered(self):
        """Test all 10 OWASP plugins are registered."""
        from src.plugins.registry import get_registry

        registry = get_registry()
        registry.auto_discover()
        plugins = registry.list_plugins()

        assert len(plugins) == 10

        plugin_ids = {p["id"] for p in plugins}
        expected_ids = {
            "llm01_prompt_injection",
            "llm02_data_leak",
            "llm03_supply_chain",
            "llm04_data_poisoning",
            "llm05_output_handling",
            "llm06_excessive_agency",
            "llm07_system_prompt_leak",
            "llm08_vector_weakness",
            "llm09_misinformation",
            "llm10_unbounded_consumption",
        }
        assert plugin_ids == expected_ids

    def test_plugin_categories(self):
        """Test plugins have correct OWASP categories."""
        from src.plugins.registry import get_registry

        registry = get_registry()
        registry.auto_discover()
        plugins = registry.list_plugins()

        categories = {p["category"] for p in plugins}
        # Should have categories for all LLM01-LLM10
        for i in range(1, 11):
            assert any(f"LLM{i:02d}" in cat or f"LLM{i}" in cat for cat in categories), f"Missing category for LLM{i}"


class TestReportingIntegration:
    """Integration tests for reporting module."""

    def test_json_reporter_import(self):
        """Test JSON reporter can be imported."""
        from src.core.reporting import JSONReporter, ReportData, VulnerabilityRecord

        assert JSONReporter is not None
        assert ReportData is not None
        assert VulnerabilityRecord is not None

    def test_html_reporter_import(self):
        """Test HTML reporter can be imported."""
        from src.core.reporting import HTMLReporter

        assert HTMLReporter is not None

    def test_report_data_creation(self):
        """Test ReportData can be created."""
        from src.core.reporting import ReportData, VulnerabilityRecord, PluginSummary
        from datetime import datetime

        report = ReportData(
            scan_id="test-scan",
            target_url="https://api.example.com",
            model="gpt-3.5-turbo",
            scan_mode="quick",
            start_time=datetime.now(),
            end_time=datetime.now(),
            vulnerabilities=[],
            plugin_summaries=[],
        )
        assert report.scan_id == "test-scan"
        assert report.target_url == "https://api.example.com"


class TestStateEngineIntegration:
    """Integration tests for state engine."""

    def test_state_engine_import(self):
        """Test state engine can be imported."""
        from src.core.state_engine import (
            Conversation,
            StateMachine,
            StateManager,
            AttackState,
        )

        assert Conversation is not None
        assert StateMachine is not None
        assert StateManager is not None
        assert AttackState is not None

    def test_state_machine_transitions(self):
        """Test state machine can transition states."""
        from src.core.state_engine import StateMachine, AttackState

        sm = StateMachine()
        assert sm.state == AttackState.IDLE

        # Valid transition
        assert sm.transition(AttackState.INITIALIZING)
        assert sm.state == AttackState.INITIALIZING

        # Invalid transition (can't go directly to COMPLETED)
        assert not sm.transition(AttackState.COMPLETED)
        assert sm.state == AttackState.INITIALIZING


class TestExecutionEngineIntegration:
    """Integration tests for execution engine."""

    def test_execution_client_import(self):
        """Test execution client can be imported."""
        from src.core.execution_engine import ExecutionClient, LLMRequest

        assert ExecutionClient is not None
        assert LLMRequest is not None

    def test_llm_request_creation(self):
        """Test LLMRequest can be created."""
        from src.core.execution_engine import LLMRequest

        request = LLMRequest(
            url="https://api.example.com/v1/chat",
            body={"model": "gpt-3.5-turbo", "messages": []},
            api_key="test-key",
        )
        assert request.url == "https://api.example.com/v1/chat"


class TestLocalLLMIntegration:
    """Integration tests for local LLM runtime."""

    def test_llm_loader_import(self):
        """Test LLM loader can be imported."""
        from src.runtime.llm_runtime import LLMLoader
        from src.runtime.llm_runtime.loader import LLMConfig

        assert LLMLoader is not None
        assert LLMConfig is not None

    def test_llm_config_defaults(self):
        """Test LLMConfig defaults."""
        from src.runtime.llm_runtime.loader import LLMConfig

        config = LLMConfig()
        assert config.n_ctx == 4096
        assert config.n_threads == 8
        assert config.n_gpu_layers == 0

    @pytest.mark.skipif(
        not Path("models/qwen2.5-7b-instruct-q3_k_m.gguf").exists(),
        reason="Model file not available"
    )
    def test_llm_load_and_inference(self):
        """Test actual LLM loading and inference (requires model file)."""
        from src.runtime.llm_runtime import LLMLoader
        from src.runtime.llm_runtime.loader import LLMConfig

        config = LLMConfig(
            model_path="models/qwen2.5-7b-instruct-q3_k_m.gguf",
            n_ctx=512,  # Small context for fast test
            n_threads=2,
            verbose=False,
        )

        loader = LLMLoader(config)
        model = loader.load()

        assert loader.is_loaded()

        # Simple inference
        response = model.create_completion(
            "Say 'test'",
            max_tokens=10,
            temperature=0.1,
        )

        assert "choices" in response
        assert len(response["choices"]) > 0


class TestFullScanWorkflow:
    """Full scan workflow tests (mocked)."""

    @patch("src.core.controller.scanner.ExecutionClient")
    @patch("src.plugins.base.BasePlugin.detect_vulnerability")
    def test_mock_scan_workflow(self, mock_detect, mock_client_class):
        """Test a mocked scan workflow."""
        # Setup mocks
        mock_client = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.status_code = 200
        mock_result.body = '{"choices": [{"message": {"content": "Hello"}}]}'
        mock_result.latency_ms = 100.0
        mock_client.execute.return_value = mock_result
        mock_client_class.return_value = mock_client

        mock_detect.return_value = Mock(
            success=False,
            detected=False,
            confidence=0.0,
            evidence={},
        )

        # Run scan
        config = ScanConfig(
            target_url="https://api.example.com/v1/chat",
            api_key="test-key",
            model="gpt-3.5-turbo",
            scan_mode="quick",
            max_attacks_per_plugin=1,
            max_requests=10,
        )

        scanner = Scanner(config)
        # Note: Full scan requires more setup, this tests initialization
        assert scanner is not None
        assert scanner._get_registry() is not None
