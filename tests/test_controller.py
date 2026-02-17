"""Tests for Controller."""

import pytest


class TestScanConfig:
    """Tests for ScanConfig."""

    def test_required_fields(self):
        """Test that target_url is required."""
        from src.core.controller.config import ScanConfig

        with pytest.raises(Exception):  # ValidationError
            ScanConfig()

    def test_defaults(self):
        """Test default configuration values."""
        from src.core.controller.config import ScanConfig

        config = ScanConfig(target_url="https://api.example.com")

        assert config.model == "gpt-3.5-turbo"
        assert config.scan_mode == "quick"
        assert config.max_requests == 50
        assert config.timeout == 30.0
        assert config.output_format == "json"

    def test_mode_validation(self):
        """Test scan mode validation."""
        from src.core.controller.config import ScanConfig

        config = ScanConfig(
            target_url="https://api.example.com",
            scan_mode="deep"
        )
        assert config.scan_mode == "deep"

        with pytest.raises(Exception):  # ValidationError
            ScanConfig(target_url="https://api.example.com", scan_mode="invalid")
