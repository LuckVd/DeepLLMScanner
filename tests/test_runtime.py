"""Tests for LLM Runtime."""

import pytest


class TestLLMLoader:
    """Tests for LLMLoader."""

    def test_config_defaults(self):
        """Test default configuration values."""
        from src.runtime.llm_runtime.loader import LLMConfig

        config = LLMConfig()
        assert config.n_ctx == 4096
        assert config.n_gpu_layers == 0
        assert config.n_threads == 8

    def test_loader_without_model_path(self):
        """Test loader raises error without model path."""
        from src.runtime.llm_runtime.loader import LLMLoader, LLMConfig

        loader = LLMLoader(LLMConfig())
        assert not loader.is_loaded()

        with pytest.raises(ValueError, match="Model path not provided"):
            loader.load()

    def test_loader_nonexistent_model(self):
        """Test loader raises error for nonexistent model."""
        from src.runtime.llm_runtime.loader import LLMLoader, LLMConfig

        config = LLMConfig(model_path="/nonexistent/model.gguf")
        loader = LLMLoader(config)

        with pytest.raises(FileNotFoundError):
            loader.load()


class TestInferenceConfig:
    """Tests for InferenceConfig."""

    def test_default_config(self):
        """Test default inference configuration."""
        from src.runtime.llm_runtime.inference import InferenceConfig

        config = InferenceConfig()
        assert config.max_tokens == 512
        assert config.temperature == 0.7
        assert config.top_p == 0.9
