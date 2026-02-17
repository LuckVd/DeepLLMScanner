"""LLM Model Loader - Load GGUF models using llama.cpp."""

from pathlib import Path
from typing import Optional

from llama_cpp import Llama
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class LLMConfig(BaseSettings):
    """Configuration for LLM runtime."""

    model_path: Optional[str] = Field(
        default=None,
        description="Path to GGUF model file"
    )
    n_ctx: int = Field(
        default=4096,
        description="Context window size"
    )
    n_gpu_layers: int = Field(
        default=0,
        description="GPU layers (0 for CPU-only)"
    )
    n_threads: int = Field(
        default=8,
        description="Number of CPU threads"
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose output"
    )

    model_config = {"env_prefix": "LLM_"}


class LLMLoader:
    """Load and manage local LLM models."""

    def __init__(self, config: Optional[LLMConfig] = None):
        """Initialize the loader with configuration.

        Args:
            config: LLM configuration. If None, uses defaults.
        """
        self.config = config or LLMConfig()
        self._model: Optional[Llama] = None

    @property
    def model(self) -> Llama:
        """Get the loaded model, loading if necessary."""
        if self._model is None:
            self._model = self.load()
        return self._model

    def load(self, model_path: Optional[str] = None) -> Llama:
        """Load a GGUF model.

        Args:
            model_path: Path to model file. Overrides config.

        Returns:
            Loaded Llama instance.

        Raises:
            ValueError: If no model path is provided.
            FileNotFoundError: If model file doesn't exist.
        """
        path = model_path or self.config.model_path

        if path is None:
            raise ValueError(
                "Model path not provided. Set LLM_MODEL_PATH environment "
                "variable or pass model_path parameter."
            )

        model_file = Path(path)
        if not model_file.exists():
            raise FileNotFoundError(f"Model file not found: {path}")

        self._model = Llama(
            model_path=str(model_file),
            n_ctx=self.config.n_ctx,
            n_gpu_layers=self.config.n_gpu_layers,
            n_threads=self.config.n_threads,
            verbose=self.config.verbose,
        )

        return self._model

    def unload(self) -> None:
        """Unload the current model to free memory."""
        if self._model is not None:
            del self._model
            self._model = None

    def is_loaded(self) -> bool:
        """Check if a model is currently loaded."""
        return self._model is not None

    def get_model_info(self) -> dict:
        """Get information about the loaded model.

        Returns:
            Dictionary with model information.
        """
        if not self.is_loaded():
            return {"status": "not_loaded"}

        return {
            "status": "loaded",
            "n_ctx": self.config.n_ctx,
            "n_threads": self.config.n_threads,
            "n_gpu_layers": self.config.n_gpu_layers,
        }
