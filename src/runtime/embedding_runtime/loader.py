"""Embedding Model Loader - Load sentence-transformers models for text vectorization."""

from dataclasses import dataclass, field
from typing import Optional

import numpy as np
from rich.console import Console

console = Console()


@dataclass
class EmbeddingConfig:
    """Configuration for Embedding runtime."""

    model_name: str = field(
        default="all-MiniLM-L6-v2",
        metadata={"help": "Name or path of the sentence-transformers model"}
    )
    device: str = field(
        default="cpu",
        metadata={"help": "Device to run model on (cpu, cuda, mps)"}
    )
    max_seq_length: Optional[int] = field(
        default=None,
        metadata={"help": "Maximum sequence length (None for model default)"}
    )
    normalize_embeddings: bool = field(
        default=True,
        metadata={"help": "Whether to normalize embeddings to unit length"}
    )
    cache_dir: Optional[str] = field(
        default=None,
        metadata={"help": "Directory to cache downloaded models"}
    )


class EmbeddingLoader:
    """Load and manage embedding models for text vectorization.

    This class provides a unified interface for loading sentence-transformers
    models and encoding text into dense vectors for similarity analysis.

    Example:
        >>> loader = EmbeddingLoader()
        >>> loader.load()
        >>> embeddings = loader.encode("Hello world")
        >>> print(embeddings.shape)
        (384,)
    """

    def __init__(self, config: Optional[EmbeddingConfig] = None):
        """Initialize the embedding loader.

        Args:
            config: Embedding configuration. If None, uses defaults.
        """
        self.config = config or EmbeddingConfig()
        self._model = None
        self._enabled = False
        self._dimension: Optional[int] = None

    @property
    def dimension(self) -> int:
        """Get the embedding dimension."""
        if self._dimension is None:
            raise RuntimeError("Model not loaded. Call load() first.")
        return self._dimension

    def is_loaded(self) -> bool:
        """Check if a model is currently loaded."""
        return self._model is not None and self._enabled

    def load(self, model_name: Optional[str] = None) -> bool:
        """Load the embedding model.

        Args:
            model_name: Model name or path. Overrides config.

        Returns:
            True if model loaded successfully, False otherwise.
        """
        name = model_name or self.config.model_name

        try:
            from sentence_transformers import SentenceTransformer

            # Load the model
            self._model = SentenceTransformer(
                name,
                device=self.config.device,
                cache_folder=self.config.cache_dir,
            )

            # Set max sequence length if specified
            if self.config.max_seq_length:
                self._model.max_seq_length = self.config.max_seq_length

            # Get embedding dimension
            self._dimension = self._model.get_sentence_embedding_dimension()
            self._enabled = True

            console.print(
                f"[green]+[/green] Embedding model loaded: {name} "
                f"(dim={self._dimension}, device={self.config.device})"
            )
            return True

        except ImportError:
            console.print(
                "[yellow]![/yellow] sentence-transformers not installed. "
                "Install with: pip install sentence-transformers"
            )
            self._enabled = False
            return False

        except Exception as e:
            console.print(f"[red]x[/red] Failed to load embedding model: {e}")
            self._enabled = False
            return False

    def unload(self) -> None:
        """Unload the current model to free memory."""
        if self._model is not None:
            del self._model
            self._model = None
            self._dimension = None
            self._enabled = False

    def encode(
        self,
        text: str,
        normalize: Optional[bool] = None,
    ) -> np.ndarray:
        """Encode a single text into an embedding vector.

        Args:
            text: Text to encode.
            normalize: Whether to normalize. None uses config default.

        Returns:
            Numpy array of shape (dimension,).

        Raises:
            RuntimeError: If model is not loaded.
        """
        if not self._enabled or self._model is None:
            raise RuntimeError("Model not loaded. Call load() first.")

        normalize_flag = (
            normalize if normalize is not None
            else self.config.normalize_embeddings
        )

        embedding = self._model.encode(
            text,
            normalize_embeddings=normalize_flag,
            convert_to_numpy=True,
        )

        return embedding  # type: ignore

    def encode_batch(
        self,
        texts: list[str],
        normalize: Optional[bool] = None,
        show_progress: bool = False,
    ) -> np.ndarray:
        """Encode multiple texts into embedding vectors.

        Args:
            texts: List of texts to encode.
            normalize: Whether to normalize. None uses config default.
            show_progress: Whether to show progress bar.

        Returns:
            Numpy array of shape (len(texts), dimension).

        Raises:
            RuntimeError: If model is not loaded.
        """
        if not self._enabled or self._model is None:
            raise RuntimeError("Model not loaded. Call load() first.")

        normalize_flag = (
            normalize if normalize is not None
            else self.config.normalize_embeddings
        )

        embeddings = self._model.encode(
            texts,
            normalize_embeddings=normalize_flag,
            convert_to_numpy=True,
            show_progress_bar=show_progress,
        )

        return embeddings  # type: ignore

    def get_model_info(self) -> dict:
        """Get information about the loaded model.

        Returns:
            Dictionary with model information.
        """
        if not self.is_loaded():
            return {"status": "not_loaded"}

        return {
            "status": "loaded",
            "model_name": self.config.model_name,
            "dimension": self._dimension,
            "device": self.config.device,
            "max_seq_length": self._model.max_seq_length if self._model else None,
            "normalize_embeddings": self.config.normalize_embeddings,
        }


# Global loader instance
_loader_instance: Optional[EmbeddingLoader] = None


def get_embedding_loader(config: Optional[EmbeddingConfig] = None) -> EmbeddingLoader:
    """Get or create the global embedding loader instance.

    Args:
        config: Embedding configuration. Only used on first call.

    Returns:
        EmbeddingLoader instance.
    """
    global _loader_instance

    if _loader_instance is None:
        _loader_instance = EmbeddingLoader(config)

    return _loader_instance


def reset_embedding_loader() -> None:
    """Reset the global embedding loader instance."""
    global _loader_instance

    if _loader_instance:
        _loader_instance.unload()
        _loader_instance = None
