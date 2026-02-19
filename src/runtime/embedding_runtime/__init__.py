"""Embedding Runtime - Text vectorization and similarity calculation.

This module provides embedding-based detection capabilities (L2 layer)
using sentence-transformers for semantic similarity analysis.
"""

# Optional dependency - only import if sentence_transformers is available
try:
    from .loader import EmbeddingLoader, EmbeddingConfig
    from .similarity import SimilarityCalculator

    __all__ = ["EmbeddingLoader", "EmbeddingConfig", "SimilarityCalculator"]
except ImportError:
    # sentence_transformers not installed - these features are unavailable
    EmbeddingLoader = None  # type: ignore
    EmbeddingConfig = None  # type: ignore
    SimilarityCalculator = None  # type: ignore
    __all__ = ["EmbeddingLoader", "EmbeddingConfig", "SimilarityCalculator"]
