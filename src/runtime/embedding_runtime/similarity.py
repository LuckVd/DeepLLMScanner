"""Similarity Calculator - Compute semantic similarity between texts."""

from dataclasses import dataclass
from typing import Optional

import numpy as np
from rich.console import Console

console = Console()


@dataclass
class SimilarityResult:
    """Result of a similarity comparison."""

    score: float
    text1: str
    text2: str
    is_similar: bool


class SimilarityCalculator:
    """Calculate semantic similarity between texts using embeddings.

    This class provides various similarity metrics and search functionality
    for finding similar texts in a corpus.

    Example:
        >>> from src.runtime.embedding_runtime import EmbeddingLoader, SimilarityCalculator
        >>> loader = EmbeddingLoader()
        >>> loader.load()
        >>> calc = SimilarityCalculator(loader)
        >>> score = calc.compute_similarity("hello", "hi there")
        >>> print(f"Similarity: {score:.3f}")
    """

    def __init__(
        self,
        loader,  # EmbeddingLoader type hint avoided to prevent circular import
        default_threshold: float = 0.75,
    ):
        """Initialize the similarity calculator.

        Args:
            loader: An EmbeddingLoader instance with a loaded model.
            default_threshold: Default threshold for considering texts similar.
        """
        self.loader = loader
        self.default_threshold = default_threshold
        self._corpus_embeddings: Optional[np.ndarray] = None
        self._corpus_texts: Optional[list[str]] = None

    def cosine_similarity(
        self,
        vec1: np.ndarray,
        vec2: np.ndarray,
    ) -> float:
        """Calculate cosine similarity between two vectors.

        Args:
            vec1: First vector.
            vec2: Second vector.

        Returns:
            Similarity score between -1 and 1 (typically 0 to 1 for normalized embeddings).
        """
        # Normalize vectors if not already normalized
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        vec1_normalized = vec1 / norm1
        vec2_normalized = vec2 / norm2

        return float(np.dot(vec1_normalized, vec2_normalized))

    def compute_similarity(
        self,
        text1: str,
        text2: str,
    ) -> float:
        """Compute semantic similarity between two texts.

        Args:
            text1: First text.
            text2: Second text.

        Returns:
            Similarity score between 0 and 1.
        """
        if not self.loader.is_loaded():
            raise RuntimeError("Embedding model not loaded")

        emb1 = self.loader.encode(text1)
        emb2 = self.loader.encode(text2)

        return self.cosine_similarity(emb1, emb2)

    def compute_similarity_batch(
        self,
        query: str,
        texts: list[str],
    ) -> list[float]:
        """Compute similarity between a query and multiple texts.

        Args:
            query: Query text.
            texts: List of texts to compare against.

        Returns:
            List of similarity scores.
        """
        if not self.loader.is_loaded():
            raise RuntimeError("Embedding model not loaded")

        # Encode query
        query_emb = self.loader.encode(query)

        # Encode all texts in batch
        text_embs = self.loader.encode_batch(texts)

        # Compute similarities
        similarities = []
        for text_emb in text_embs:
            sim = self.cosine_similarity(query_emb, text_emb)
            similarities.append(sim)

        return similarities

    def index_corpus(self, texts: list[str]) -> None:
        """Index a corpus of texts for fast similarity search.

        Args:
            texts: List of texts to index.
        """
        if not self.loader.is_loaded():
            raise RuntimeError("Embedding model not loaded")

        self._corpus_texts = texts
        self._corpus_embeddings = self.loader.encode_batch(texts)

        console.print(
            f"[green]+[/green] Indexed {len(texts)} texts for similarity search"
        )

    def find_similar(
        self,
        query: str,
        threshold: Optional[float] = None,
        top_k: int = 5,
    ) -> list[tuple[int, float, str]]:
        """Find texts similar to the query in the indexed corpus.

        Args:
            query: Query text.
            threshold: Minimum similarity threshold. None uses default.
            top_k: Maximum number of results to return.

        Returns:
            List of tuples (index, similarity_score, text) sorted by similarity.

        Raises:
            RuntimeError: If corpus has not been indexed.
        """
        if self._corpus_embeddings is None or self._corpus_texts is None:
            raise RuntimeError("Corpus not indexed. Call index_corpus() first.")

        threshold = threshold if threshold is not None else self.default_threshold

        # Encode query
        query_emb = self.loader.encode(query)

        # Compute similarities with all corpus embeddings
        similarities = []
        for idx, corpus_emb in enumerate(self._corpus_embeddings):
            sim = self.cosine_similarity(query_emb, corpus_emb)
            if sim >= threshold:
                similarities.append((idx, sim, self._corpus_texts[idx]))

        # Sort by similarity (descending) and take top_k
        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities[:top_k]

    def is_similar(
        self,
        text1: str,
        text2: str,
        threshold: Optional[float] = None,
    ) -> SimilarityResult:
        """Check if two texts are semantically similar.

        Args:
            text1: First text.
            text2: Second text.
            threshold: Similarity threshold. None uses default.

        Returns:
            SimilarityResult with score and similarity flag.
        """
        threshold = threshold if threshold is not None else self.default_threshold
        score = self.compute_similarity(text1, text2)

        return SimilarityResult(
            score=score,
            text1=text1,
            text2=text2,
            is_similar=score >= threshold,
        )

    def find_most_similar(
        self,
        query: str,
        candidates: list[str],
    ) -> tuple[int, float, str]:
        """Find the most similar text from a list of candidates.

        Args:
            query: Query text.
            candidates: List of candidate texts.

        Returns:
            Tuple of (index, similarity_score, text) for the best match.
        """
        scores = self.compute_similarity_batch(query, candidates)
        best_idx = int(np.argmax(scores))

        return (best_idx, scores[best_idx], candidates[best_idx])

    def clear_corpus(self) -> None:
        """Clear the indexed corpus to free memory."""
        self._corpus_embeddings = None
        self._corpus_texts = None

    def get_corpus_info(self) -> dict:
        """Get information about the indexed corpus.

        Returns:
            Dictionary with corpus information.
        """
        if self._corpus_embeddings is None:
            return {"status": "not_indexed"}

        return {
            "status": "indexed",
            "num_texts": len(self._corpus_texts) if self._corpus_texts else 0,
            "embedding_dimension": self._corpus_embeddings.shape[1]
            if self._corpus_embeddings is not None else None,
            "default_threshold": self.default_threshold,
        }


# Convenience functions for quick usage

def quick_similarity(text1: str, text2: str, model_name: str = "all-MiniLM-L6-v2") -> float:
    """Quickly compute similarity between two texts.

    This is a convenience function that loads a model temporarily.
    For repeated use, create EmbeddingLoader and SimilarityCalculator instances.

    Args:
        text1: First text.
        text2: Second text.
        model_name: Name of the embedding model to use.

    Returns:
        Similarity score between 0 and 1.
    """
    from .loader import EmbeddingLoader, EmbeddingConfig

    config = EmbeddingConfig(model_name=model_name)
    loader = EmbeddingLoader(config)

    if not loader.load():
        raise RuntimeError("Failed to load embedding model")

    calc = SimilarityCalculator(loader)
    return calc.compute_similarity(text1, text2)
