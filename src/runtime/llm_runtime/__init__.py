"""LLM Runtime - Local model loading and inference using llama.cpp."""

# Optional dependency - only import if llama_cpp is available
try:
    from .loader import LLMLoader
    from .inference import LLMInference
    __all__ = ["LLMLoader", "LLMInference"]
except ImportError:
    # llama_cpp not installed - these features are unavailable
    LLMLoader = None  # type: ignore
    LLMInference = None  # type: ignore
    __all__ = ["LLMLoader", "LLMInference"]
