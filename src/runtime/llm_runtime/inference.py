"""LLM Inference - Generate text using loaded models."""

from typing import Generator, Optional

from llama_cpp import Llama
from pydantic import BaseModel

from .loader import LLMLoader


class InferenceConfig(BaseModel):
    """Configuration for inference."""

    max_tokens: int = 512
    temperature: float = 0.7
    top_p: float = 0.9
    top_k: int = 40
    repeat_penalty: float = 1.1
    stop: list[str] = []


class InferenceResult(BaseModel):
    """Result of an inference call."""

    text: str
    tokens_generated: int
    finish_reason: str


class LLMInference:
    """Generate text using a loaded LLM model."""

    def __init__(self, loader: LLMLoader, config: Optional[InferenceConfig] = None):
        """Initialize inference with a model loader.

        Args:
            loader: LLMLoader instance with a loaded model.
            config: Inference configuration.
        """
        self.loader = loader
        self.config = config or InferenceConfig()

    @property
    def model(self) -> Llama:
        """Get the underlying Llama model."""
        return self.loader.model

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> InferenceResult:
        """Generate text from a prompt.

        Args:
            prompt: User prompt.
            system_prompt: Optional system prompt.
            **kwargs: Override inference config parameters.

        Returns:
            InferenceResult with generated text.
        """
        # Build full prompt with system message if provided
        if system_prompt:
            full_prompt = f"<|system|>\n{system_prompt}\n<|user|>\n{prompt}\n<|assistant| >"
        else:
            full_prompt = prompt

        # Merge config with kwargs
        max_tokens = kwargs.get("max_tokens", self.config.max_tokens)
        temperature = kwargs.get("temperature", self.config.temperature)
        top_p = kwargs.get("top_p", self.config.top_p)
        top_k = kwargs.get("top_k", self.config.top_k)
        repeat_penalty = kwargs.get("repeat_penalty", self.config.repeat_penalty)
        stop = kwargs.get("stop", self.config.stop)

        # Generate
        result = self.model(
            full_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            top_k=top_k,
            repeat_penalty=repeat_penalty,
            stop=stop or None,
        )

        # Extract text
        text = result["choices"][0]["text"]
        tokens_generated = result["usage"]["completion_tokens"]
        finish_reason = result["choices"][0]["finish_reason"]

        return InferenceResult(
            text=text,
            tokens_generated=tokens_generated,
            finish_reason=finish_reason,
        )

    def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> Generator[str, None, None]:
        """Generate text as a stream.

        Args:
            prompt: User prompt.
            system_prompt: Optional system prompt.
            **kwargs: Override inference config parameters.

        Yields:
            Chunks of generated text.
        """
        # Build full prompt
        if system_prompt:
            full_prompt = f"<|system|>\n{system_prompt}\n<|user|>\n{prompt}\n<|assistant| >"
        else:
            full_prompt = prompt

        # Merge config with kwargs
        max_tokens = kwargs.get("max_tokens", self.config.max_tokens)
        temperature = kwargs.get("temperature", self.config.temperature)
        top_p = kwargs.get("top_p", self.config.top_p)
        stop = kwargs.get("stop", self.config.stop)

        # Stream generation
        stream = self.model(
            full_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            stop=stop or None,
            stream=True,
        )

        for chunk in stream:
            text = chunk["choices"][0].get("text", "")
            if text:
                yield text

    def judge(self, prompt: str, context: str) -> dict:
        """Use LLM as a judge for detection.

        This is a specialized method for the detection engine
        that returns structured JSON output.

        Args:
            prompt: The question to judge.
            context: Context for the judgment.

        Returns:
            Parsed JSON judgment.
        """
        import json

        system = """You are a security analysis assistant. Analyze the given context and answer the question.
Always respond with valid JSON. Do not include any text outside the JSON object."""

        judgment_prompt = f"""Context:
{context}

Question: {prompt}

Respond with a JSON object containing:
- "is_vulnerable": boolean
- "confidence": float (0.0-1.0)
- "reasoning": string
- "evidence": array of strings

JSON Response:"""

        result = self.generate(
            prompt=judgment_prompt,
            system_prompt=system,
            temperature=0.1,  # Low temperature for consistent judgments
            max_tokens=512,
            stop=["}", "\n\n"],
        )

        # Parse JSON from response
        try:
            # Add back the closing brace if it was used as stop token
            json_text = result.text.strip()
            if not json_text.endswith("}"):
                json_text += "}"
            return json.loads(json_text)
        except json.JSONDecodeError:
            return {
                "is_vulnerable": False,
                "confidence": 0.0,
                "reasoning": "Failed to parse LLM response",
                "evidence": [],
                "raw_response": result.text,
            }
