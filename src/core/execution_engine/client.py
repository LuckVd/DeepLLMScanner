"""HTTP Client for executing requests to LLM APIs."""

import time
import uuid
from typing import Any, Optional

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .models import LLMRequest, LLMResponse, RequestConfig, RequestResult

console = Console()


class ExecutionClient:
    """HTTP client for executing LLM API requests."""

    def __init__(self, config: Optional[RequestConfig] = None):
        """Initialize the execution client.

        Args:
            config: Request configuration.
        """
        self.config = config or RequestConfig()
        self._client: Optional[httpx.Client] = None
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_latency_ms": 0.0,
        }

    def _get_client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
        return self._client

    def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def execute(
        self,
        request: LLMRequest,
        show_progress: bool = True
    ) -> RequestResult:
        """Execute a single HTTP request.

        Args:
            request: The request to execute.
            show_progress: Whether to show progress indicator.

        Returns:
            RequestResult with response details.
        """
        client = self._get_client()
        request_id = str(uuid.uuid4())[:8]

        # Prepare kwargs
        kwargs = request.to_httpx_kwargs()

        # Execute with retries
        last_error: Optional[str] = None
        start_time = time.time()

        for attempt in range(self.config.max_retries):
            try:
                if show_progress:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn(f"[cyan]Request {request_id}..."),
                        console=console,
                    ) as progress:
                        progress.add_task("request", total=None)
                        response = client.request(**kwargs)
                else:
                    response = client.request(**kwargs)

                latency_ms = (time.time() - start_time) * 1000

                # Update stats
                self._stats["total_requests"] += 1
                self._stats["successful_requests"] += 1
                self._stats["total_latency_ms"] += latency_ms

                return RequestResult(
                    success=True,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.text,
                    latency_ms=latency_ms,
                    request_id=request_id,
                )

            except httpx.TimeoutException as e:
                last_error = f"Timeout: {e}"
            except httpx.RequestError as e:
                last_error = f"Request error: {e}"
            except Exception as e:
                last_error = f"Unexpected error: {e}"

            # Wait before retry
            if attempt < self.config.max_retries - 1:
                time.sleep(self.config.retry_delay)

        # All retries failed
        latency_ms = (time.time() - start_time) * 1000
        self._stats["total_requests"] += 1
        self._stats["failed_requests"] += 1

        return RequestResult(
            success=False,
            error=last_error,
            latency_ms=latency_ms,
            request_id=request_id,
        )

    def execute_llm_request(
        self,
        url: str,
        prompt: str,
        api_key: Optional[str] = None,
        model: str = "gpt-3.5-turbo",
        **kwargs
    ) -> tuple[RequestResult, Optional[LLMResponse]]:
        """Execute a request to an LLM API.

        Args:
            url: API endpoint URL.
            prompt: The prompt to send.
            api_key: API key for authentication.
            model: Model to use.
            **kwargs: Additional request body parameters.

        Returns:
            Tuple of (RequestResult, LLMResponse or None).
        """
        # Build request
        body = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            **kwargs
        }

        request = LLMRequest(
            url=url,
            body=body,
            api_key=api_key,
        )

        # Execute
        result = self.execute(request)

        # Parse response
        llm_response = None
        if result.success and result.body:
            try:
                import json
                data = json.loads(result.body)
                llm_response = LLMResponse.from_openai_format(data)
            except (json.JSONDecodeError, KeyError):
                pass

        return result, llm_response

    def get_stats(self) -> dict[str, Any]:
        """Get execution statistics.

        Returns:
            Dictionary with statistics.
        """
        stats = dict(self._stats)
        if stats["total_requests"] > 0:
            stats["avg_latency_ms"] = (
                stats["total_latency_ms"] / stats["total_requests"]
            )
            stats["success_rate"] = (
                stats["successful_requests"] / stats["total_requests"]
            )
        else:
            stats["avg_latency_ms"] = 0.0
            stats["success_rate"] = 0.0
        return stats

    def reset_stats(self) -> None:
        """Reset execution statistics."""
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_latency_ms": 0.0,
        }

    def __enter__(self) -> "ExecutionClient":
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit."""
        self.close()
