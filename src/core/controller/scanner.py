"""Main Scanner class - orchestrates the scan process."""

import json
from datetime import datetime
from typing import Any, Optional
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .config import ScanConfig
from ..execution_engine import ExecutionClient, LLMRequest

console = Console()


class Scanner:
    """Main scanner orchestrator."""

    def __init__(self, config: ScanConfig):
        """Initialize scanner with configuration.

        Args:
            config: Scan configuration.
        """
        self.config = config
        self._execution_client: Optional[ExecutionClient] = None
        self._llm_loader = None
        self._llm_inference = None

    def _get_execution_client(self) -> ExecutionClient:
        """Get or create execution client."""
        if self._execution_client is None:
            from ..execution_engine import RequestConfig
            exec_config = RequestConfig(
                timeout=self.config.timeout,
            )
            self._execution_client = ExecutionClient(exec_config)
        return self._execution_client

    def _init_local_llm(self) -> bool:
        """Initialize local LLM if configured.

        Returns:
            True if LLM is available, False otherwise.
        """
        if self.config.llm_model_path is None:
            return False

        try:
            from ...runtime.llm_runtime import LLMLoader, LLMInference
            from ...runtime.llm_runtime.loader import LLMConfig

            llm_config = LLMConfig(
                model_path=self.config.llm_model_path,
                n_ctx=self.config.llm_n_ctx,
                n_threads=self.config.llm_n_threads,
            )
            self._llm_loader = LLMLoader(llm_config)
            self._llm_inference = LLMInference(self._llm_loader)

            console.print(f"[green]✓[/green] Local LLM loaded: {self.config.llm_model_path}")
            return True

        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Failed to load local LLM: {e}")
            return False

    def run(self) -> dict[str, Any]:
        """Run the scan.

        Returns:
            Scan report dictionary.
        """
        start_time = datetime.now()
        console.print(f"\n[bold blue]DeepLLMScanner[/bold blue] - Starting scan")
        console.print(f"Target: {self.config.target_url}")
        console.print(f"Mode: {self.config.scan_mode}")

        # Initialize components
        exec_client = self._get_execution_client()
        has_local_llm = self._init_local_llm()

        # Test connection
        console.print("\n[cyan]Testing connection...[/cyan]")
        result, response = exec_client.execute_llm_request(
            url=self.config.target_url,
            prompt="Hello, this is a test message. Please respond with 'OK'.",
            api_key=self.config.api_key,
            model=self.config.model,
        )

        report = {
            "scan_id": f"scan-{start_time.strftime('%Y%m%d%H%M%S')}",
            "start_time": start_time.isoformat(),
            "config": {
                "target_url": self.config.target_url,
                "model": self.config.model,
                "scan_mode": self.config.scan_mode,
            },
            "connection_test": {
                "success": result.success,
                "status_code": result.status_code,
                "latency_ms": result.latency_ms,
            },
            "local_llm": {
                "enabled": has_local_llm,
                "model_path": self.config.llm_model_path,
            },
            "statistics": exec_client.get_stats(),
        }

        if result.success and response:
            console.print(f"[green]✓[/green] Connection successful")
            console.print(f"  Response: {response.content[:100]}...")
            report["connection_test"]["response_preview"] = response.content[:200]
        else:
            console.print(f"[red]✗[/red] Connection failed: {result.error}")
            report["connection_test"]["error"] = result.error

        # Test local LLM if available
        if has_local_llm and self._llm_inference:
            console.print("\n[cyan]Testing local LLM...[/cyan]")
            try:
                llm_result = self._llm_inference.generate(
                    prompt="Say 'OK' if you can read this.",
                    max_tokens=10,
                )
                console.print(f"[green]✓[/green] Local LLM working")
                console.print(f"  Response: {llm_result.text[:50]}...")
                report["local_llm"]["test_response"] = llm_result.text[:100]
            except Exception as e:
                console.print(f"[red]✗[/red] Local LLM test failed: {e}")
                report["local_llm"]["error"] = str(e)

        # Finalize
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        report["end_time"] = end_time.isoformat()
        report["duration_seconds"] = duration

        # Print summary
        self._print_summary(report)

        # Save output
        if self.config.output_path:
            self._save_report(report)

        # Cleanup
        exec_client.close()

        return report

    def _print_summary(self, report: dict[str, Any]) -> None:
        """Print scan summary."""
        console.print("\n" + "=" * 50)
        console.print("[bold]Scan Summary[/bold]")
        console.print("=" * 50)

        table = Table(show_header=False)
        table.add_column("Key", style="cyan")
        table.add_column("Value")

        table.add_row("Scan ID", report["scan_id"])
        table.add_row("Duration", f"{report['duration_seconds']:.2f}s")
        table.add_row("Target", report["config"]["target_url"])
        table.add_row(
            "Connection",
            "[green]OK[/green]" if report["connection_test"]["success"] else "[red]Failed[/red]"
        )
        table.add_row(
            "Local LLM",
            "[green]Enabled[/green]" if report["local_llm"]["enabled"] else "[yellow]Disabled[/yellow]"
        )

        console.print(table)

    def _save_report(self, report: dict[str, Any]) -> None:
        """Save report to file."""
        output_path = Path(self.config.output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        console.print(f"\n[green]Report saved to:[/green] {output_path}")
