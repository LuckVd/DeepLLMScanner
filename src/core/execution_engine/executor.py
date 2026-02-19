"""High-level attack executor that integrates plugins and attack engine."""

from typing import Any, Iterator, Optional

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from src.core.attack_engine import AttackCategory, AttackGenerator, GeneratedAttack
from src.plugins.base import AttackContext, AttackResult, BasePlugin, ScanResult

from .client import ExecutionClient
from .context import (
    AttackExecutionRecord,
    ExecutionContext,
    ExecutionPhase,
    ScanStatus,
)
from .models import LLMRequest, LLMResponse, RequestConfig, RequestResult

console = Console()


class AttackExecutor:
    """High-level executor for running vulnerability scans.

    This class integrates:
    - AttackGenerator: Generates attack payloads from templates
    - ExecutionClient: Sends HTTP requests to target APIs
    - Plugin system: Detects vulnerabilities in responses
    """

    def __init__(
        self,
        target_url: str,
        api_key: Optional[str] = None,
        model: str = "gpt-3.5-turbo",
        request_config: Optional[RequestConfig] = None,
        llm_model_path: Optional[str] = None,
        use_llm_judge: bool = True,
    ):
        """Initialize the attack executor.

        Args:
            target_url: Target LLM API endpoint URL.
            api_key: Optional API key for authentication.
            model: Target model name (e.g., "deepseek-chat", "gpt-4").
            request_config: HTTP request configuration.
            llm_model_path: Path to local GGUF model for LLM Judge.
            use_llm_judge: Whether to use LLM Judge for validation.
        """
        self.target_url = target_url
        self.api_key = api_key
        self.model = model
        self.request_config = request_config or RequestConfig()
        self._client = ExecutionClient(self.request_config)
        self._generator = AttackGenerator()
        self._plugins: dict[str, BasePlugin] = {}
        self._context: Optional[ExecutionContext] = None
        self._execution_records: list[AttackExecutionRecord] = []

        # Initialize LLM Judge if model path is provided
        if llm_model_path and use_llm_judge:
            self._init_llm_judge(llm_model_path)

    def _init_llm_judge(self, model_path: str) -> bool:
        """Initialize the global LLM Judge instance."""
        try:
            from src.core.detection_engine import get_judge, reset_judge

            # Reset any existing judge first
            reset_judge()

            # Create new judge with model path
            judge = get_judge(model_path)
            if judge.is_enabled():
                console.print(f"[green]+[/green] LLM Judge enabled for validation")
                return True
            else:
                console.print(f"[yellow]![/yellow] LLM Judge initialization failed")
                return False
        except Exception as e:
            console.print(f"[yellow]![/yellow] LLM Judge error: {e}")
            return False

    def register_plugin(self, plugin: BasePlugin) -> None:
        """Register a plugin for execution.

        Args:
            plugin: Plugin instance to register.
        """
        self._plugins[plugin.id] = plugin
        console.print(f"[green]+[/green] Registered plugin: {plugin.id}")

    def register_plugins(self, plugins: list[BasePlugin]) -> None:
        """Register multiple plugins.

        Args:
            plugins: List of plugin instances.
        """
        for plugin in plugins:
            self.register_plugin(plugin)

    def get_plugin(self, plugin_id: str) -> Optional[BasePlugin]:
        """Get a registered plugin by ID.

        Args:
            plugin_id: Plugin identifier.

        Returns:
            Plugin instance or None.
        """
        return self._plugins.get(plugin_id)

    def list_plugins(self) -> list[str]:
        """List registered plugin IDs.

        Returns:
            List of plugin IDs.
        """
        return list(self._plugins.keys())

    def create_context(
        self,
        plugin_ids: Optional[list[str]] = None,
        scan_mode: str = "quick",
        max_attacks_per_plugin: int = 100,
    ) -> ExecutionContext:
        """Create a new execution context.

        Args:
            plugin_ids: Plugins to run. If None, runs all registered.
            scan_mode: Scan mode (quick, standard, deep).
            max_attacks_per_plugin: Max attacks per plugin.

        Returns:
            New ExecutionContext instance.
        """
        plugins = plugin_ids or list(self._plugins.keys())

        ctx = ExecutionContext(
            target_url=self.target_url,
            plugin_ids=plugins,
            scan_mode=scan_mode,
            max_attacks_per_plugin=max_attacks_per_plugin,
        )

        return ctx

    def execute_attack(
        self,
        attack: GeneratedAttack,
        plugin: BasePlugin,
        context: Optional[ExecutionContext] = None,
        attack_context: Optional[AttackContext] = None,
    ) -> AttackExecutionRecord:
        """Execute a single attack and detect vulnerability.

        Args:
            attack: The attack to execute.
            plugin: Plugin handling this attack.
            context: Optional execution context for tracking.
            attack_context: Optional multi-turn attack context.

        Returns:
            AttackExecutionRecord with results.
        """
        record = AttackExecutionRecord(
            plugin_id=plugin.id,
            template_id=attack.template_id,
            payload=attack.payload,
            category=attack.category.value,
            request_url=self.target_url,
        )

        # Build and execute request
        request = LLMRequest(
            url=self.target_url,
            body={
                "model": self.model,
                "messages": [{"role": "user", "content": attack.payload}],
            },
            api_key=self.api_key,
        )

        result = self._client.execute(request, show_progress=False)

        record.response_status = result.status_code
        record.response_latency_ms = result.latency_ms
        record.response_body = result.body

        if not result.success:
            record.error = result.error
            return record

        # Detect vulnerability
        detection = plugin.detect_vulnerability(
            attack=attack,
            response=result.body or "",
            context=attack_context,
        )

        record.detected = detection.detected
        record.confidence = detection.confidence
        record.evidence = detection.evidence

        # Calculate severity
        severity = plugin.calculate_severity(detection, attack_context)
        record.severity = severity.value

        # Validate if detected
        if detection.detected:
            record.validated = plugin.validate_vulnerability(detection, attack_context)

        # Update context if provided
        if context:
            context.increment_attack(
                success=detection.detected,
                vulnerability=record.validated,
            )

        return record

    def execute_plugin(
        self,
        plugin: BasePlugin,
        context: ExecutionContext,
        max_attacks: Optional[int] = None,
    ) -> ScanResult:
        """Execute all attacks for a single plugin.

        Args:
            plugin: Plugin to execute.
            context: Execution context.
            max_attacks: Override max attacks limit.

        Returns:
            ScanResult with all attack results.
        """
        context.set_plugin(plugin.id)
        context.set_phase(ExecutionPhase.ATTACK_GENERATION)

        max_attacks = max_attacks or context.max_attacks_per_plugin
        results: list[AttackResult] = []
        successful = 0

        # Generate attacks
        attack_context = AttackContext()
        attacks = list(plugin.generate_attacks(attack_context))[:max_attacks]

        context.set_phase(ExecutionPhase.REQUEST_EXECUTION)
        context.total_attacks += len(attacks)

        console.print(f"[cyan]Executing {len(attacks)} attacks for {plugin.name}...[/cyan]")

        # Use simple progress without Unicode characters for Windows compatibility
        for i, attack in enumerate(attacks):
            console.print(f"  [dim]{plugin.id} [{i+1}/{len(attacks)}][/dim]")

            record = self.execute_attack(
                attack=attack,
                plugin=plugin,
                context=context,
                attack_context=attack_context,
            )

            self._execution_records.append(record)

            # Convert record to AttackResult for ScanResult
            result = AttackResult(
                attack=attack,
                success=record.detected,
                response=record.response_body,
                detected=record.detected,
                confidence=record.confidence,
                evidence=record.evidence,
                error=record.error,
            )
            results.append(result)

            if record.detected:
                successful += 1

        # Create scan result
        scan_result = ScanResult(
            plugin_id=plugin.id,
            category=plugin.category,
            total_attacks=len(attacks),
            successful_attacks=successful,
            vulnerabilities_found=sum(1 for r in results if r.detected),
            results=results,
        )

        return scan_result

    def run_scan(
        self,
        plugin_ids: Optional[list[str]] = None,
        scan_mode: str = "quick",
        max_attacks_per_plugin: int = 100,
        show_summary: bool = True,
    ) -> tuple[ExecutionContext, list[ScanResult]]:
        """Run a complete vulnerability scan.

        Args:
            plugin_ids: Specific plugins to run. If None, runs all registered.
            scan_mode: Scan mode (quick, standard, deep).
            max_attacks_per_plugin: Maximum attacks per plugin.
            show_summary: Whether to print summary after completion.

        Returns:
            Tuple of (ExecutionContext, list of ScanResults).
        """
        # Create context
        self._context = self.create_context(
            plugin_ids=plugin_ids,
            scan_mode=scan_mode,
            max_attacks_per_plugin=max_attacks_per_plugin,
        )

        context = self._context
        context.start()
        context.set_phase(ExecutionPhase.INITIALIZATION)

        console.print(f"\n[bold blue]Starting scan: {context.scan_id}[/bold blue]")
        console.print(f"Target: {self.target_url}")
        console.print(f"Mode: {scan_mode}")
        console.print(f"Plugins: {', '.join(context.plugin_ids)}\n")

        # Get plugins to run
        plugins_to_run = [
            self._plugins[pid]
            for pid in context.plugin_ids
            if pid in self._plugins
        ]

        if not plugins_to_run:
            context.fail("No valid plugins to execute")
            return context, []

        # Execute each plugin
        scan_results: list[ScanResult] = []

        for plugin in plugins_to_run:
            if context.status == ScanStatus.CANCELLED:
                break

            try:
                result = self.execute_plugin(plugin, context)
                scan_results.append(result)
            except Exception as e:
                context.add_error(f"Plugin {plugin.id} failed: {str(e)}")
                console.print(f"[red]Error in {plugin.id}: {e}[/red]")

        # Complete scan
        context.complete()

        if show_summary:
            self._print_summary(context, scan_results)

        return context, scan_results

    def _print_summary(
        self,
        context: ExecutionContext,
        scan_results: list[ScanResult],
    ) -> None:
        """Print scan summary."""
        console.print("\n" + "=" * 60)
        console.print("[bold blue]Scan Summary[/bold blue]")
        console.print("=" * 60)

        console.print(f"\nScan ID: {context.scan_id}")
        console.print(f"Status: {context.status.value}")
        console.print(f"Duration: {context.duration_seconds:.2f}s")
        console.print(f"Target: {context.target_url}")

        console.print(f"\n[bold]Statistics:[/bold]")
        console.print(f"  Total Attacks: {context.executed_attacks}")
        console.print(f"  Vulnerabilities Found: {context.vulnerabilities_found}")
        console.print(f"  Success Rate: {context.success_rate:.1%}")

        if scan_results:
            console.print(f"\n[bold]Results by Plugin:[/bold]")
            for result in scan_results:
                status = "[green]OK[/green]" if result.vulnerabilities_found == 0 else "[red]![/red]"
                console.print(
                    f"  {status} {result.plugin_id}: "
                    f"{result.vulnerabilities_found}/{result.total_attacks} vulnerabilities"
                )

        if context.errors:
            console.print(f"\n[bold red]Errors:[/bold red]")
            for error in context.errors[:5]:
                console.print(f"  - {error}")

        console.print("\n" + "=" * 60)

    def get_execution_records(self) -> list[AttackExecutionRecord]:
        """Get all execution records.

        Returns:
            List of AttackExecutionRecord instances.
        """
        return self._execution_records

    def get_client_stats(self) -> dict[str, Any]:
        """Get HTTP client statistics.

        Returns:
            Dictionary with client stats.
        """
        return self._client.get_stats()

    def close(self) -> None:
        """Close the executor and release resources."""
        self._client.close()

    def __enter__(self) -> "AttackExecutor":
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit."""
        self.close()
