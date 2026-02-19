"""Main Scanner class - orchestrates the scan process."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .config import ScanConfig
from ..execution_engine import (
    AttackExecutor,
    AttackExecutionRecord,
    ExecutionContext,
    ExecutionClient,
    LLMRequest,
)
from ..reporting import (
    JSONReporter,
    HTMLReporter,
    ReportData,
    VulnerabilityRecord,
    PluginSummary,
)
from src.plugins.base import ScanResult
from src.plugins.registry import PluginRegistry, get_registry

console = Console()


class Scanner:
    """Main scanner orchestrator."""

    def __init__(self, config: ScanConfig):
        """Initialize scanner with configuration.

        Args:
            config: Scan configuration.
        """
        self.config = config
        self._registry: Optional[PluginRegistry] = None
        self._executor: Optional[AttackExecutor] = None
        self._llm_loader = None
        self._llm_inference = None

    def _get_registry(self) -> PluginRegistry:
        """Get or create plugin registry."""
        if self._registry is None:
            self._registry = get_registry()
            # Auto-discover plugins
            self._registry.auto_discover()
        return self._registry

    def _get_executor(self) -> AttackExecutor:
        """Get or create attack executor."""
        if self._executor is None:
            self._executor = AttackExecutor(
                target_url=self.config.target_url,
                api_key=self.config.api_key,
                model=self.config.model,
            )
        return self._executor

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

            console.print(f"[green]+[/green] Local LLM loaded: {self.config.llm_model_path}")
            return True

        except Exception as e:
            console.print(f"[yellow]![/yellow] Failed to load local LLM: {e}")
            return False

    def test_connection(self) -> tuple[bool, str]:
        """Test connection to target API.

        Returns:
            Tuple of (success, message).
        """
        client = ExecutionClient()
        request = LLMRequest(
            url=self.config.target_url,
            body={
                "model": self.config.model,
                "messages": [{"role": "user", "content": "Hello, please respond with 'OK'."}],
            },
            api_key=self.config.api_key,
        )

        result = client.execute(request, show_progress=False)
        client.close()

        if result.success:
            return True, f"Connection successful (status: {result.status_code}, latency: {result.latency_ms:.0f}ms)"
        else:
            return False, f"Connection failed: {result.error}"

    def list_plugins(self) -> list[dict[str, Any]]:
        """List available plugins.

        Returns:
            List of plugin info dictionaries.
        """
        registry = self._get_registry()
        return registry.list_plugins()

    def run(self) -> dict[str, Any]:
        """Run the complete security scan.

        Returns:
            Scan report dictionary.
        """
        start_time = datetime.now()
        scan_id = f"scan-{start_time.strftime('%Y%m%d%H%M%S')}"

        # Print header
        console.print(Panel.fit(
            f"[bold blue]DeepLLMScanner[/bold blue] v0.1.0\n"
            f"Scan ID: {scan_id}",
            title="Security Scan"
        ))

        # Initialize
        console.print(f"\n[cyan]Target:[/cyan] {self.config.target_url}")
        console.print(f"[cyan]Model:[/cyan] {self.config.model}")
        console.print(f"[cyan]Mode:[/cyan] {self.config.scan_mode}")

        # Test connection first
        console.print("\n[cyan]Testing connection...[/cyan]")
        success, message = self.test_connection()
        if success:
            console.print(f"[green]OK[/green] {message}")
        else:
            console.print(f"[red]FAIL[/red] {message}")
            return {
                "scan_id": scan_id,
                "success": False,
                "error": message,
                "start_time": start_time.isoformat(),
            }

        # Initialize local LLM if configured
        has_local_llm = self._init_local_llm()

        # Get plugins
        registry = self._get_registry()
        available_plugins = registry.get_enabled_plugins()

        # Filter plugins if specified
        if self.config.plugins:
            plugin_ids = set(self.config.plugins)
            plugins_to_run = [p for p in available_plugins if p.id in plugin_ids]
        else:
            plugins_to_run = available_plugins

        if not plugins_to_run:
            console.print("[yellow]![/yellow] No plugins to execute")
            return {
                "scan_id": scan_id,
                "success": False,
                "error": "No plugins available",
                "start_time": start_time.isoformat(),
            }

        console.print(f"\n[cyan]Plugins to run:[/cyan] {', '.join(p.id for p in plugins_to_run)}")

        # Create executor and register plugins
        executor = self._get_executor()
        for plugin in plugins_to_run:
            executor.register_plugin(plugin)

        # Run scan
        console.print(f"\n[bold green]Starting security scan...[/bold green]\n")

        context, scan_results = executor.run_scan(
            plugin_ids=[p.id for p in plugins_to_run],
            scan_mode=self.config.scan_mode,
            max_attacks_per_plugin=self.config.max_attacks_per_plugin,
            show_summary=False,
        )

        # Build report
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        report = {
            "scan_id": scan_id,
            "success": True,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": round(duration, 2),
            "config": {
                "target_url": self.config.target_url,
                "model": self.config.model,
                "scan_mode": self.config.scan_mode,
                "max_attacks_per_plugin": self.config.max_attacks_per_plugin,
            },
            "local_llm": {
                "enabled": has_local_llm,
                "model_path": self.config.llm_model_path,
            },
            "summary": {
                "total_attacks": context.total_attacks,
                "executed_attacks": context.executed_attacks,
                "vulnerabilities_found": context.vulnerabilities_found,
                "success_rate": round(context.success_rate, 2),
            },
            "plugins": [],
            "vulnerabilities": [],
        }

        # Add plugin results
        for result in scan_results:
            # Calculate risk scores for detected vulnerabilities
            plugin = registry.get_plugin(result.plugin_id)
            if plugin:
                for attack_result in result.results:
                    if attack_result.detected:
                        # Use the new process_result method for validation and scoring
                        plugin.process_result(attack_result, validate=False, calculate_risk=True)

            plugin_report = {
                "plugin_id": result.plugin_id,
                "category": result.category.value,
                "total_attacks": result.total_attacks,
                "vulnerabilities_found": result.vulnerabilities_found,
                "success_rate": round(result.success_rate, 2),
            }

            # Add risk summary if available
            risk_scores = [r.risk_score for r in result.results if r.detected and r.risk_score]
            if risk_scores:
                from src.core.scoring_engine import RiskLevel
                plugin_report["risk_summary"] = {
                    "total_scored": len(risk_scores),
                    "average_score": round(sum(s.score for s in risk_scores) / len(risk_scores), 2),
                    "max_score": max(s.score for s in risk_scores),
                    "by_level": {
                        "critical": len([s for s in risk_scores if s.level == RiskLevel.CRITICAL]),
                        "high": len([s for s in risk_scores if s.level == RiskLevel.HIGH]),
                        "medium": len([s for s in risk_scores if s.level == RiskLevel.MEDIUM]),
                        "low": len([s for s in risk_scores if s.level == RiskLevel.LOW]),
                    },
                }

            report["plugins"].append(plugin_report)

            # Add vulnerability details
            for attack_result in result.results:
                if attack_result.detected:
                    vuln = {
                        "plugin_id": result.plugin_id,
                        "category": result.category.value,
                        "payload": attack_result.attack.payload[:200],
                        "response": attack_result.response[:1000] if attack_result.response else None,
                        "confidence": attack_result.confidence,
                        "evidence": attack_result.evidence,
                    }

                    # Add risk score if available
                    if attack_result.risk_score:
                        vuln["risk_score"] = {
                            "score": attack_result.risk_score.score,
                            "level": attack_result.risk_score.level.value,
                            "priority": attack_result.risk_score.priority.value,
                            "breakdown": attack_result.risk_score.breakdown,
                        }

                    # Add validation result if available
                    if attack_result.validation:
                        vuln["validation"] = {
                            "status": attack_result.validation.status.value,
                            "reproducibility": attack_result.validation.reproducibility,
                            "method": attack_result.validation.validation_method.value if attack_result.validation.validation_method else None,
                        }

                    report["vulnerabilities"].append(vuln)

        # Print summary
        self._print_summary(report)

        # Save output
        if self.config.output_path:
            self._save_report(report)

        # Cleanup
        executor.close()

        return report

    def _print_summary(self, report: dict[str, Any]) -> None:
        """Print scan summary."""
        console.print("\n" + "=" * 60)
        console.print("[bold]Scan Summary[/bold]")
        console.print("=" * 60)

        # General info
        table = Table(show_header=False)
        table.add_column("Key", style="cyan")
        table.add_column("Value")

        table.add_row("Scan ID", report["scan_id"])
        table.add_row("Duration", f"{report['duration_seconds']}s")
        table.add_row("Target", report["config"]["target_url"])
        table.add_row("Mode", report["config"]["scan_mode"])

        console.print(table)

        # Statistics
        console.print(f"\n[bold]Statistics:[/bold]")
        stats = report["summary"]
        console.print(f"  Total Attacks: {stats['total_attacks']}")
        console.print(f"  Executed: {stats['executed_attacks']}")
        console.print(f"  Vulnerabilities Found: [red]{stats['vulnerabilities_found']}[/red]")
        console.print(f"  Success Rate: {stats['success_rate']:.1%}")

        # Plugin results
        if report["plugins"]:
            console.print(f"\n[bold]Plugin Results:[/bold]")
            plugin_table = Table(show_header=True)
            plugin_table.add_column("Plugin", style="cyan")
            plugin_table.add_column("Attacks")
            plugin_table.add_column("Vulnerabilities")
            plugin_table.add_column("Success Rate")

            for p in report["plugins"]:
                vuln_color = "red" if p["vulnerabilities_found"] > 0 else "green"
                plugin_table.add_row(
                    p["plugin_id"],
                    str(p["total_attacks"]),
                    f"[{vuln_color}]{p['vulnerabilities_found']}[/{vuln_color}]",
                    f"{p['success_rate']:.1%}",
                )
            console.print(plugin_table)

        # Vulnerabilities
        if report["vulnerabilities"]:
            console.print(f"\n[bold red]Vulnerabilities Detected:[/bold red]")
            for i, vuln in enumerate(report["vulnerabilities"][:10], 1):
                console.print(f"\n[yellow]{i}.[/yellow] [{vuln['plugin_id']}] Confidence: {vuln['confidence']:.0%}")
                console.print(f"   Payload: {vuln['payload'][:100]}...")

        console.print("\n" + "=" * 60)

    def _save_report(self, report: dict[str, Any]) -> None:
        """Save report to file.

        Supports multiple formats based on file extension:
        - .json: JSON report
        - .html: HTML report
        - .json+html (or no extension): Both formats
        """
        output_path = Path(self.config.output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Determine output format from extension
        suffix = output_path.suffix.lower()

        # Build ReportData from report dict
        report_data = self._build_report_data(report)

        if suffix == ".json":
            # JSON only
            reporter = JSONReporter()
            reporter.generate(report_data, str(output_path))
            console.print(f"\n[green]Report saved to:[/green] {output_path}")

        elif suffix == ".html":
            # HTML only
            reporter = HTMLReporter()
            reporter.generate(report_data, str(output_path))
            console.print(f"\n[green]HTML report saved to:[/green] {output_path}")

        else:
            # Default: generate both JSON and HTML
            json_path = output_path.with_suffix(".json") if suffix else output_path.parent / f"{output_path.stem}.json"
            html_path = output_path.with_suffix(".html") if suffix else output_path.parent / f"{output_path.stem}.html"

            # Generate JSON
            json_reporter = JSONReporter()
            json_reporter.generate(report_data, str(json_path))
            console.print(f"\n[green]JSON report saved to:[/green] {json_path}")

            # Generate HTML
            html_reporter = HTMLReporter()
            html_reporter.generate(report_data, str(html_path))
            console.print(f"[green]HTML report saved to:[/green] {html_path}")

    def _build_report_data(self, report: dict[str, Any]) -> ReportData:
        """Build ReportData from report dictionary."""
        # Parse timestamps
        start_time = datetime.fromisoformat(report["start_time"])
        end_time = datetime.fromisoformat(report["end_time"])

        # Build vulnerability records
        vulnerabilities = []
        for vuln in report.get("vulnerabilities", []):
            risk_score = None
            risk_level = None
            priority = None

            if "risk_score" in vuln:
                risk_score = vuln["risk_score"]["score"]
                risk_level = vuln["risk_score"]["level"]
                priority = vuln["risk_score"]["priority"]

            validation_passed = None
            if "validation" in vuln:
                validation_passed = vuln["validation"].get("reproducible", 1.0) >= 0.8

            vulnerabilities.append(VulnerabilityRecord(
                id=f"{vuln['plugin_id']}-{len(vulnerabilities) + 1}",
                plugin_id=vuln["plugin_id"],
                category=vuln["category"],
                payload=vuln["payload"],
                response=vuln.get("response", ""),
                confidence=vuln["confidence"],
                evidence=vuln.get("evidence", {}),
                risk_score=risk_score,
                risk_level=risk_level,
                priority=priority,
                validation_passed=validation_passed,
            ))

        # Build plugin summaries
        plugin_summaries = []
        for plugin in report.get("plugins", []):
            plugin_summaries.append(PluginSummary(
                plugin_id=plugin["plugin_id"],
                category=plugin["category"],
                total_attacks=plugin["total_attacks"],
                vulnerabilities_found=plugin["vulnerabilities_found"],
                success_rate=plugin["success_rate"],
                risk_summary=plugin.get("risk_summary"),
            ))

        return ReportData(
            scan_id=report["scan_id"],
            target_url=report["config"]["target_url"],
            model=report["config"]["model"],
            scan_mode=report["config"]["scan_mode"],
            start_time=start_time,
            end_time=end_time,
            vulnerabilities=vulnerabilities,
            plugin_summaries=plugin_summaries,
            config=report.get("config", {}),
            local_llm=report.get("local_llm", {}),
        )
