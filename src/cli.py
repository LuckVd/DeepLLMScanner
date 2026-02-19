#!/usr/bin/env python3
"""DeepLLMScanner CLI - Command-line interface for LLM security scanning."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from src.core.controller.scanner import Scanner
from src.core.controller.config import ScanConfig

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="deepscanner")
def cli():
    """DeepLLMScanner - LLM Security Vulnerability Scanner.

    Scan LLM APIs for OWASP LLM Top 10 vulnerabilities.
    """
    pass


@cli.command()
@click.option(
    "--url", "-u",
    required=True,
    help="Target LLM API endpoint URL (e.g., https://api.openai.com/v1/chat/completions)"
)
@click.option(
    "--api-key", "-k",
    default=None,
    envvar="OPENAI_API_KEY",
    help="API key for authentication (or set OPENAI_API_KEY env var)"
)
@click.option(
    "--model", "-m",
    default="gpt-3.5-turbo",
    show_default=True,
    help="Target model name"
)
@click.option(
    "--model-path", "-p",
    default=None,
    type=click.Path(exists=False),
    help="Path to local GGUF model for enhanced detection"
)
@click.option(
    "--mode",
    type=click.Choice(["quick", "standard", "deep"]),
    default="quick",
    show_default=True,
    help="Scan mode: quick (fast), standard (balanced), deep (thorough)"
)
@click.option(
    "--plugins", "-l",
    default=None,
    help="Comma-separated list of plugin IDs to run (default: all)"
)
@click.option(
    "--max-attacks",
    default=10,
    show_default=True,
    help="Maximum attacks per plugin"
)
@click.option(
    "--max-requests",
    default=50,
    show_default=True,
    help="Maximum total requests"
)
@click.option(
    "--timeout",
    default=30.0,
    show_default=True,
    help="Request timeout in seconds"
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Output file path for report"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "html"]),
    default="json",
    show_default=True,
    help="Output format"
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output"
)
@click.option(
    "--threads",
    default=8,
    show_default=True,
    help="Number of CPU threads for local model"
)
@click.option(
    "--context",
    default=4096,
    show_default=True,
    help="Context window size for local model"
)
def scan(
    url: str,
    api_key: Optional[str],
    model: str,
    model_path: Optional[str],
    mode: str,
    plugins: Optional[str],
    max_attacks: int,
    max_requests: int,
    timeout: float,
    output: Optional[str],
    format: str,
    verbose: bool,
    threads: int,
    context: int,
):
    """Run a security scan on the target LLM API.

    Examples:

        # Basic scan
        deepscanner scan --url https://api.example.com/v1/chat

        # With API key
        deepscanner scan -u https://api.example.com/v1/chat -k sk-xxx

        # With local model for enhanced detection
        deepscanner scan -u https://api.example.com/v1/chat -p ./models/qwen.gguf

        # Specific plugins only
        deepscanner scan -u https://api.example.com/v1/chat -l llm01,llm07

        # HTML report
        deepscanner scan -u https://api.example.com/v1/chat -o report.html -f html
    """
    # Parse plugins
    plugin_list = None
    if plugins:
        plugin_list = [p.strip() for p in plugins.split(",")]

    # Validate model path if provided
    if model_path and not Path(model_path).exists():
        console.print(f"[red]Error:[/red] Model file not found: {model_path}")
        sys.exit(1)

    # Create config
    config = ScanConfig(
        target_url=url,
        api_key=api_key,
        model=model,
        llm_model_path=model_path,
        llm_n_ctx=context,
        llm_n_threads=threads,
        scan_mode=mode,
        plugins=plugin_list,
        max_attacks_per_plugin=max_attacks,
        max_requests=max_requests,
        timeout=timeout,
        output_format=format,
        output_path=output,
        verbose=verbose,
    )

    # Run scanner
    try:
        scanner = Scanner(config)
        report = scanner.run()

        if output:
            console.print(f"\n[green]Report saved to:[/green] {output}")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        if verbose:
            console.print_exception()
        sys.exit(1)


@cli.command("list-plugins")
def list_plugins():
    """List all available security plugins."""
    config = ScanConfig(target_url="http://placeholder")  # Placeholder for registry
    scanner = Scanner(config)
    plugins = scanner.list_plugins()

    table = Table(title="Available Security Plugins")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Category", style="yellow")
    table.add_column("Priority", style="magenta")
    table.add_column("Description", style="white")

    for plugin in plugins:
        table.add_row(
            plugin.get("id", "unknown"),
            plugin.get("name", "Unknown"),
            plugin.get("category", "unknown"),
            str(plugin.get("priority", "normal")),
            plugin.get("description", "")[:50] + "..." if len(plugin.get("description", "")) > 50 else plugin.get("description", ""),
        )

    console.print(table)
    console.print(f"\nTotal: {len(plugins)} plugins")


@cli.command("test-connection")
@click.option("--url", "-u", required=True, help="Target LLM API endpoint URL")
@click.option("--api-key", "-k", default=None, help="API key for authentication")
@click.option("--model", "-m", default="gpt-3.5-turbo", help="Target model name")
def test_connection(url: str, api_key: Optional[str], model: str):
    """Test connection to the target LLM API."""
    config = ScanConfig(
        target_url=url,
        api_key=api_key,
        model=model,
    )
    scanner = Scanner(config)

    console.print(f"[cyan]Testing connection to:[/cyan] {url}")
    success, message = scanner.test_connection()

    if success:
        console.print(f"[green]OK[/green] {message}")
    else:
        console.print(f"[red]ERROR[/red] {message}")
        sys.exit(1)


@cli.command("test-model")
@click.option("--model-path", "-p", required=True, type=click.Path(exists=True), help="Path to GGUF model file")
@click.option("--prompt", default="Hello, respond with 'OK'.", help="Test prompt")
@click.option("--threads", default=8, help="Number of CPU threads")
@click.option("--context", default=2048, help="Context window size")
def test_model(model_path: str, prompt: str, threads: int, context: int):
    """Test local GGUF model loading and inference."""
    console.print(f"[cyan]Loading model:[/cyan] {model_path}")

    try:
        from src.runtime.llm_runtime import LLMLoader
        from src.runtime.llm_runtime.loader import LLMConfig

        config = LLMConfig(
            model_path=model_path,
            n_ctx=context,
            n_threads=threads,
            verbose=False,
        )

        loader = LLMLoader(config)
        model = loader.load()

        console.print("[green]OK[/green] Model loaded successfully")
        console.print(f"[cyan]Running inference...[/cyan]")

        response = model.create_completion(
            prompt,
            max_tokens=50,
            temperature=0.7,
        )

        text = response["choices"][0]["text"].strip()
        console.print(f"[green]Response:[/green] {text}")
        console.print(f"[dim]Tokens: {response['usage']['completion_tokens']}[/dim]")

    except Exception as e:
        console.print(f"[red]ERROR[/red] Error: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
