"""CLI entry point for DeepLLMScanner."""

import os
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.text import Text

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="deepllm")
def main() -> None:
    """DeepLLMScanner - CPU-only LLM DAST Framework.

    A security scanner for LLM APIs covering OWASP LLM Top 10 vulnerabilities.
    """
    pass


@main.command()
@click.argument("target_url")
@click.option(
    "--api-key", "-k",
    envvar="LLM_API_KEY",
    help="API key for the target LLM (or set LLM_API_KEY env var)"
)
@click.option(
    "--model", "-m",
    default="gpt-3.5-turbo",
    help="Target model name"
)
@click.option(
    "--mode",
    type=click.Choice(["quick", "standard", "deep"]),
    default="quick",
    help="Scan mode: quick (fast), standard (balanced), deep (thorough)"
)
@click.option(
    "--plugins", "-p",
    help="Comma-separated list of plugin IDs to run (e.g., LLM01,LLM02). Default: all"
)
@click.option(
    "--max-attacks",
    default=10,
    help="Maximum attacks per plugin (default: 10)"
)
@click.option(
    "--llm-model",
    envvar="LLM_MODEL_PATH",
    help="Path to local GGUF model for enhanced detection"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path for JSON report"
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output"
)
def scan(
    target_url: str,
    api_key: Optional[str],
    model: str,
    mode: str,
    plugins: Optional[str],
    max_attacks: int,
    llm_model: Optional[str],
    output: Optional[str],
    verbose: bool,
) -> None:
    """Run a security scan on the target LLM API.

    TARGET_URL: The LLM API endpoint to scan (e.g., https://api.openai.com/v1/chat/completions)

    Examples:

        # Scan OpenAI API
        deepllm scan https://api.openai.com/v1/chat/completions -k sk-xxx -m gpt-4

        # Scan DeepSeek API with specific plugins
        deepllm scan https://api.deepseek.com/v1/chat/completions -k sk-xxx -p LLM01,LLM07

        # Quick scan with limited attacks
        deepllm scan https://api.example.com/v1/chat -k xxx --max-attacks 5
    """
    from src.core.controller import Scanner, ScanConfig

    # Parse plugins
    plugin_list = None
    if plugins:
        plugin_list = [p.strip() for p in plugins.split(",")]

    # Build config
    config = ScanConfig(
        target_url=target_url,
        api_key=api_key,
        model=model,
        scan_mode=mode,
        plugins=plugin_list,
        max_attacks_per_plugin=max_attacks,
        llm_model_path=llm_model,
        output_path=output,
        verbose=verbose,
    )

    # Run scanner
    scanner = Scanner(config)
    report = scanner.run()

    # Exit with appropriate code
    if not report.get("success", False):
        raise SystemExit(1)


@main.command()
def plugins() -> None:
    """List available security plugins.

    Shows all registered OWASP LLM security testing plugins.
    """
    from src.plugins.registry import get_registry

    registry = get_registry()
    registry.auto_discover()

    available = registry.list_plugins()

    if not available:
        console.print("[yellow]No plugins registered.[/yellow]")
        console.print("\nMake sure plugin modules are installed in src/plugins/")
        return

    # Create table
    table = Table(title="Available Security Plugins", show_header=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="green")
    table.add_column("Category", style="yellow")
    table.add_column("Status")
    table.add_column("Description")

    for plugin in available:
        status_color = "green" if plugin["status"] == "enabled" else "red"
        table.add_row(
            plugin["id"],
            plugin["name"],
            plugin["category"],
            f"[{status_color}]{plugin['status']}[/{status_color}]",
            plugin["description"][:50] + "..." if len(plugin["description"]) > 50 else plugin["description"],
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(available)} plugins[/dim]")


@main.command()
@click.option(
    "--api-key", "-k",
    envvar="LLM_API_KEY",
    help="API key (or set LLM_API_KEY env var)"
)
def interactive(api_key: Optional[str]) -> None:
    """Interactive scan mode with guided setup.

    Walks through scan configuration step by step.
    """
    console.print(Panel.fit(
        "[bold blue]DeepLLMScanner[/bold blue] - Interactive Mode\n"
        "This wizard will guide you through setting up a security scan.",
        title="Welcome"
    ))

    # Step 1: Target URL
    console.print("\n[bold cyan]Step 1: Target Configuration[/bold cyan]")
    target_url = Prompt.ask(
        "Enter target API URL",
        default="https://api.openai.com/v1/chat/completions",
    )

    # Step 2: API Key
    if not api_key:
        api_key = Prompt.ask(
            "Enter API key (or press Enter to skip)",
            password=True,
            default="",
        )
        if not api_key:
            api_key = None

    # Step 3: Model
    model = Prompt.ask(
        "Enter model name",
        default="gpt-3.5-turbo",
    )

    # Step 4: Scan mode
    console.print("\n[bold cyan]Step 2: Scan Mode[/bold cyan]")
    console.print("  [yellow]quick[/yellow]     - Fast scan, basic attacks (recommended for testing)")
    console.print("  [yellow]standard[/yellow]  - Balanced scan, more attack variations")
    console.print("  [yellow]deep[/yellow]      - Thorough scan, all attack vectors")
    mode = Prompt.ask(
        "Select scan mode",
        choices=["quick", "standard", "deep"],
        default="quick",
    )

    # Step 5: Plugin selection
    console.print("\n[bold cyan]Step 3: Plugin Selection[/bold cyan]")
    from src.plugins.registry import get_registry
    registry = get_registry()
    registry.auto_discover()
    available_plugins = registry.list_plugins()

    if available_plugins:
        console.print("\nAvailable plugins:")
        for p in available_plugins:
            console.print(f"  [cyan]{p['id']}[/cyan] - {p['name']}")

        select_all = Confirm.ask("Run all plugins?", default=True)

        if select_all:
            selected_plugins = None
        else:
            plugin_input = Prompt.ask(
                "Enter plugin IDs (comma-separated, e.g., LLM01,LLM02)",
                default=",".join(p["id"] for p in available_plugins[:2]),
            )
            selected_plugins = [p.strip() for p in plugin_input.split(",")]
    else:
        console.print("[yellow]No plugins available.[/yellow]")
        selected_plugins = None

    # Step 6: Attack limit
    console.print("\n[bold cyan]Step 4: Attack Settings[/bold cyan]")
    max_attacks = IntPrompt.ask(
        "Maximum attacks per plugin",
        default=5,
    )

    # Step 7: Output
    console.print("\n[bold cyan]Step 5: Output[/bold cyan]")
    save_report = Confirm.ask("Save report to file?", default=False)
    output_path = None
    if save_report:
        output_path = Prompt.ask(
            "Output file path",
            default="scan_report.json",
        )

    # Confirmation
    console.print("\n" + "=" * 50)
    console.print("[bold]Configuration Summary:[/bold]")
    console.print(f"  Target URL: {target_url}")
    console.print(f"  Model: {model}")
    console.print(f"  Scan Mode: {mode}")
    console.print(f"  Plugins: {'All' if selected_plugins is None else ', '.join(selected_plugins)}")
    console.print(f"  Max Attacks/Plugin: {max_attacks}")
    if output_path:
        console.print(f"  Output: {output_path}")
    console.print("=" * 50)

    if not Confirm.ask("\nStart scan?", default=True):
        console.print("[yellow]Scan cancelled.[/yellow]")
        return

    # Run scan
    from src.core.controller import Scanner, ScanConfig

    config = ScanConfig(
        target_url=target_url,
        api_key=api_key,
        model=model,
        scan_mode=mode,
        plugins=selected_plugins,
        max_attacks_per_plugin=max_attacks,
        output_path=output_path,
    )

    scanner = Scanner(config)
    report = scanner.run()

    # Show next steps
    if report.get("vulnerabilities"):
        console.print(f"\n[yellow]![/yellow] Found {len(report['vulnerabilities'])} potential vulnerabilities!")
        console.print("Review the details above and consider remediation.")


@main.command()
def check() -> None:
    """Check system requirements and configuration."""
    from rich.table import Table

    console.print("\n[bold]System Check[/bold]\n")

    table = Table(show_header=True)
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details")

    # Check Python version
    import sys
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 10)
    table.add_row(
        "Python",
        "[green]OK[/green]" if py_ok else "[red]Failed[/red]",
        py_version
    )

    # Check llama-cpp-python
    try:
        import llama_cpp
        table.add_row("llama-cpp-python", "[green]OK[/green]", llama_cpp.__version__)
    except ImportError:
        table.add_row("llama-cpp-python", "[yellow]Optional[/yellow]", "pip install llama-cpp-python")

    # Check httpx
    try:
        import httpx
        table.add_row("httpx", "[green]OK[/green]", httpx.__version__)
    except ImportError:
        table.add_row("httpx", "[red]Required[/red]", "pip install httpx")

    # Check pydantic
    try:
        import pydantic
        table.add_row("pydantic", "[green]OK[/green]", pydantic.__version__)
    except ImportError:
        table.add_row("pydantic", "[red]Required[/red]", "pip install pydantic")

    # Check rich
    try:
        import rich
        from rich.console import Console
        table.add_row("rich", "[green]OK[/green]", "installed")
    except ImportError:
        table.add_row("rich", "[red]Required[/red]", "pip install rich")

    # Check click
    try:
        import click
        table.add_row("click", "[green]OK[/green]", "installed")
    except ImportError:
        table.add_row("click", "[red]Required[/red]", "pip install click")

    # Check yaml
    try:
        import yaml
        table.add_row("pyyaml", "[green]OK[/green]", yaml.__version__)
    except ImportError:
        table.add_row("pyyaml", "[red]Required[/red]", "pip install pyyaml")

    # Check environment variables
    table.add_row(
        "LLM_API_KEY",
        "[green]Set[/green]" if os.getenv("LLM_API_KEY") else "[yellow]Not set[/yellow]",
        "Target API key"
    )
    table.add_row(
        "LLM_MODEL_PATH",
        "[green]Set[/green]" if os.getenv("LLM_MODEL_PATH") else "[yellow]Not set[/yellow]",
        "Local model path (optional)"
    )

    # Check plugins
    try:
        from src.plugins.registry import get_registry
        registry = get_registry()
        count = registry.auto_discover()
        table.add_row("Plugins", "[green]OK[/green]", f"{count} plugins loaded")
    except Exception as e:
        table.add_row("Plugins", "[yellow]Warning[/yellow]", str(e)[:30])

    console.print(table)
    console.print()


@main.command()
@click.option(
    "--model", "-m",
    required=True,
    type=click.Path(exists=True),
    help="Path to GGUF model file"
)
@click.option(
    "--prompt", "-p",
    default="Hello! Please introduce yourself.",
    help="Test prompt"
)
def test_llm(model: str, prompt: str) -> None:
    """Test local LLM model loading and inference.

    Example:
        deepllm test-llm -m ./models/llama-3-8b.Q4_K_M.gguf -p "Hello"
    """
    from src.runtime.llm_runtime import LLMLoader, LLMInference
    from src.runtime.llm_runtime.loader import LLMConfig

    console.print(f"\n[cyan]Loading model:[/cyan] {model}")

    try:
        # Load model
        config = LLMConfig(model_path=model)
        loader = LLMLoader(config)

        console.print("[cyan]Initializing model...[/cyan]")
        loader.load()

        # Create inference
        inference = LLMInference(loader)

        console.print(f"\n[cyan]Prompt:[/cyan] {prompt}")
        console.print("[cyan]Generating response...[/cyan]\n")

        # Generate
        result = inference.generate(prompt, max_tokens=100)

        console.print(f"[green]Response:[/green] {result.text}")
        console.print(f"\n[dim]Tokens: {result.tokens_generated}, Reason: {result.finish_reason}[/dim]")

        # Cleanup
        loader.unload()
        console.print("\n[green]+[/green] Test completed successfully")

    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
