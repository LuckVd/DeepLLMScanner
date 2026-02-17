"""CLI entry point for DeepLLMScanner."""

import os
from typing import Optional

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="deepllm")
def main() -> None:
    """DeepLLMScanner - CPU-only LLM DAST Framework."""
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
    help="Scan mode"
)
@click.option(
    "--llm-model",
    envvar="LLM_MODEL_PATH",
    help="Path to local GGUF model for enhanced detection"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path for report"
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
    llm_model: Optional[str],
    output: Optional[str],
    verbose: bool,
) -> None:
    """Run a security scan on the target LLM API.

    TARGET_URL: The LLM API endpoint to scan.
    """
    from src.core.controller import Scanner, ScanConfig

    # Build config
    config = ScanConfig(
        target_url=target_url,
        api_key=api_key,
        model=model,
        scan_mode=mode,
        llm_model_path=llm_model,
        output_path=output,
        verbose=verbose,
    )

    # Run scanner
    scanner = Scanner(config)
    report = scanner.run()

    # Exit with appropriate code
    if not report.get("connection_test", {}).get("success", False):
        raise SystemExit(1)


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
        "[green]✓ OK[/green]" if py_ok else "[red]✗ Failed[/red]",
        py_version
    )

    # Check llama-cpp-python
    try:
        import llama_cpp
        table.add_row("llama-cpp-python", "[green]✓ OK[/green]", llama_cpp.__version__)
    except ImportError:
        table.add_row("llama-cpp-python", "[red]✗ Not installed[/red]", "pip install llama-cpp-python")

    # Check httpx
    try:
        import httpx
        table.add_row("httpx", "[green]✓ OK[/green]", httpx.__version__)
    except ImportError:
        table.add_row("httpx", "[red]✗ Not installed[/red]", "pip install httpx")

    # Check pydantic
    try:
        import pydantic
        table.add_row("pydantic", "[green]✓ OK[/green]", pydantic.__version__)
    except ImportError:
        table.add_row("pydantic", "[red]✗ Not installed[/red]", "pip install pydantic")

    # Check rich
    try:
        import rich
        table.add_row("rich", "[green]✓ OK[/green]", rich.__version__)
    except ImportError:
        table.add_row("rich", "[red]✗ Not installed[/red]", "pip install rich")

    # Check environment variables
    table.add_row(
        "LLM_API_KEY",
        "[green]✓ Set[/green]" if os.getenv("LLM_API_KEY") else "[yellow]○ Not set[/yellow]",
        "Target API key"
    )
    table.add_row(
        "LLM_MODEL_PATH",
        "[green]✓ Set[/green]" if os.getenv("LLM_MODEL_PATH") else "[yellow]○ Not set[/yellow]",
        "Local model path"
    )

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
        console.print("\n[green]✓ Test completed successfully[/green]")

    except Exception as e:
        console.print(f"\n[red]✗ Error:[/red] {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
