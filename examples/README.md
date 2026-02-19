# DeepLLMScanner Examples

This directory contains example configurations and usage patterns.

## Quick Start

### Basic Scan

```bash
# Using CLI
python -m src.cli scan --url https://api.example.com/v1/chat --api-key your-key

# Or using the config file
python -m src.cli scan --config examples/config.yaml
```

### With Local Model

```bash
python -m src.cli scan \
  --url https://api.example.com/v1/chat \
  --api-key your-key \
  --model-path ./models/qwen2.5-7b-instruct-q3_k_m.gguf
```

### Specific Plugins Only

```bash
python -m src.cli scan \
  --url https://api.example.com/v1/chat \
  --api-key your-key \
  --plugins llm01,llm07
```

### HTML Report

```bash
python -m src.cli scan \
  --url https://api.example.com/v1/chat \
  --api-key your-key \
  --output report.html \
  --format html
```

## Programmatic Usage

```python
from src.core.controller.scanner import Scanner
from src.core.controller.config import ScanConfig

# Create configuration
config = ScanConfig(
    target_url="https://api.example.com/v1/chat/completions",
    api_key="your-api-key",
    model="gpt-3.5-turbo",
    scan_mode="quick",
    max_attacks_per_plugin=10,
    output_format="json",
    output_path="report.json",
)

# Run scanner
scanner = Scanner(config)
report = scanner.run()

# Access results
print(f"Found {len(report.get('vulnerabilities', []))} vulnerabilities")
```

## Available Plugins

| ID | Name | OWASP Category |
|----|------|----------------|
| llm01_prompt_injection | Prompt Injection | LLM01 |
| llm02_data_leak | Data Leak | LLM02 |
| llm03_supply_chain | Supply Chain | LLM03 |
| llm04_data_poisoning | Data Poisoning | LLM04 |
| llm05_output_handling | Output Handling | LLM05 |
| llm06_excessive_agency | Excessive Agency | LLM06 |
| llm07_system_prompt_leak | System Prompt Leak | LLM07 |
| llm08_vector_weakness | Vector Weakness | LLM08 |
| llm09_misinformation | Misinformation | LLM09 |
| llm10_unbounded_consumption | Unbounded Consumption | LLM10 |

## Scan Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| quick | Fast scan with basic tests | CI/CD, quick checks |
| standard | Balanced scan with more tests | Regular security testing |
| deep | Thorough scan with all tests | Full security audits |
