# DeepLLMScanner

> CPU-only | Local 7B-13B 4bit Model Enhanced | Multi-layer Detection | OWASP LLM Top 10 Coverage

DeepLLMScanner is a Dynamic Application Security Testing (DAST) framework for LLM applications.

## Features

- **CPU-only** - No GPU required, runs on standard servers
- **Local LLM Enhanced** - Uses local models for intelligent attack generation and response analysis
- **Multi-layer Detection** - Rule + Embedding + LLM three-tier detection system
- **Validation Driven** - Reverse validation to reduce false positives
- **OWASP LLM Top 10** - Covers all 10 LLM security risk categories
- **Multi-turn Attacks** - State engine for sophisticated conversation-based attacks

## Installation

```bash
# Clone repository
git clone https://github.com/LuckVd/DeepLLMScanner.git
cd DeepLLMScanner

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -e .

# Install with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

### 1. List Available Plugins

```bash
python -m src.cli list-plugins
```

### 2. Test Local Model (Optional)

```bash
python -m src.cli test-model -p ./models/qwen2.5-7b-instruct-q3_k_m.gguf
```

### 3. Test Connection

```bash
python -m src.cli test-connection -u https://api.openai.com/v1/chat/completions -k $OPENAI_API_KEY
```

### 4. Run Scan

```bash
# Basic scan
python -m src.cli scan -u https://api.openai.com/v1/chat/completions -k $OPENAI_API_KEY

# With local model for enhanced detection
python -m src.cli scan \
  -u https://api.openai.com/v1/chat/completions \
  -k $OPENAI_API_KEY \
  -p ./models/qwen2.5-7b-instruct-q3_k_m.gguf \
  -o report.html \
  -f html

# Specific plugins only
python -m src.cli scan \
  -u https://api.example.com/v1/chat \
  -k $API_KEY \
  --plugins llm01,llm07
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `scan` | Run security scan on target API |
| `list-plugins` | List all available security plugins |
| `test-connection` | Test connection to target API |
| `test-model` | Test local GGUF model loading |

### Scan Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Target API URL | Required |
| `-k, --api-key` | API key | env: OPENAI_API_KEY |
| `-m, --model` | Target model name | gpt-3.5-turbo |
| `-p, --model-path` | Local GGUF model path | None |
| `--mode` | Scan mode (quick/standard/deep) | quick |
| `--plugins` | Comma-separated plugin IDs | all |
| `-o, --output` | Output file path | stdout |
| `-f, --format` | Output format (json/html) | json |
| `-v, --verbose` | Verbose output | False |

## OWASP LLM Top 10 Coverage

| ID | Plugin | Risk Category |
|----|--------|---------------|
| LLM01 | Prompt Injection | Prompt Injection |
| LLM02 | Data Leak | Sensitive Information Disclosure |
| LLM03 | Supply Chain | Supply Chain Vulnerabilities |
| LLM04 | Data Poisoning | Data and Model Poisoning |
| LLM05 | Output Handling | Improper Output Handling |
| LLM06 | Excessive Agency | Excessive Agency |
| LLM07 | System Prompt Leak | System Prompt Leakage |
| LLM08 | Vector Weakness | Vector and Embedding Weaknesses |
| LLM09 | Misinformation | Misinformation |
| LLM10 | Unbounded Consumption | Unbounded Consumption |

## Project Structure

```
DeepLLMScanner/
├── src/
│   ├── cli.py                    # CLI entry point
│   ├── core/
│   │   ├── controller/           # Scan controller
│   │   ├── execution_engine/     # HTTP execution engine
│   │   ├── state_engine/         # Multi-turn conversation state
│   │   ├── validation_engine/    # Vulnerability validation
│   │   ├── scoring_engine/       # Risk scoring
│   │   └── reporting/            # JSON/HTML reports
│   ├── runtime/
│   │   └── llm_runtime/          # Local LLM runtime (llama.cpp)
│   └── plugins/                  # OWASP LLM Top 10 plugins
│       ├── LLM01_prompt_injection/
│       ├── LLM02_data_leak/
│       ├── ...
│       └── LLM10_unbounded_consumption/
├── tests/
│   ├── test_e2e.py              # End-to-end tests
│   ├── test_state_engine.py     # State engine tests
│   └── ...
├── examples/
│   └── config.yaml              # Example configuration
└── docs/
```

## Development Status

| Phase | Goal | Status |
|-------|------|--------|
| Phase 0 | Basic Runtime Layer | Completed |
| Phase 1 | MVP Scanner (LLM01/02/07) | Completed |
| Phase 2 | Multi-turn Attacks + Full Coverage | Completed |
| Phase 3 | Advanced Capabilities + Evolution | Planned |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | Target LLM API key |
| `LLM_MODEL_PATH` | Local GGUF model path |
| `LLM_N_CTX` | Context window size (default: 4096) |
| `LLM_N_THREADS` | CPU threads (default: 8) |

## Recommended Local Models

| Model | Size | Memory | Notes |
|-------|------|--------|-------|
| Qwen2.5-7B-Instruct Q3_K_M | ~3.6 GB | ~5 GB | Good balance |
| Mistral-7B-Instruct Q4_K_M | ~4.1 GB | ~6 GB | High accuracy |
| Llama-2-7B-Chat Q4_K_M | ~3.8 GB | ~5.5 GB | Stable |

## Testing

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_e2e.py -v

# Run with coverage
pytest tests/ --cov=src
```

## License

MIT
