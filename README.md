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
│   │   ├── llm_runtime/          # Local LLM runtime (llama.cpp)
│   │   └── embedding_runtime/    # Embedding runtime (sentence-transformers)
│   └── plugins/                  # OWASP LLM Top 10 plugins
│       ├── LLM01_prompt_injection/
│       ├── LLM02_data_leak/
│       ├── ...
│       └── LLM10_unbounded_consumption/
├── tests/
│   ├── test_e2e.py              # End-to-end tests
│   ├── test_state_engine.py     # State engine tests
│   ├── test_embedding_runtime.py # Embedding runtime tests
│   └── ...
├── examples/
│   └── config.yaml              # Example configuration
└── docs/
```

## Detection Layers

DeepLLMScanner uses a multi-layer detection system:

| Layer | Method | Description |
|-------|--------|-------------|
| L1 | Rule-based | Regex patterns and keyword matching |
| L2 | Embedding-based | Semantic similarity using sentence-transformers |
| L3 | LLM-based | Intelligent judgment using local LLM |

## Validation System

DeepLLMScanner includes a multi-attempt stability validation system to reduce false positives:

### Stability Validation

```python
from src.core.validation_engine import StabilityValidator, StabilityConfig, ValidationStrategy

# Configure validation
config = StabilityConfig(
    min_validations=2,           # Minimum attempts
    max_validations=3,           # Maximum attempts
    required_consistency=0.66,   # 2/3 must succeed
    strategy=ValidationStrategy.HYBRID,  # REPLAY, VARIANT, HYBRID, PROGRESSIVE
)

validator = StabilityValidator(config=config, executor=execute_func)

# Validate a detected vulnerability
result = validator.validate_stability(
    attack_result=original_result,
    detector=detect_func,
    variant_generator=gen_variants,  # Optional
    mode="standard",  # quick, standard, deep
)

# Check results
if result.is_stable:
    print(f"Confirmed vulnerability with {result.confidence:.0%} confidence")
elif result.is_false_positive:
    print("False positive - could not reproduce")
else:
    print(f"Unstable - needs review ({result.consistency:.0%} consistency)")
```

### Stability Levels

| Level | Description | Consistency |
|-------|-------------|-------------|
| STABLE | Consistently reproducible | >= 66% |
| UNSTABLE | Inconsistently reproducible | 50-65% |
| FLAKY | Rarely reproducible | < 50% |
| FALSE_POSITIVE | Not reproducible | 0% |

### Validation Strategies

| Strategy | Description |
|----------|-------------|
| REPLAY | Re-execute same attack multiple times |
| VARIANT | Use attack variants for validation |
| HYBRID | Mix of replay and variant (default) |
| PROGRESSIVE | Increase attempts if unstable |

### Embedding Runtime (L2 Detection)

The embedding_runtime module provides semantic similarity analysis:

```python
from src.runtime.embedding_runtime import EmbeddingLoader, SimilarityCalculator

# Load embedding model
loader = EmbeddingLoader()
loader.load()  # Uses all-MiniLM-L6-v2 by default

# Calculate similarity
calc = SimilarityCalculator(loader)
score = calc.compute_similarity("system prompt", response_text)

# Check if texts are semantically similar
result = calc.is_similar("secret key", response, threshold=0.75)
print(f"Similar: {result.is_similar}, Score: {result.score:.3f}")

# Index and search corpus
calc.index_corpus(["text1", "text2", "text3"])
matches = calc.find_similar("query", threshold=0.7, top_k=5)
```

**Default Model:** `all-MiniLM-L6-v2` (384 dimensions, CPU-friendly)

## Development Status

| Phase | Goal | Status |
|-------|------|--------|
| Phase 0 | Basic Runtime Layer | Completed |
| Phase 1 | MVP Scanner (LLM01/02/07) | Completed |
| Phase 2 | Multi-turn Attacks + Full Coverage | Completed |
| Phase 2.5 | CLI + E2E Integration Tests | Completed |
| Phase 3 | Advanced Capabilities + Evolution | In Progress |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | Target LLM API key |
| `LLM_MODEL_PATH` | Local GGUF model path |
| `LLM_N_CTX` | Context window size (default: 4096) |
| `LLM_N_THREADS` | CPU threads (default: 8) |
| `EMBEDDING_MODEL` | Embedding model name (default: all-MiniLM-L6-v2) |

## Dependencies

### Core Dependencies
- `llama-cpp-python` - Local LLM inference
- `sentence-transformers` - Embedding model for L2 detection (optional)
- `aiohttp` - Async HTTP client
- `rich` - CLI output formatting

### Optional Dependencies
- `sentence-transformers` - Required for L2 (Embedding) detection layer

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

# Current test coverage: 333 passed, 8 skipped
```

## License

MIT
