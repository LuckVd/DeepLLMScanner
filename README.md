# DeepLLMScanner

> CPU-only 可运行 | 本地 7B-13B 4bit 模型增强 | 多层检测 + 验证驱动 | 覆盖 OWASP LLM Top 10

DeepLLMScanner 是一个面向 LLM 应用安全的动态安全测试（DAST）框架。

## 特性

- **CPU-only** - 无需 GPU，在普通服务器上即可运行
- **本地模型增强** - 使用本地 LLM 进行智能攻击生成和响应分析
- **多层检测** - 规则 + Embedding + LLM 三层检测体系
- **验证驱动** - 反向验证降低误报率
- **OWASP LLM Top 10** - 覆盖全部 10 类 LLM 安全风险

## 安装

```bash
# 克隆仓库
git clone https://github.com/your-org/DeepLLMScanner.git
cd DeepLLMScanner

# 安装依赖
pip install -e .

# 或安装开发依赖
pip install -e ".[dev]"
```

## 快速开始

### 1. 检查系统环境

```bash
deepllm check
```

### 2. 测试本地模型（可选）

```bash
# 设置模型路径
export LLM_MODEL_PATH=/path/to/your/model.gguf

# 测试模型加载
deepllm test-llm -m /path/to/model.gguf
```

### 3. 运行扫描

```bash
# 基础扫描
deepllm scan https://api.openai.com/v1/chat/completions \
  --api-key $LLM_API_KEY \
  --model gpt-3.5-turbo

# 使用本地模型增强
deepllm scan https://api.openai.com/v1/chat/completions \
  --api-key $LLM_API_KEY \
  --llm-model ./models/llama-3-8b.Q4_K_M.gguf \
  --output report.json
```

## 项目结构

```
DeepLLMScanner/
├── src/
│   ├── core/
│   │   ├── controller/      # 扫描控制器
│   │   ├── execution_engine/ # HTTP 执行引擎
│   │   ├── detection_engine/ # 检测引擎 (L1/L2/L3)
│   │   ├── validation_engine/ # 验证引擎
│   │   └── ...
│   ├── runtime/
│   │   ├── llm_runtime/     # 本地 LLM 运行时
│   │   └── embedding_runtime/ # Embedding 运行时
│   ├── plugins/             # OWASP LLM Top 10 插件
│   └── deepllm_scanner/     # CLI 入口
├── tests/
└── docs/
```

## 开发阶段

| 阶段 | 目标 | 状态 |
|------|------|------|
| Phase 0 | 基础运行层 | ✅ 完成 |
| Phase 1 | MVP 扫描器 (LLM01/02/07) | 🚧 进行中 |
| Phase 2 | 增强能力 + 全风险覆盖 | 📋 计划中 |
| Phase 3 | 高级能力 + 进化算法 | 📋 计划中 |

## 环境变量

| 变量 | 描述 |
|------|------|
| `LLM_API_KEY` | 目标 LLM API 密钥 |
| `LLM_MODEL_PATH` | 本地 GGUF 模型路径 |
| `LLM_N_CTX` | 上下文窗口大小（默认 4096） |
| `LLM_N_THREADS` | CPU 线程数（默认 8） |

## License

MIT
