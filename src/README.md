# src/

DeepLLMScanner 源码目录 - CPU-only 可运行 · 本地 7B-13B 4bit 模型增强 · 多层检测 + 验证驱动 · 覆盖 OWASP LLM Top 10

## 目录结构

```
src/
├── core/                           # 核心引擎
│   ├── controller/                 # 扫描控制器 - 协调各引擎
│   │   ├── __init__.py
│   │   ├── scanner.py              # 主扫描器
│   │   └── config.py               # 扫描配置
│   ├── scheduler/                  # 调度器 - 任务编排
│   │   ├── __init__.py
│   │   ├── scheduler.py
│   │   └── task.py
│   ├── attack_engine/              # 攻击引擎 - 生成攻击载荷
│   │   ├── __init__.py
│   │   ├── engine.py               # 攻击生成引擎
│   │   ├── mutation.py             # 变异规则
│   │   └── evolver.py              # 进化机制
│   ├── state_engine/               # 状态引擎 - 多轮对话状态管理
│   │   ├── __init__.py
│   │   ├── session.py              # 会话管理
│   │   └── context.py              # 上下文管理
│   ├── execution_engine/           # 执行引擎 - HTTP 调用
│   │   ├── __init__.py
│   │   ├── client.py               # HTTP 客户端
│   │   ├── retry.py                # 重试机制
│   │   └── statistics.py           # 执行统计
│   ├── detection_engine/           # 检测引擎 - 漏洞识别
│   │   ├── __init__.py
│   │   ├── engine.py               # 检测引擎主类
│   │   ├── rules.py                # L1: 规则检测
│   │   ├── embedding.py            # L2: Embedding 检测
│   │   └── llm.py                  # L3: LLM 裁决
│   ├── validation_engine/          # 验证引擎 - 二次确认
│   │   ├── __init__.py
│   │   ├── validator.py            # 验证器
│   │   └── confirmation.py         # 确认机制
│   ├── scoring_engine/             # 评分引擎 - 风险计算
│   │   ├── __init__.py
│   │   ├── scorer.py               # 风险评分器
│   │   └── formula.py              # 评分公式
│   └── reporting/                  # 报告生成 - 输出格式化
│       ├── __init__.py
│       ├── generator.py            # 报告生成器
│       ├── json_exporter.py        # JSON 输出
│       └── html_exporter.py        # HTML 输出
│
├── runtime/                        # 运行时
│   ├── llm_runtime/                # LLM 模型运行时
│   │   ├── __init__.py
│   │   ├── loader.py               # 模型加载器
│   │   ├── inference.py            # 推理接口
│   │   └── cache.py                # 缓存管理
│   └── embedding_runtime/          # Embedding 运行时
│       ├── __init__.py
│       ├── encoder.py              # Embedding 编码器
│       └── similarity.py           # 相似度计算
│
├── plugins/                        # OWASP LLM Top 10 插件
│   ├── __init__.py
│   ├── base.py                     # 插件基类
│   ├── registry.py                 # 插件注册中心
│   ├── LLM01_prompt_injection/     # 提示注入
│   │   ├── __init__.py
│   │   ├── plugin.py
│   │   ├── templates.py
│   │   └── rules.py
│   ├── LLM02_data_leak/            # 敏感信息泄露
│   ├── LLM03_supply_chain/         # 供应链安全
│   ├── LLM04_data_poisoning/       # 数据投毒
│   ├── LLM05_output_handling/      # 输出处理不当
│   ├── LLM06_excessive_agency/     # 过度代理
│   ├── LLM07_system_prompt_leak/   # 系统提示泄露
│   ├── LLM08_vector_weakness/      # 向量与嵌入弱点
│   ├── LLM09_misinformation/       # 虚假信息
│   └── LLM10_unbounded_consumption/# 无限制消费
│
├── templates/                      # 攻击模板库
│   ├── prompt_injection/
│   │   ├── basic.yaml
│   │   ├── jailbreak.yaml
│   │   └── role_play.yaml
│   ├── data_leak/
│   ├── system_prompt_leak/
│   └── ...
│
├── rules/                          # 检测规则库
│   ├── patterns.yaml               # 正则模式
│   ├── keywords.yaml               # 关键词列表
│   ├── sensitive_data.yaml         # 敏感数据模式
│   └── ...
│
└── configs/                        # 配置文件
    ├── default.yaml                # 默认配置
    ├── models.yaml                 # 模型配置
    └── modes/                      # 扫描模式配置
        ├── quick.yaml
        ├── standard.yaml
        └── deep.yaml
```

## 核心目录说明

### core/ - 核心引擎

| 目录 | 职责 | 阶段 |
|------|------|------|
| `controller/` | 扫描生命周期管理，协调各引擎工作 | Phase 0 |
| `scheduler/` | 任务调度、并发控制、优先级管理 | Phase 1 |
| `attack_engine/` | 攻击载荷生成：模板加载、变异、LLM 增强 | Phase 1 |
| `state_engine/` | 多轮对话状态追踪、上下文管理 | Phase 2 |
| `execution_engine/` | HTTP 请求执行、重试、超时、统计 | Phase 0 |
| `detection_engine/` | 三层检测：规则 → Embedding → LLM | Phase 1 |
| `validation_engine/` | 漏洞确认、误报过滤 | Phase 1 |
| `scoring_engine/` | 风险评分计算 | Phase 1 |
| `reporting/` | 报告生成：JSON/HTML | Phase 1 |

### runtime/ - 运行时

| 目录 | 职责 | 阶段 |
|------|------|------|
| `llm_runtime/` | LLM 模型加载、推理、缓存 | Phase 0 |
| `embedding_runtime/` | Embedding 编码、相似度计算 | Phase 2 |

### plugins/ - 插件系统

| 目录 | OWASP 风险 | 阶段 |
|------|------------|------|
| `LLM01_prompt_injection/` | 提示注入 | Phase 1 |
| `LLM02_data_leak/` | 敏感信息泄露 | Phase 1 |
| `LLM03_supply_chain/` | 供应链安全 | Phase 2 |
| `LLM04_data_poisoning/` | 数据与模型投毒 | Phase 2 |
| `LLM05_output_handling/` | 输出处理不当 | Phase 2 |
| `LLM06_excessive_agency/` | 过度代理 | Phase 2 |
| `LLM07_system_prompt_leak/` | 系统提示泄露 | Phase 1 |
| `LLM08_vector_weakness/` | 向量与嵌入弱点 | Phase 2 |
| `LLM09_misinformation/` | 虚假信息 | Phase 2 |
| `LLM10_unbounded_consumption/` | 无限制消费 | Phase 2 |

### templates/ - 攻击模板

按风险类型组织的攻击模板，YAML 格式，支持变量替换。

### rules/ - 检测规则

- `patterns.yaml` - 正则表达式模式
- `keywords.yaml` - 敏感关键词
- `sensitive_data.yaml` - 敏感数据特征

### configs/ - 配置文件

- `default.yaml` - 默认扫描配置
- `models.yaml` - 模型路径和参数
- `modes/` - 各扫描模式配置 (quick/standard/deep)

## 开发阶段

| 阶段 | 目标 | 重点模块 |
|------|------|----------|
| Phase 0 | 基础运行层 | llm_runtime, execution_engine, controller |
| Phase 1 | MVP 扫描器 | plugin_system, attack_engine, detection, validation, scoring, reporting |
| Phase 2 | 增强能力 | state_engine, embedding_runtime, detection_L2, LLM03-10 插件 |
| Phase 3 | 高级能力 | 进化算法, HTML 报告, 仪表板 |

## 说明

- 详细架构设计见 `docs/ROADMAP.md`
- 模块定义见 `.claude/PROJECT.md`
- 当前开发目标见 `docs/CURRENT_GOAL.md`
