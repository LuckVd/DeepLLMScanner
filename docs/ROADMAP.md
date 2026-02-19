# DeepLLMScanner 项目路线图

> CPU-only 可运行 | 本地 7B-13B 4bit 模型增强 | 多层检测 + 验证驱动 | 覆盖 OWASP LLM Top 10

---

## 一、项目目标

| 目标 | 描述 |
|------|------|
| CPU-only 可运行 | 无需 GPU，在普通服务器上运行 |
| 本地模型增强 | 7B-13B 4bit 量化模型进行攻击生成和裁决 |
| 多层检测 + 验证驱动 | 规则/Embedding/LLM 三层检测 + 反向验证 |
| 覆盖 OWASP LLM Top 10 | 全部 10 类 LLM 安全风险 |
| 可作为 Sprint 拆分依据 | 清晰的 Phase 和任务分解 |

---

## 二、系统总体架构

```
DeepLLMScanner
│
├── core
│   ├── controller          # 扫描控制器
│   ├── scheduler           # 任务调度器
│   ├── attack_engine       # 攻击生成引擎
│   ├── state_engine        # 多轮对话状态管理
│   ├── execution_engine    # HTTP 执行引擎
│   ├── detection_engine    # 检测引擎 (L1/L2/L3)
│   ├── validation_engine   # 验证引擎
│   ├── scoring_engine      # 风险评分引擎
│
├── runtime
│   ├── llm_runtime         # 本地 LLM 运行时 (llama.cpp)
│   └── embedding_runtime   # Embedding 运行时
│
├── plugins
│   ├── LLM01_prompt_injection
│   ├── LLM02_data_leak
│   ├── LLM03_supply_chain
│   ├── LLM04_data_poisoning
│   ├── LLM05_output_handling
│   ├── LLM06_excessive_agency
│   ├── LLM07_system_prompt_leak
│   ├── LLM08_vector_weakness
│   ├── LLM09_misinformation
│   └── LLM10_unbounded_consumption
│
└── reporting               # 报告生成模块
```

---

## 三、功能拆解总表

### 核心功能表

| 一级模块 | 二级功能 | 描述 | 必要性 | 阶段 |
|----------|----------|------|--------|------|
| Controller | 配置加载 | 解析扫描参数 | 必须 | Phase 1 |
| Controller | 插件注册 | 自动加载风险插件 | 必须 | Phase 1 |
| Scheduler | 风险调度 | 控制扫描顺序 | 必须 | Phase 1 |
| Attack Engine | 模板攻击生成 | 基础攻击构造 | 必须 | Phase 1 |
| Attack Engine | Prompt 变异 | 语义扰动 | 必须 | Phase 1 |
| Attack Engine | LLM 攻击增强 | 隐蔽攻击 | 重要 | Phase 2 |
| Attack Engine | 进化算法 | 优选攻击 | 高级 | Phase 3 |
| State Engine | 多轮对话 | 上下文维持 | 必须 | Phase 2 |
| Execution Engine | HTTP 执行 | 请求发送 | 必须 | Phase 1 |
| Execution Engine | 并发控制 | 线程池 | 重要 | Phase 2 |
| Detection L1 | 规则检测 | regex + 关键词 | 必须 | Phase 1 |
| Detection L2 | Embedding 检测 | 相似度分析 | 重要 | Phase 2 |
| Detection L3 | LLM 裁决 | JSON 判断漏洞 | 必须 | Phase 1 |
| Validation | 漏洞复现 | 重放攻击 | 必须 | Phase 1 |
| Validation | 变体验证 | 稳定性确认 | 重要 | Phase 2 |
| Scoring | 风险评分 | 计算风险值 | 必须 | Phase 1 |
| Reporting | JSON 报告 | 输出结果 | 必须 | Phase 1 |
| Reporting | HTML 报告 | 可视化 | 可选 | Phase 3 |
| Plugin System | 插件标准接口 | 风险扩展机制 | 必须 | Phase 1 |
| Runtime | 本地 LLM 加载 | llama.cpp 运行 | 必须 | Phase 1 |
| Runtime | Embedding 加载 | 向量生成 | 重要 | Phase 2 |

---

## 四、OWASP LLM Top 10 插件实现

| 插件 | 风险类型 | 实现重点 |
|------|----------|----------|
| LLM01 | Prompt Injection | 单轮 + 多轮 + 延迟注入 |
| LLM02 | 数据泄露 | PII 检测 + LLM 真实性确认 |
| LLM03 | 供应链风险 | 版本与依赖暴露 |
| LLM04 | 数据投毒 | 污染传播验证 |
| LLM05 | 输出处理不当 | 危险代码生成 |
| LLM06 | 过度代理 | function_call 越权 |
| LLM07 | 系统提示泄露 | Embedding 比对 |
| LLM08 | 向量数据库弱点 | Metadata 泄露 |
| LLM09 | 错误信息 | 一致性分析 |
| LLM10 | 无界消耗 | Token 放大曲线 |

---

## 五、扫描模式定义

| 模式 | 攻击层级 | 检测层级 | 验证 | 适用场景 |
|------|----------|----------|------|----------|
| **quick** | 单轮 | L1 | 无 | CI/CD 快速检查 |
| **standard** | 多轮 | L1 + L2 + L3 | 单次 | 常规安全测试 |
| **deep** | 进化 + 多轮 | 全部 | 多次 | 全面安全审计 |

---

## 六、风险评分公式

```
risk_score = severity_weight × confidence × reproducibility × impact_factor

参数说明：
- severity_weight: 严重程度权重 (OWASP 类别固有)
- confidence: 检测置信度 (0.0 - 1.0)
- reproducibility: 可复现性 (验证结果)
- impact_factor: 影响因子 (根据响应内容评估)
```

### 风险等级划分

| 分数范围 | 等级 | 处理优先级 |
|----------|------|------------|
| 0-25 | Low | P3 |
| 25-50 | Medium | P2 |
| 50-75 | High | P1 |
| 75-100 | Critical | P0 |

---

## 七、开发顺序总表

### Phase 0：基础运行层 ✅ COMPLETED

**目标**：能调用目标 API，能调用本地模型，能打印结果

| 顺序 | 模块 | 目标 | 产出 | 状态 |
|------|------|------|------|------|
| 1 | llm_runtime | 本地模型加载成功 | 可调用推理接口 | done |
| 2 | execution_engine | HTTP 请求成功 | 可返回响应 | done |
| 3 | controller | 配置读取成功 | CLI 运行入口 | done |

**完成标志**：
- [x] 能调用目标 API
- [x] 能调用本地模型
- [x] 能打印结果

---

### Phase 1：最小可用扫描器 ✅ COMPLETED

**目标**：实现 LLM01/02/07 + JSON 报告

| 顺序 | 模块 | 内容 | 状态 |
|------|------|------|------|
| 4 | plugin_system | 插件接口标准 | done |
| 5 | attack_engine | 基础模板攻击 | done |
| 6 | detection_L1 | regex 检测 | done |
| 7 | detection_L3 | LLM 裁决 | done |
| 8 | validation_engine | 漏洞重放 | done |
| 9 | scoring_engine | 风险计算 | done |
| 10 | reporting | JSON 输出 | done |
| 11 | LLM01 插件 | Prompt Injection | done |
| 12 | LLM02 插件 | 数据泄露 | done |
| 13 | LLM07 插件 | 系统提示泄露 | done |

**完成标志**：
- [x] 可扫描 3 类风险
- [x] 可输出漏洞 JSON
- [x] 可复现漏洞

---

### Phase 2：增强能力 ✅ COMPLETED

**目标**：多轮攻击 + Embedding 检测 + 全 10 类覆盖

| 顺序 | 模块 | 内容 | 状态 |
|------|------|------|------|
| 14 | state_engine | 多轮对话 | done |
| 15 | detection_L2 | Embedding 检测 | done |
| 16 | embedding_runtime | 向量生成 | done |
| 17 | 变异引擎 | Prompt 多策略扰动 | done |
| 18 | 并发控制 | 扫描加速 | done |
| 19 | LLM03-LLM06 插件 | 风险实现 | done |
| 20 | LLM08-LLM10 插件 | 风险实现 | done |

**完成标志**：
- [x] 覆盖 OWASP LLM Top 10
- [x] 支持 standard 模式

---

### Phase 2.5：CLI + E2E 集成测试 ✅ COMPLETED

**目标**：CLI 接口 + 端到端集成测试

| 顺序 | 模块 | 内容 | 状态 |
|------|------|------|------|
| 21 | CLI 入口 | scan, list-plugins, test-connection, test-model | done |
| 22 | E2E 测试 | 25 个端到端集成测试 | done |
| 23 | 示例文档 | examples/config.yaml + README | done |

**完成标志**：
- [x] CLI 命令可用
- [x] 280+ 测试全部通过
- [x] 文档完善

---

### Phase 3：高级能力 🔄 IN PROGRESS

**目标**：deep 模式 + 攻击进化

| 顺序 | 模块 | 内容 | 状态 |
|------|------|------|------|
| 21 | 进化算法模块 | 攻击优选 | todo |
| 22 | 多次稳定验证 | 减少误报 | todo |
| 23 | 成本放大检测 | LLM10 增强 | todo |
| 24 | HTML 报告 | 可视化输出 | todo |
| 25 | 扫描统计仪表板 | 综合评分 | todo |

**完成标志**：
- [ ] deep 模式可运行
- [ ] 生成完整报告
- [ ] 可商业化展示

---

## 八、整体开发节奏

```
Week 1        Phase 0: 基础运行层 ✅
Week 2-3      Phase 1: MVP 扫描器 (LLM01/02/07) ✅
Week 4-6      Phase 2: 全风险覆盖 + 增强能力 ✅
Week 6-7      Phase 2.5: CLI + E2E 集成测试 ✅
Week 7-8      Phase 3: 深度模式 + 进化算法 🔄 (进行中)
```

---

## 九、模块规划

| 模块 | 路径 | Status | Level |
|------|------|--------|-------|
| claude-control | `.claude/**` | done | core |
| governance-specs | `docs/api/**`, `docs/CURRENT_GOAL.md`, `docs/ROADMAP.md` | done | core |
| git-history | `docs/git/**` | done | stable |
| project-docs | `docs/*.md`, `README.md` | done | active |
| core-controller | `src/core/controller/**` | done | active |
| core-scheduler | `src/core/scheduler/**` | done | active |
| core-attack | `src/core/attack_engine/**` | done | active |
| core-state | `src/core/state_engine/**` | done | active |
| core-execution | `src/core/execution_engine/**` | done | active |
| core-detection | `src/core/detection_engine/**` | done | active |
| core-validation | `src/core/validation_engine/**` | done | active |
| core-scoring | `src/core/scoring_engine/**` | done | active |
| core-reporting | `src/core/reporting/**` | done | active |
| runtime-llm | `src/runtime/llm_runtime/**` | done | active |
| runtime-embedding | `src/runtime/embedding_runtime/**` | done | active |
| plugins-owasp | `src/plugins/**` | done | active |

---

## 十、最终交付能力定义

DeepLLMScanner 最终应具备：

| 能力 | 描述 |
|------|------|
| 本地模型增强裁决 | CPU 运行 7B-13B 4bit 模型 |
| 多轮状态攻击 | 支持上下文维持的多轮攻击 |
| 插件化风险模块 | 可扩展的风险插件架构 |
| 可复现漏洞确认 | 验证引擎确保漏洞可复现 |
| 风险评分体系 | 统一的风险评分公式 |
| 覆盖 OWASP LLM Top 10 | 全部 10 类 LLM 安全风险 |
| CPU-only 可运行 | 无需 GPU 依赖 |

---

## 十一、当前焦点

> 与 `docs/CURRENT_GOAL.md` 保持同步

| 字段 | 值 |
|------|-----|
| **阶段** | Phase 3 |
| **目标** | 高级能力 - deep 模式 + 攻击进化 |
| **重点模块** | 多次稳定验证, HTML 报告, 进化算法 |
| **测试覆盖** | 302 passed, 8 skipped |

---

## 十二、风险与依赖

| 类型 | 描述 | 影响 | 状态 |
|------|------|------|------|
| 依赖 | llama-cpp-python | 高 | ✅ 已集成 |
| 依赖 | sentence-transformers | 中 | ✅ 已集成 |
| 风险 | CPU 推理性能 | 中 | ✅ 已优化 (4bit 量化) |
| 风险 | 模型内存占用 | 高 | ✅ 已优化 (GGUF 格式) |

---

## 附录：目录结构

```
DeepLLMScanner/
├── src/
│   ├── core/
│   │   ├── controller/
│   │   ├── scheduler/
│   │   ├── attack_engine/
│   │   ├── state_engine/
│   │   ├── execution_engine/
│   │   ├── detection_engine/
│   │   ├── validation_engine/
│   │   ├── scoring_engine/
│   │   └── reporting/
│   ├── runtime/
│   │   ├── llm_runtime/
│   │   └── embedding_runtime/
│   ├── plugins/
│   │   ├── base.py
│   │   ├── registry.py
│   │   ├── LLM01_prompt_injection/
│   │   ├── LLM02_data_leak/
│   │   ├── LLM03_supply_chain/
│   │   ├── LLM04_data_poisoning/
│   │   ├── LLM05_output_handling/
│   │   ├── LLM06_excessive_agency/
│   │   ├── LLM07_system_prompt_leak/
│   │   ├── LLM08_vector_weakness/
│   │   ├── LLM09_misinformation/
│   │   └── LLM10_unbounded_consumption/
│   ├── templates/
│   ├── rules/
│   └── configs/
├── tests/
├── docs/
└── examples/
```
