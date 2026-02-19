# PROJECT.md

> ClaudeDevKit 唯一配置文档 — 项目信息、模块定义、保护规则、开发历史

---

## 项目信息

| 字段 | 值 |
|------|-----|
| **名称** | DeepLLMScanner |
| **类型** | library |
| **描述** | CPU-only 可运行 · 本地 7B-13B 4bit 模型增强 · 多层检测 + 验证驱动 · 覆盖 OWASP LLM Top 10 |
| **技术栈** | Python + llama.cpp (CPU) + sentence-transformers + GGUF 4bit |

---

## 模块定义

### 模块状态说明

| Status | 说明 |
|--------|------|
| `todo` | 未开始 |
| `dev` | 开发中 |
| `done` | 已完成 |

### 模块等级说明

| Level | 含义 | 修改规则 |
|-------|------|----------|
| `active` | 活跃开发 | 自由修改 |
| `stable` | 已稳定 | 需确认 |
| `core` | 核心保护 | 禁止自动修改 |

### 模块列表

| 模块 | 路径 | Status | Level |
|------|------|--------|-------|
| claude-control | `.claude/**` | done | core |
| governance-specs | `docs/api/**`, `docs/CURRENT_GOAL.md`, `docs/ROADMAP.md` | done | core |
| git-history | `docs/git/**` | done | stable |
| project-docs | `docs/*.md`, `README.md` | todo | active |
| core-controller | `src/core/controller/**` | dev | active |
| core-scheduler | `src/core/scheduler/**` | todo | active |
| core-attack | `src/core/attack_engine/**` | todo | active |
| core-state | `src/core/state_engine/**` | dev | active |
| core-execution | `src/core/execution_engine/**` | todo | active |
| core-detection | `src/core/detection_engine/**` | todo | active |
| core-validation | `src/core/validation_engine/**` | dev | active |
| core-scoring | `src/core/scoring_engine/**` | dev | active |
| core-reporting | `src/core/reporting/**` | dev | active |
| runtime-llm | `src/runtime/llm_runtime/**` | todo | active |
| runtime-embedding | `src/runtime/embedding_runtime/**` | done | active |
| plugins-owasp | `src/plugins/**` | dev | active |

---

## 保护规则

### 文件保护

```
Level: core  → 禁止自动修改，需人工降级
Level: stable → 修改前输出 Stability Modification Proposal，等待确认
Level: active → 允许自由修改
```

### API 保护

API 文件变更时：
- 检测 Breaking Change（参数删除/类型变更/响应结构变化）
- 稳定 API 变更需确认
- 自动提示更新 `docs/api/API.md`

### 默认原则

- 未定义的模块默认为 `active`
- 不确定时默认视为 `stable`
- AI 不得自动升级 Level（active → stable → core）

---

## 开发历史

> 每次提交后自动追加

| 日期 | Commit | 描述 |
|------|--------|------|
| 2026-02-19 | f43e913 | feat: implement Phase 2 - multi-turn attacks and full OWASP LLM Top 10 coverage |
| 2026-02-19 | 85bc20f | feat: improve LLM07 detection accuracy with multi-layer approach |

---

## 自动升级规则

提交后自动检测：

1. **模块状态升级建议**
   - 条件：模块 `dev` + 最近 3 次提交无该模块变动
   - 动作：建议升级为 `done` + `stable`

2. **API 变更检测**
   - 条件：检测到 API 文件变更
   - 动作：提示更新 `docs/api/API.md`

3. **保护文件警告**
   - 条件：修改 `stable` 或 `core` 文件
   - 动作：输出提示，等待确认

---

## 当前目标

> 当前开发目标独立维护，详见 `docs/CURRENT_GOAL.md`

**当前阶段**：Phase 2 - 多轮攻击 + 全 10 类覆盖 (completed)

**快速操作：**
- 查看目标：`/goal`
- 设置目标：`/goal set <任务描述>`
- 标记完成：`/goal done`
