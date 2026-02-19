# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | Phase 2 - 多轮攻击 + 全 10 类覆盖 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-19 |
| **完成日期** | 2026-02-19 |

---

## 完成标准

- [x] 实现 `state_engine` - 多轮对话攻击
- [x] 实现 LLM03 插件 - Supply Chain（供应链风险）
- [x] 实现 LLM04 插件 - Data Poisoning（数据投毒）
- [x] 实现 LLM05 插件 - Output Handling（输出处理不当）
- [x] 实现 LLM06 插件 - Excessive Agency（过度代理）
- [x] 实现 LLM08 插件 - Vector Weakness（向量数据库弱点）
- [x] 实现 LLM09 插件 - Misinformation（错误信息）
- [x] 实现 LLM10 插件 - Unbounded Consumption（无界消耗）
- [x] 覆盖 OWASP LLM Top 10 全部类别

---

## 任务清单

| 序号 | 任务 | 产出 | 状态 |
|------|------|------|------|
| 1 | 实现 state_engine 多轮对话 | `src/core/state_engine/` | completed |
| 2 | 实现 LLM03 Supply Chain 插件 | `src/plugins/LLM03_supply_chain/` | completed |
| 3 | 实现 LLM04 Data Poisoning 插件 | `src/plugins/LLM04_data_poisoning/` | completed |
| 4 | 实现 LLM05 Output Handling 插件 | `src/plugins/LLM05_output_handling/` | completed |
| 5 | 实现 LLM06 Excessive Agency 插件 | `src/plugins/LLM06_excessive_agency/` | completed |
| 6 | 实现 LLM08 Vector Weakness 插件 | `src/plugins/LLM08_vector_weakness/` | completed |
| 7 | 实现 LLM09 Misinformation 插件 | `src/plugins/LLM09_misinformation/` | completed |
| 8 | 实现 LLM10 Unbounded Consumption 插件 | `src/plugins/LLM10_unbounded_consumption/` | completed |
| 9 | 编写单元测试 | `tests/test_state_engine.py` (37 个) | completed |
| 10 | 集成测试验证 | 10 个插件全部注册成功 | completed |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-19 | 🎯 目标设置：Phase 2 - 多轮攻击 + 全 10 类覆盖 |
| 2026-02-19 | ✅ 完成 state_engine 多轮对话模块 (37 个测试) |
| 2026-02-19 | ✅ 完成 LLM03 Supply Chain 插件 |
| 2026-02-19 | ✅ 完成 LLM04 Data Poisoning 插件 |
| 2026-02-19 | ✅ 完成 LLM05 Output Handling 插件 |
| 2026-02-19 | ✅ 完成 LLM06 Excessive Agency 插件 |
| 2026-02-19 | ✅ 完成 LLM08 Vector Weakness 插件 |
| 2026-02-19 | ✅ 完成 LLM09 Misinformation 插件 |
| 2026-02-19 | ✅ 完成 LLM10 Unbounded Consumption 插件 |
| 2026-02-19 | ✅ 所有 10 个插件注册成功 |
| 2026-02-19 | ✅ 251 个测试全部通过 |

---

## 实际效果

| 指标 | 当前 | 目标 | 实际 |
|------|------|------|------|
| 插件数量 | 3 个 | 10 个 | ✅ 10 个 |
| 攻击方式 | 单轮 | 单轮 + 多轮 | ✅ 已实现 |
| OWASP 覆盖 | 30% | 100% | ✅ 100% |
| Phase 进度 | Phase 1 | Phase 2 | ✅ Phase 2 完成 |

---

## 新增文件

### State Engine
```
src/core/state_engine/
├── __init__.py
├── conversation.py   # 对话管理
├── state.py          # 状态机
└── manager.py        # 会话管理
```

### 插件
```
src/plugins/
├── LLM03_supply_chain/plugin.py
├── LLM04_data_poisoning/plugin.py
├── LLM05_output_handling/plugin.py
├── LLM06_excessive_agency/plugin.py
├── LLM08_vector_weakness/plugin.py
├── LLM09_misinformation/plugin.py
└── LLM10_unbounded_consumption/plugin.py
```

### 测试
```
tests/test_state_engine.py  # 37 个测试
```

---

## 插件检测能力

| 插件 | 检测内容 |
|------|----------|
| LLM03 | 版本暴露、训练数据泄露、基础设施信息 |
| LLM04 | 后门触发、偏见输出、操纵模式 |
| LLM05 | XSS、代码执行、SQL 注入、不安全 Markdown |
| LLM06 | 未授权函数调用、权限提升、敏感操作 |
| LLM08 | 元数据暴露、数据检索、访问控制 |
| LLM09 | 幻觉、过度自信、虚假信息 |
| LLM10 | Token 放大、重复输出、资源耗尽 |
