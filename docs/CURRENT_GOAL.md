# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | Phase 1 MVP 攻击引擎 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-17 |

---

## 完成标准

- [x] 实现攻击模板加载功能（从 YAML 加载）
- [x] 实现基础攻击生成功能（变量替换）
- [x] 联网搜集并生成 LLM01 Prompt Injection 模板
- [x] 联网搜集并生成 LLM02 Data Leak 模板
- [x] 联网搜集并生成 LLM07 System Prompt Leak 模板

---

## 关联模块

- `src/core/attack_engine/` - 攻击引擎核心 ✅
- `src/core/attack_engine/templates/` - YAML 模板目录 ✅

---

## 任务清单

| 序号 | 任务 | 产出 | 状态 |
|------|------|------|------|
| 1 | 联网搜集 LLM01/02/07 攻击 payload | 原始数据收集 | ✅ completed |
| 2 | 创建攻击引擎数据模型 | `models.py` | ✅ completed |
| 3 | 实现模板加载器 | `generator.py` (模板加载部分) | ✅ completed |
| 4 | 实现基础生成器 | `generator.py` (变量替换部分) | ✅ completed |
| 5 | 创建 LLM01 YAML 模板 | `templates/LLM01_prompt_injection.yaml` | ✅ completed |
| 6 | 创建 LLM02 YAML 模板 | `templates/LLM02_data_leak.yaml` | ✅ completed |
| 7 | 创建 LLM07 YAML 模板 | `templates/LLM07_system_prompt_leak.yaml` | ✅ completed |
| 8 | 编写单元测试 | `tests/test_attack_engine.py` | ✅ completed |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-17 | 🎯 目标设置：Phase 1 MVP 攻击引擎 |
| 2026-02-17 | 📦 创建 `models.py` - 数据模型 (AttackPayload, AttackTemplate, GeneratedAttack 等) |
| 2026-02-17 | 🔧 创建 `generator.py` - 模板加载器和攻击生成器 |
| 2026-02-17 | 📝 创建 LLM01/LLM02/LLM07 YAML 模板 (基于 Garak + PromptInject 数据) |
| 2026-02-17 | 🧪 创建 `test_attack_engine.py` - 20 个测试用例全部通过 |
| 2026-02-17 | ✅ Phase 1 MVP 攻击引擎完成 |

---

## 产出文件

| 文件 | 说明 |
|------|------|
| `src/core/attack_engine/__init__.py` | 模块导出 |
| `src/core/attack_engine/models.py` | 数据模型定义 |
| `src/core/attack_engine/generator.py` | 模板加载器和攻击生成器 |
| `src/core/attack_engine/templates/LLM01_prompt_injection.yaml` | LLM01 攻击模板 |
| `src/core/attack_engine/templates/LLM02_data_leak.yaml` | LLM02 攻击模板 |
| `src/core/attack_engine/templates/LLM07_system_prompt_leak.yaml` | LLM07 攻击模板 |
| `tests/test_attack_engine.py` | 单元测试 (20 passed) |

---

## 备注

本目标聚焦于攻击引擎的最小可用实现：

1. **模板来源**：联网搜集 Garak、PromptInject 等开源数据集
2. **模板格式**：YAML，支持 `{{variable}}` 变量替换
3. **覆盖范围**：LLM01/02/07 三类 OWASP LLM Top 10 风险

后续 Phase 1 还需实现：插件系统、检测引擎、验证引擎、评分引擎、报告生成。
