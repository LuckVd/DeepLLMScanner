# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 实现多次稳定验证模块 - 减少漏洞误报率 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-20 |
| **完成日期** | 2026-02-20 |

---

## 完成标准

- [x] 设计多次验证策略 (重复执行 + 变体验证)
- [x] 实现 `StabilityValidator` 类
- [x] 集成到现有 `validation_engine`
- [x] 添加配置选项 (验证次数、间隔、阈值)
- [x] 编写单元测试
- [x] 更新文档

---

## 任务清单

| 序号 | 任务 | 产出 | 状态 |
|------|------|------|------|
| 1 | 设计验证策略 | 多次验证流程设计文档 | completed |
| 2 | 实现 StabilityValidator | `src/core/validation_engine/stability.py` | completed |
| 3 | 集成到 validation_engine | 更新 __init__.py 导出 | completed |
| 4 | 添加配置支持 | StabilityConfig 类 | completed |
| 5 | 编写单元测试 | `tests/test_stability_validator.py` (31 个测试) | completed |
| 6 | 更新文档 | README + PROJECT.md | completed |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-20 | 🎯 目标设置：实现多次稳定验证模块 |
| 2026-02-20 | ✅ 设计验证策略 (REPLAY/VARIANT/HYBRID/PROGRESSIVE) |
| 2026-02-20 | ✅ 实现 StabilityValidator 核心类 |
| 2026-02-20 | ✅ 实现 StabilityConfig 配置类 |
| 2026-02-20 | ✅ 实现 StabilityResult 结果类 |
| 2026-02-20 | ✅ 更新 validation_engine/__init__.py 导出 |
| 2026-02-20 | ✅ 编写 31 个单元测试 (全部通过) |
| 2026-02-20 | ✅ 333 个总测试全部通过 |
| 2026-02-20 | ✅ 更新 README 文档 (添加 Validation System 章节) |
| 2026-02-20 | ✅ 更新 PROJECT.md (core-validation 状态改为 stable) |
| 2026-02-20 | ✅ 目标完成 |

---

## 技术设计

### 多次验证策略

```
第一次验证 (原始攻击)
    ↓
漏洞检测到?
    ↓ Yes
第二次验证 (相同攻击重放)
    ↓
漏洞复现?
    ↓ Yes
第三次验证 (变体攻击)
    ↓
漏洞确认 (高置信度)
```

### 核心类设计

```python
@dataclass
class StabilityConfig:
    enabled: bool = True
    min_validations: int = 2       # 最少验证次数
    max_validations: int = 3       # 最多验证次数
    required_consistency: float = 0.66  # 一致性阈值 (2/3)
    retry_delay: float = 0.5       # 重试间隔 (秒)
    variant_on_retry: bool = True  # 重试时使用变体

class StabilityValidator:
    def __init__(self, config: StabilityConfig)
    def validate(self, attack, response, detection_result) -> StabilityResult
    def validate_with_retries(self, attack_func, detection_func) -> StabilityResult

@dataclass
class StabilityResult:
    is_stable: bool              # 漏洞是否稳定可复现
    confidence: float            # 置信度 (0-1)
    validation_count: int        # 实际验证次数
    successful_count: int        # 成功复现次数
    attempts: list[ValidationAttempt]  # 每次验证详情
```

### 验证流程

1. **首次检测**: 使用原始攻击检测漏洞
2. **重复验证**: 相同攻击重放 N 次
3. **变体验证**: (可选) 使用攻击变体验证
4. **一致性计算**: successful_count / validation_count >= threshold
5. **结果判定**: 稳定漏洞 / 不稳定 / 误报

---

## 关联模块

- `src/core/validation_engine/` - 主要修改位置
- `src/core/controller/` - 配置集成
- `src/core/attack_engine/` - 变体生成
- `tests/test_validation_engine.py` - 测试扩展

---

## 预期收益

- 减少误报率 (通过多次验证确认)
- 提高漏洞可信度 (稳定性评分)
- 支持不同扫描模式配置 (quick/standard/deep)
