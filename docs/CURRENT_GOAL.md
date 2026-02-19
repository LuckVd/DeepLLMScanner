# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 补全 embedding_runtime 模块 - 实现 Detection L2 层向量相似度检测 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-20 |
| **完成日期** | 2026-02-20 |

---

## 完成标准

- [ ] 创建 `src/runtime/embedding_runtime/` 目录结构
- [ ] 实现 Embedding 加载器 (sentence-transformers)
- [ ] 实现文本向量化和相似度计算接口
- [ ] 集成到 LLM07/LLM08 插件的检测逻辑
- [ ] 编写单元测试
- [ ] 更新文档

---

## 任务清单

| 序号 | 任务 | 产出 | 状态 |
|------|------|------|------|
| 1 | 创建目录结构 | `src/runtime/embedding_runtime/__init__.py` | completed |
| 2 | 实现 Embedding 加载器 | `src/runtime/embedding_runtime/loader.py` | completed |
| 3 | 实现相似度计算 | `src/runtime/embedding_runtime/similarity.py` | completed |
| 4 | 集成到检测引擎 | 更新 LLM07 插件 | completed |
| 5 | 更新 LLM07 插件 | 使用 Embedding 检测 (L2 层) | completed |
| 6 | 编写单元测试 | `tests/test_embedding_runtime.py` (22 个测试) | completed |
| 7 | 更新文档 | README + PROJECT.md | pending |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-20 | 🎯 目标设置：补全 embedding_runtime 模块 |
| 2026-02-20 | ✅ 创建目录结构和 __init__.py |
| 2026-02-20 | ✅ 实现 EmbeddingLoader 类 (sentence-transformers 加载) |
| 2026-02-20 | ✅ 实现 SimilarityCalculator 类 (余弦相似度、批量计算、语料索引) |
| 2026-02-20 | ✅ 集成到 LLM07 插件 (添加 L2 Embedding 检测层) |
| 2026-02-20 | ✅ 编写 22 个单元测试 (全部通过) |
| 2026-02-20 | ✅ 302 个总测试全部通过 |

---

## 技术设计

### 目录结构

```
src/runtime/embedding_runtime/
├── __init__.py        # 模块导出
├── loader.py          # Embedding 模型加载
└── similarity.py      # 相似度计算
```

### 核心类

```python
# loader.py
class EmbeddingLoader:
    - load(model_name: str)  # 加载 sentence-transformers 模型
    - encode(text: str) -> np.ndarray  # 文本向量化
    - encode_batch(texts: list) -> np.ndarray  # 批量向量化

# similarity.py
class SimilarityCalculator:
    - cosine_similarity(vec1, vec2) -> float
    - batch_similarity(query, corpus) -> list[float]
    - find_similar(query, corpus, threshold) -> list[tuple]
```

### 依赖

- `sentence-transformers` - Embedding 模型加载
- `numpy` - 向量运算

### 默认模型

- `all-MiniLM-L6-v2` - 轻量级，CPU 友好，384 维向量

---

## 关联模块

- `src/runtime/embedding_runtime/` - 本次实现
- `src/core/detection_engine/` - 集成使用
- `src/plugins/LLM07_system_prompt_leak/` - 优先集成
- `src/plugins/LLM08_vector_weakness/` - 后续集成
