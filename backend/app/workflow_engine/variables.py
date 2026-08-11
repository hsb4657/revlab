"""变量池与占位符解析({{key}}),参考 n8n/LangGraph 变量传递"""
from __future__ import annotations
import json
import re

PLACEHOLDER_RE = re.compile(r"\{\{\s*([^}\s]+)\s*\}\}")


def _lookup(path: str, pool: dict):
    """从变量池按路径取值。path 支持 a.b.c 与 list[i]。"""
    cur = pool
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def resolve(text, pool: dict, max_depth: int = 10) -> str:
    """递归解析占位符。返回替换后的字符串。"""
    def _one(t):
        for m in PLACEHOLDER_RE.finditer(t):
            key = m.group(1).strip()
            val = _lookup(key, pool)
            if val is not None:
                if isinstance(val, (dict, list)):
                    val = json.dumps(val, ensure_ascii=False)
                else:
                    val = str(val)
                return t[:m.start()] + val + t[m.end():], True
        return t, False

    cur = text
    for _ in range(max_depth):
        cur, changed = _one(cur)
        if not changed:
            break
    return cur


def unresolved_keys(text: str) -> list:
    return [m.group(1).strip() for m in PLACEHOLDER_RE.finditer(text)]


def collect_outputs(node_id: str, result: dict, pool: dict):
    """将节点输出写入变量池,前缀 node_id 便于引用 {{node_id.key}}。
    顶层键(如 sample_path)也暴露,供后续节点直接引用。"""
    if not isinstance(result, dict):
        result = {"result": result}
    pool[f"{node_id}"] = result
    for k, v in result.items():
        pool[f"{node_id}.{k}"] = v
        if k not in pool and not str(k).startswith("__"):
            pool[k] = v
    return pool


def find_in_pool(pool: dict, key: str):
    """在变量池中查找键:顶层优先,其次遍历各节点输出 dict。"""
    if key in pool:
        return pool[key]
    for v in pool.values():
        if isinstance(v, dict) and key in v:
            return v[key]
    return None


def extract_variables(text: str) -> list:
    """提取文本中的所有变量引用键。"""
    return [m.group(1).strip() for m in PLACEHOLDER_RE.finditer(text)]
