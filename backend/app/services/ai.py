"""AI 模型接入服务(OpenAI 兼容接口):配置管理 / 对话 / 智能报告解读
配置存储于 data/ai_config.json,支持任意兼容 /chat/completions 的提供商。
"""
import json
from pathlib import Path

import httpx

from ..core.config import DATA_DIR

CONFIG_FILE = DATA_DIR / "ai_config.json"

EVIDENCE_SCHEMA = "revlab.ai-evidence/v1"


def _limit_value(value, *, depth: int = 0, max_depth: int = 4,
                max_items: int = 40, max_string: int = 1800):
    """Bound nested analysis output before it enters an LLM prompt.

    Analysis nodes often contain full disassembly/decompiler output.  Keeping
    the first bounded slice preserves useful anchors without allowing one
    unusually large sample to consume the whole model context.
    """
    if depth >= max_depth:
        return "..."
    if isinstance(value, str):
        return value[:max_string]
    if isinstance(value, (bytes, bytearray)):
        return value[:64].hex()
    if isinstance(value, list):
        return [_limit_value(item, depth=depth + 1, max_depth=max_depth,
                             max_items=max_items, max_string=max_string)
                for item in value[:max_items]]
    if isinstance(value, dict):
        items = list(value.items())[:max_items]
        return {str(key)[:120]: _limit_value(item, depth=depth + 1,
                                              max_depth=max_depth,
                                              max_items=max_items,
                                              max_string=max_string)
                for key, item in items}
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:max_string]


def _evidence_status(value: object) -> str:
    """Map stage output to a conservative evidence level."""
    if not isinstance(value, dict):
        return "static" if value else "missing"
    for key in ("execution_status", "evidence_status", "validation_state", "status"):
        raw = str(value.get(key) or "").lower()
        if raw in {"blocked_by_policy", "blocked", "not_collected", "not_executed",
                   "awaiting_runtime_evidence", "runtime_required"}:
            return "blocked"
        if raw in {"confirmed", "verified", "completed", "done", "plain", "decrypted"}:
            return "runtime" if key in {"execution_status", "evidence_status"} else "static"
        if raw in {"candidate", "unconfirmed", "inferred", "ai_inferred"}:
            return "inferred"
    if value.get("executed") is False:
        return "blocked"
    if value.get("executed") is True or value.get("execution_available") is True:
        return "runtime"
    return "static"


def build_evidence_bundle(sample_type: str, sources: dict | None = None,
                          *, extra: dict | None = None) -> dict:
    """Build the common evidence envelope used by all AI-assisted nodes.

    ``sources`` remains keyed by the producing stage so a reviewer can trace a
    claim back to its input.  Values are bounded and never promoted to a
    confirmed runtime observation by this helper.
    """
    rows = {}
    for name, value in (sources or {}).items():
        rows[str(name)] = {
            "source": str(name),
            "evidence_level": _evidence_status(value),
            "data": _limit_value(value),
        }
    bundle = {
        "schema": EVIDENCE_SCHEMA,
        "sample_type": str(sample_type),
        "sources": rows,
        "limitations": [
            "AI 输出是基于当前证据的推断，不会替代静态解析或运行时验证。",
            "候选地址、API 名称、高熵和字符串只能作为线索，不能单独证明行为。",
            "动态阶段被策略阻止或未采集时，不得描述为样本运行时行为。",
        ],
    }
    if extra:
        bundle.update(_limit_value(extra, max_depth=3, max_items=32, max_string=1200))
    return bundle

_DEFAULT_CONFIG = {
    "enabled": False,
    "base_url": "https://api.openai.com/v1",
    "api_key": "",
    "model": "gpt-4o-mini",
    "temperature": 0.2,
    "max_tokens": 2000,
    "timeout": 90,
}


def _path() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_FILE


def load_config() -> dict:
    if _path().exists():
        try:
            cfg = {**_DEFAULT_CONFIG, **json.loads(_path().read_text(encoding="utf-8"))}
            return cfg
        except Exception:
            pass
    return dict(_DEFAULT_CONFIG)


def save_config(cfg: dict) -> dict:
    cur = load_config()
    cur.update({k: v for k, v in cfg.items() if k in _DEFAULT_CONFIG})
    _path().write_text(json.dumps(cur, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "config": {k: (v if k != "api_key" else "***") for k, v in cur.items()}}


def _endpoint(cfg: dict) -> str:
    base = cfg.get("base_url", "").rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return f"{base}/chat/completions"


def chat_completion(cfg: dict, messages: list, *, tools: list | None = None,
                    tool_choice: str | dict | None = None) -> dict:
    """Call an OpenAI-compatible chat endpoint and return the raw response.

    Keeping the raw completion available is what lets the workflow AI act as
    an operator: a model can request a registered analysis tool, receive its
    result, and continue reasoning instead of guessing from one static prompt.
    """
    url = _endpoint(cfg)
    headers = {"Authorization": f"Bearer {cfg.get('api_key', '')}",
               "Content-Type": "application/json"}
    payload = {
        "model": cfg.get("model", "gpt-4o-mini"),
        "messages": messages,
        "temperature": cfg.get("temperature", 0.2),
        "max_tokens": cfg.get("max_tokens", 2000),
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = tool_choice or "auto"
    with httpx.Client(timeout=cfg.get("timeout", 90)) as client:
        resp = client.post(url, headers=headers, json=payload)
        if resp.status_code != 200:
            raise RuntimeError(f"AI API error {resp.status_code}: {resp.text[:400]}")
        return resp.json()


def chat(cfg: dict, messages: list, *, tools: list | None = None,
         tool_choice: str | dict | None = None) -> str:
    """调用 /chat/completions,返回 assistant 文本。

    ``tools`` is accepted for compatibility with agent callers; callers that
    need tool calls should use :func:`chat_completion` to inspect the raw
    assistant message.
    """
    data = chat_completion(cfg, messages, tools=tools, tool_choice=tool_choice)
    message = (data.get("choices") or [{}])[0].get("message") or {}
    content = message.get("content")
    if isinstance(content, list):
        content = "".join(str(part.get("text", "")) if isinstance(part, dict) else str(part)
                           for part in content)
    return str(content or "")


def test_connection(cfg: dict) -> dict:
    try:
        out = chat(cfg, [{"role": "user", "content": "仅回复:OK"}])
        return {"ok": True, "reply": (out or "").strip()[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def build_sample_ai_evidence(sample: dict) -> dict:
    """Create a traceable, bounded context for the normal sample chat.

    The old implementation flattened a few fields into prose and silently
    omitted execution status.  This structured form keeps PE, runtime and
    report evidence separate so the model cannot confuse a missing observation
    with a negative result.
    """
    summary = sample.get("summary") or {}
    pe = summary.get("pe") or {}
    packer = pe.get("packer") or {}
    sections = []
    for section in (pe.get("sections") or [])[:32]:
        if not isinstance(section, dict):
            continue
        sections.append({key: section.get(key) for key in (
            "name", "virtual_address", "virtual_size", "raw_ptr", "raw_size",
            "characteristics", "entropy", "suspicious") if key in section})
    imports = []
    for item in (pe.get("imports") or [])[:60]:
        if not isinstance(item, dict):
            continue
        names = item.get("functions") or item.get("imports") or []
        imports.append({"dll": item.get("dll") or item.get("name"),
                        "functions": [str(x.get("name") if isinstance(x, dict) else x)
                                      for x in names[:32]]})
    dynamic = summary.get("dynamic") or summary.get("network") or {}
    sources = {
        "sample": {
            "file_name": sample.get("file_name"), "file_size": sample.get("file_size"),
            "sha256": sample.get("sha256"), "md5": sample.get("md5"),
            "imphash": sample.get("imphash"),
        },
        "pe_static": {
            "is_pe": pe.get("is_pe"), "machine": pe.get("machine"),
            "is_64bit": pe.get("is_64bit"), "subsystem": pe.get("subsystem"),
            "entry_point": pe.get("entry_point"), "image_base": pe.get("image_base"),
            "timestamp": pe.get("timestamp"), "debug": pe.get("debug"),
            "security": pe.get("security"), "sections": sections,
            "imports": imports, "exports": (pe.get("exports") or [])[:32],
        },
        "packer_static": packer,
        "strings_static": {"count": len(summary.get("strings") or []),
                            "items": (summary.get("strings") or [])[:80]},
        "disassembly_static": summary.get("disassembly") or {},
        "decompile_static": summary.get("decompile") or {},
        "dynamic_observation": dynamic,
    }
    return build_evidence_bundle(
        "PE", sources,
        extra={"sample_id": sample.get("id"), "analysis_id": sample.get("analysis_id")},
    )


def _sample_context(sample: dict) -> str:
    """将结构化样本证据压缩为可供 AI 理解的 JSON 文本。"""
    return json.dumps(build_sample_ai_evidence(sample), ensure_ascii=False, separators=(",", ":"))[:24000]


def summarize_sample(sample: dict, prompt: str = "") -> str:
    """基于样本分析结果生成 AI 智能解读。"""
    cfg = load_config()
    if not cfg.get("enabled") or not cfg.get("api_key"):
        raise RuntimeError("AI 模型未配置。请先在「AI 模型」面板配置 base_url/api_key/model 并启用。")
    ctx = _sample_context(sample)
    sys_msg = (
        "你是 REVLab 的二进制分析助手。只使用输入中的证据回答，输出中文 Markdown。"
        "请按以下顺序给出：样本概况、证据表、可疑点及证据引用、可能误报、待验证假设、下一步建议。"
        "严格区分 static（静态）、runtime（运行时观测）、inferred（模型推断）和 blocked（未执行/被策略阻止）。"
        "高熵、导入 API 或字符串只能是线索；没有 runtime 证据就不能写成‘样本运行时做了什么’。"
        "不确定时明确写‘未知’及缺少的证据，不要补造地址、密钥、网络连接或工具结果。"
    )
    user = f"【结构化样本证据】\n{ctx}\n\n【用户问题】\n{prompt or '请给出完整分析解读'}"
    return chat(cfg, [{"role": "system", "content": sys_msg}, {"role": "user", "content": user}])
