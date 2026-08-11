"""AI 模型接入服务(OpenAI 兼容接口):配置管理 / 对话 / 智能报告解读
配置存储于 data/ai_config.json,支持任意兼容 /chat/completions 的提供商。
"""
import json
from pathlib import Path

import httpx

from ..core.config import DATA_DIR

CONFIG_FILE = DATA_DIR / "ai_config.json"

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


def chat(cfg: dict, messages: list) -> str:
    """调用 /chat/completions,返回 assistant 文本。"""
    url = _endpoint(cfg)
    headers = {"Authorization": f"Bearer {cfg.get('api_key', '')}",
               "Content-Type": "application/json"}
    payload = {
        "model": cfg.get("model", "gpt-4o-mini"),
        "messages": messages,
        "temperature": cfg.get("temperature", 0.2),
        "max_tokens": cfg.get("max_tokens", 2000),
    }
    with httpx.Client(timeout=cfg.get("timeout", 90)) as client:
        resp = client.post(url, headers=headers, json=payload)
        if resp.status_code != 200:
            raise RuntimeError(f"AI API error {resp.status_code}: {resp.text[:400]}")
        data = resp.json()
        return data["choices"][0]["message"]["content"]


def test_connection(cfg: dict) -> dict:
    try:
        out = chat(cfg, [{"role": "user", "content": "仅回复:OK"}])
        return {"ok": True, "reply": (out or "").strip()[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _sample_context(sample: dict) -> str:
    """将样本分析结果压缩为可供 AI 理解的上下文。"""
    sum_ = sample.get("summary") or {}
    pe = sum_.get("pe") or {}
    pk = pe.get("packer") or {}
    secs = pe.get("sections") or []
    imports = pe.get("imports") or []
    lines = []
    lines.append(f"文件: {sample.get('file_name')}  ({sample.get('file_size', 0)} bytes)")
    lines.append(f"SHA256: {sample.get('sha256')}")
    lines.append(f"imphash: {sample.get('imphash')}")
    if pe.get("is_pe"):
        lines.append(f"架构: {pe.get('machine')} {'64位' if pe.get('is_64bit') else '32位'} 子系统: {pe.get('subsystem')}")
        lines.append(f"入口点: {pe.get('entry_point')}  ImageBase: {pe.get('image_base')}")
        lines.append(f"编译时间: {pe.get('timestamp')}  PDB: {pe.get('debug', {}).get('pdb', '-')}")
        lines.append("节区: " + " | ".join(f"{s.get('name')}(熵{s.get('entropy')})" for s in secs[:10]))
        lines.append(f"壳判定: {pk.get('verdict')} (confidence {pk.get('confidence', 0)}%)")
        lines.append(f"导入DLL: {', '.join(i.get('dll') for i in imports[:20])}")
    strs = (sum_.get("strings") or [])[:40]
    if strs:
        lines.append("兴趣字符串: " + " | ".join(f"{s.get('value', '')}" for s in strs))
    dis = sum_.get("disassembly") or {}
    lines.append(f"入口反汇编指令数: {dis.get('count', 0)}")
    dec = sum_.get("decompile") or {}
    lines.append(f"反编译函数数: {dec.get('function_count', 0) if dec.get('ok') else '未执行'}")
    net = sum_.get("network") or {}
    conns = net.get("connections") or []
    if conns:
        lines.append("网络连接: " + " | ".join(
            f"{c['client']['ip']}:{c['client']['port']}->{c['server']['ip']}:{c['server']['port']}{'(' + c.get('server_name','') + ')'}"
            for c in conns[:15]))
        lines.append("DNS: " + ", ".join(q.get("query", "") for q in (net.get("dns_queries") or [])[:15]))
    return "\n".join(lines)


def summarize_sample(sample: dict, prompt: str = "") -> str:
    """基于样本分析结果生成 AI 智能解读。"""
    cfg = load_config()
    if not cfg.get("enabled") or not cfg.get("api_key"):
        raise RuntimeError("AI 模型未配置。请先在「AI 模型」面板配置 base_url/api_key/model 并启用。")
    ctx = _sample_context(sample)
    sys_msg = ("你是资深的 Windows 二进制逆向分析工程师。请基于给出的样本分析数据,输出中文解读报告,"
               "包含:文件性质判断、关键特征、可疑点、逆向思路建议。用 markdown,简洁专业。")
    user = f"【样本分析数据】\n{ctx}\n\n{prompt or '请给出完整分析解读'}"
    return chat(cfg, [{"role": "system", "content": sys_msg}, {"role": "user", "content": user}])
