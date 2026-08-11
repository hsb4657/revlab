"""UE 三大件特征字节签名库
基于公开 UE 逆向社区知识(UE4Dumper / UnrealDumper 等)。
?? 表示通配符字节;RIP-relative 指令的 4 字节相对偏移自动提取。
"""
from __future__ import annotations
import json
import re
from pathlib import Path

from ...core.config import DATA_DIR

# 签名条目: {name, signature(hex), min_offset(相对RIP偏移长度), versions, desc}
BUILTIN_SIGNATURES: list = [
    # ---------------- GObjects (TUObjectArray) ----------------
    {
        "name": "GObjects_UE4",
        "signature": "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1",
        "offset": 4, "rel": True, "versions": ["4.25", "4.26", "4.27", "5.0", "5.1", "5.2"],
        "desc": "mov rax,[rip+?]; mov rcx,[rax+rcx*8]; lea rax,[rax+rdx*8] (经典 TUObjectArray)",
    },
    {
        "name": "GObjects_UE4_v2",
        "signature": "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1 48 85 C0",
        "offset": 4, "rel": True, "versions": ["4.22", "4.23", "4.24", "4.25"],
        "desc": "带 null 检查的 TUObjectArray 访问",
    },
    {
        "name": "GObjects_UE5",
        "signature": "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1 48 89",
        "offset": 4, "rel": True, "versions": ["5.3", "5.4", "5.5"],
        "desc": "UE5 FChunkedFixedUObjectArray 访问",
    },
    {
        "name": "GObjects_LEA",
        "signature": "48 8D 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1",
        "offset": 4, "rel": True, "versions": ["4.20", "4.21", "4.22"],
        "desc": "lea rax,[rip+?] 变体",
    },
    # ---------------- GNames (FNamePool / TNameEntryArray) ----------------
    {
        "name": "GNames_Pool",
        "signature": "48 8D 05 ?? ?? ?? ?? 0F B7 14 48",
        "offset": 4, "rel": True, "versions": ["4.23", "4.24", "4.25", "4.26", "4.27", "5.0", "5.1", "5.2", "5.3", "5.4", "5.5"],
        "desc": "lea rax,[rip+?] FNamePool 基址",
    },
    {
        "name": "GNames_Pool_v2",
        "signature": "48 8D 05 ?? ?? ?? ?? 66 89 04 48",
        "offset": 4, "rel": True, "versions": ["5.2", "5.3", "5.4", "5.5"],
        "desc": "FNamePool + IndexToName 加速表写入",
    },
    {
        "name": "GNames_Direct",
        "signature": "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 16 48 8B 40 10",
        "offset": 4, "rel": True, "versions": ["4.10", "4.11", "4.12", "4.13", "4.14", "4.15", "4.16", "4.17", "4.18", "4.19", "4.20"],
        "desc": "TNameEntryArray 直接索引(GNames 基址)",
    },
    {
        "name": "GNames_Direct_v2",
        "signature": "48 8B 05 ?? ?? ?? ?? 48 85 C0 75 12",
        "offset": 4, "rel": True, "versions": ["4.8", "4.9", "4.10", "4.11", "4.12"],
        "desc": "TNameEntryArray 变体",
    },
    # ---------------- GWorld ----------------
    {
        "name": "GWorld",
        "signature": "48 8B 1D ?? ?? ?? ?? 48 8B 5D 08",
        "offset": 4, "rel": True, "versions": ["4.x", "5.x"],
        "desc": "mov rbx,[rip+?] UWorld 全局指针引用",
    },
    {
        "name": "GWorld_v2",
        "signature": "48 8B 1D ?? ?? ?? ?? 48 85 DB 74 25",
        "offset": 4, "rel": True, "versions": ["4.22", "4.23", "4.24", "4.25", "4.26", "4.27"],
        "desc": "带 null 检查的 GWorld 引用",
    },
    {
        "name": "GWorld_UE5",
        "signature": "48 8B 1D ?? ?? ?? ?? 48 8B 5D D0",
        "offset": 4, "rel": True, "versions": ["5.0", "5.1", "5.2", "5.3", "5.4", "5.5"],
        "desc": "UE5 GWorld 引用",
    },
    # ---------------- GEngine / 辅助 ----------------
    {
        "name": "GEngine",
        "signature": "48 8B 05 ?? ?? ?? ?? 48 8B 38 E8 ?? ?? ?? ?? 84 C0",
        "offset": 4, "rel": True, "versions": ["4.x", "5.x"],
        "desc": "GEngine 全局指针引用",
    },
]


def _parse_sig(sig: str) -> list:
    """解析签名为 (byte|None) 列表。支持 '??' 与通配大小写。"""
    out = []
    for tok in sig.split():
        if tok == "??" or tok == "?":
            out.append(None)
        else:
            out.append(int(tok, 16))
    return out


def load_custom_signatures() -> list:
    p = DATA_DIR / "ue_custom_signatures.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def save_custom_signature(entry: dict) -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    sigs = load_custom_signatures()
    sigs = [s for s in sigs if s.get("name") != entry.get("name")]
    sigs.append(entry)
    (DATA_DIR / "ue_custom_signatures.json").write_text(
        json.dumps(sigs, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "count": len(sigs)}


def all_signatures() -> list:
    return BUILTIN_SIGNATURES + load_custom_signatures()


def signatures_for_version(version: str) -> list:
    vs = []
    for s in all_signatures():
        if any(v in s.get("versions", []) for v in (version, "4.x" if version.startswith("4") else "5.x")):
            vs.append(s)
    return vs


def scan_signature(data: bytes, entry: dict, max_hits: int = 8):
    """扫描签名的匹配位置。返回 [{offset, rel_address, imm_start, imm}]。
    rel: 若签名含 RIP-relative(entry['rel']),则计算目标地址 = 下一条指令偏移 + imm32。
    修正点: imm 应取首个 '??' 通配段(即 RIP 相对偏移字段,如 48 8B 05 ?? ?? ?? ?? 中位于
    pattern 索引 3..6),而非固定 entry['offset'] 处;下一条指令 = match + imm_start + 4。
    此处返回文件内相对偏移,VA 计算由调用方完成。
    """
    pattern = _parse_sig(entry["signature"])
    n = len(pattern)
    hits = []
    # imm 起点:优先取首个 '??' 通配位置(标准 RIP-relative 布局),否则回退 entry['offset']
    try:
        imm_start = pattern.index(None)
    except ValueError:
        imm_start = int(entry.get("offset", 4))
    rel_off = imm_start
    i = 0
    while i <= len(data) - n:
        ok = True
        for j, b in enumerate(pattern):
            if b is not None and data[i + j] != b:
                ok = False
                break
        if ok:
            target = None
            if entry.get("rel"):
                # RIP-relative: imm 位于首个 '??' 处(通常 4 字节),下一条指令在 imm 之后
                imm = int.from_bytes(data[i + imm_start:i + imm_start + 4], "little", signed=True)
                target = (i + imm_start + 4) + imm  # 相对当前扫描文件偏移计算,VA 由调用方映射
            hits.append({"match": i, "imm": imm if entry.get("rel") else None,
                         "target": target, "imm_start": imm_start if entry.get("rel") else None})
            if len(hits) >= max_hits:
                break
            i += n
        else:
            i += 1
    return hits
