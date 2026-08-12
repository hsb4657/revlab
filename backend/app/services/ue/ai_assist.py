"""UE AI 辅助分析:构建可解释的静态证据(候选地址 + 反汇编片段),调用配置的
OpenAI 兼容模型,产出结构化结论(三大件精确地址 / GetName 算法 / 解密算法)。

设计约束
--------
* 输入为 dump 文件上的静态证据:签名命中、RIP-relative 候选、GetName 标记、
  XOR 立即数候选、加密信号与版本信息。
* 候选地址是映像内的 RVA(不含加载基址);绝对地址 = ImageBase + RVA。
* AI 输出为 JSON 并做本地规范化:无效字段回退为空/None,保证下游报告与变量
  池始终拿到可序列化结构,不把模型臆断当已验证事实。
"""
from __future__ import annotations

import json
import re
from typing import Any

from ...core.config import config
from ...services import disassembler, pe_parser
from .. import ai as ai_svc


def _to_hex(value: Any) -> str:
    try:
        return hex(int(str(value), 0))
    except (TypeError, ValueError):
        return ""


def _rva_to_off(pe: dict, rva: int, data_len: int) -> int | None:
    """RVA → 文件偏移(节内线性映射,与 analyzer.offset_to_va 互逆)。"""
    for s in pe.get("sections", []):
        va = int(s.get("virtual_address", "0x0"), 16)
        vsz = s.get("virtual_size", 0) or s.get("raw_size", 0)
        if va <= rva < va + max(vsz, 1):
            raw = int(s.get("raw_ptr", "0x0"), 16)
            off = raw + (rva - va)
            return off if off < data_len else None
    return None


def _rva_of_file_offset(pe: dict, off: int, data_len: int) -> int | None:
    """文件偏移 → RVA(节内线性映射)。"""
    for s in pe.get("sections", []):
        raw = int(s.get("raw_ptr", "0x0"), 16)
        size = s.get("raw_size", 0)
        if raw <= off < raw + max(size, 1):
            va = int(s.get("virtual_address", "0x0"), 16)
            return va + (off - raw)
    if 0 <= off < data_len:
        return off
    return None


def _section_name_at(pe: dict, rva: int) -> str:
    for s in pe.get("sections", []):
        va = int(s.get("virtual_address", "0x0"), 16)
        vsz = s.get("virtual_size", 0) or s.get("raw_size", 0)
        if va <= rva < va + max(vsz, 1):
            return str(s.get("name", ""))
    return "?"


def _disasm_around(data: bytes, pe: dict, rva: int | None, count: int = 24) -> list[dict]:
    """反汇编 RVA 附近 count 条指令,返回 [{rva, mnemonic, op_str}]。"""
    if not isinstance(rva, int):
        return []
    data_len = len(data)
    off = _rva_to_off(pe, rva, data_len)
    if off is None:
        return []
    arch = "x64" if pe.get("machine") == "x64" else "x86"
    start = max(0, off - 4)
    out = disassembler.disassemble(data, base=0, arch=arch, start=start,
                                   max_insns=count, show_bytes=False)
    insns = []
    for item in out.get("insns", []):
        insns.append({
            "rva": _to_hex(_rva_of_file_offset(pe, item["address"], data_len)),
            "mnemonic": item["mnemonic"],
            "op_str": item["op_str"],
        })
        if len(insns) >= count:
            break
    return insns


def _limit(value: Any, depth: int = 0, max_len: int = 1400) -> Any:
    """限制证据体积,防止上下文爆炸。"""
    if depth > 3:
        return "..."
    if isinstance(value, str):
        return value[:max_len]
    if isinstance(value, list):
        return [_limit(item, depth + 1, max_len) for item in value[:24]]
    if isinstance(value, dict):
        return {str(key)[:80]: _limit(item, depth + 1, max_len)
                for key, item in list(value.items())[:32]}
    return value


def build_ue_evidence(result: dict, data: bytes, pe: dict) -> dict:
    """从 UEAnalyzer 结果构建 AI 可读的证据包。

    result: UEAnalyzer.run() 的输出
    data:   样本字节
    pe:     pe_parser.parse_pe() 输出(需含 sections/data)
    """
    majors = result.get("three_majors") or {}
    candidates = result.get("major_candidates") or {}
    signature_hits = (result.get("signature_hits") or [])[:16]
    fname = result.get("fname_analysis") or {}
    getname = fname.get("get_name_xor") or result.get("get_name_xor") or {}

    globals_evidence: dict[str, Any] = {}
    for key, label in (
        ("gobjects", "GObjects"),
        ("gnames", "GNames/FNamePool"),
        ("gworld", "GWorld"),
        ("gengine", "GEngine"),
    ):
        selected = majors.get(key) or {}
        raw_list = (candidates.get(key) or [])[:8]
        rows = []
        for item in raw_list:
            target = item.get("target_va")
            match = item.get("match_va")
            row = {
                "name": item.get("name"),
                "match_rva": _to_hex(match),
                "target_rva": _to_hex(target),
                "section": _section_name_at(pe, target) if isinstance(target, int) else "?",
                "confidence": item.get("confidence", 0),
                "score": item.get("score", 0),
                "validation_state": item.get("validation_state", "candidate"),
                "versions": item.get("versions", []),
                "disassembly_at_match": _disasm_around(data, pe, match, 16),
            }
            rows.append(row)
        globals_evidence[key] = {
            "label": label,
            "selected_rva": _to_hex(selected.get("target_va")),
            "selected_confidence": selected.get("confidence", 0),
            "validation_state": selected.get("validation_state", "unconfirmed"),
            "candidates": rows,
        }

    xor_candidates = (getname.get("xor_candidates") or [])[:12]
    data_len = len(data)
    xor_rows = []
    for item in xor_candidates:
        off = item.get("offset")
        rva = _rva_of_file_offset(pe, off, data_len) if isinstance(off, int) else None
        xor_rows.append({
            "file_offset": off,
            "rva": _to_hex(rva),
            "key_hex": item.get("key_hex"),
            "encoding": item.get("encoding"),
            "width": item.get("width"),
            "disassembly": _disasm_around(data, pe, rva, 10),
        })

    getname_markers = (getname.get("function_markers") or [])[:6]
    getname_disasm = []
    for marker in getname_markers:
        off = marker.get("offset")
        rva = _rva_of_file_offset(pe, off, data_len) if isinstance(off, int) else None
        if rva is not None:
            getname_disasm.append({
                "marker": marker.get("name"),
                "rva": _to_hex(rva),
                "disassembly": _disasm_around(data, pe, rva, 40),
            })

    version_layout = result.get("version_layout") or {}
    evidence = {
        "engine_version": result.get("engine_version") or "",
        "engine_family": result.get("engine_family") or "",
        "detected_version": result.get("detected_version") or "",
        "version_status": result.get("version_status", "unconfirmed"),
        "image_base": _to_hex(pe.get("image_base")),
        "arch": pe.get("machine", "unknown"),
        "fname_model": result.get("fname") or "",
        "fname_algorithm_candidates": [
            {
                "name": item.get("name"),
                "formula": item.get("formula"),
                "confidence": item.get("confidence", 0),
                "validation_state": item.get("validation_state", "unconfirmed"),
            }
            for item in (fname.get("algorithm_candidates") or [])
        ],
        "entry_layout_candidates": [
            {
                "profile": item.get("profile"),
                "stride": item.get("stride"),
                "entry": item.get("entry"),
                "confidence": item.get("confidence", 0),
            }
            for item in (fname.get("entry_layout_candidates") or [])[:6]
        ],
        "globals": globals_evidence,
        "getname_xor": {
            "status": getname.get("status", "unconfirmed"),
            "key_candidates": (getname.get("key_candidates") or [])[:12],
            "plaintext_candidates": (getname.get("plaintext_candidates") or [])[:8],
            "xor_candidates": xor_rows,
            "getname_disassembly": getname_disasm,
        },
        "encryption_signals": [
            {
                "name": item.get("name"),
                "detail": item.get("detail"),
                "risk": item.get("risk"),
            }
            for item in (result.get("encryption") or []) if isinstance(item, dict)
        ],
        "needs_decryption": bool(result.get("needs_decryption")),
        "signature_hits": [
            {
                "name": item.get("name"),
                "match_rva": _to_hex(item.get("match_va")),
                "target_rva": _to_hex(item.get("target_va")),
                "versions": item.get("versions", []),
                "confidence": item.get("confidence", 0),
            }
            for item in signature_hits
        ],
        "version_layout": _limit(version_layout, max_len=800),
        "static_limitations": (result.get("runtime_validation") or {}).get("static_limitations", []),
    }
    return evidence


def _parse_int_address(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def normalize_ue_assist(raw: Any, image_base: int | None = None) -> dict:
    """规范化 AI 输出为稳定结构;任何字段缺失都不影响报告渲染。

    image_base: 已知的映像基址(来自 PE 头),当模型未逐项返回时用于计算绝对 VA。
    """
    if not isinstance(raw, dict):
        raw = {}
    three = raw.get("three_majors") or raw.get("globals") or {}
    if not isinstance(three, dict):
        three = {}
    norm_three = {}
    for key, label in (("gobjects", "GObjects"), ("gnames", "GNames/FNamePool"),
                       ("gworld", "GWorld"), ("gengine", "GEngine")):
        item = three.get(key) or three.get(label) or {}
        if not isinstance(item, dict):
            item = {}
        rva = _parse_int_address(item.get("rva") or item.get("address"))
        item_base = _parse_int_address(item.get("image_base"))
        base = item_base if item_base is not None else image_base
        norm_three[key] = {
            "rva": rva,
            "rva_hex": _to_hex(rva),
            "absolute_va": (base + rva) if (base is not None and rva is not None) else None,
            "absolute_va_hex": _to_hex((base + rva) if (base is not None and rva is not None) else None),
            "confidence": item.get("confidence"),
            "reason": str(item.get("reason") or "")[:2000],
        }
    gna = raw.get("getname_algorithm") or {}
    if not isinstance(gna, dict):
        gna = {}
    da = raw.get("decryption_algorithm") or {}
    if not isinstance(da, dict):
        da = {}
    notes = raw.get("notes") or []
    if not isinstance(notes, list):
        notes = [str(notes)]
    return {
        "three_majors": norm_three,
        "getname_algorithm": {
            "model": str(gna.get("model") or "")[:64],
            "block_bits": gna.get("block_bits"),
            "entry_stride": gna.get("entry_stride"),
            "header_info_offset": gna.get("header_info_offset"),
            "wide_bit": gna.get("wide_bit"),
            "length_shift": gna.get("length_shift"),
            "key_hex": str(gna.get("key_hex") or ""),
            "description": str(gna.get("description") or "")[:4000],
            "steps": gna.get("steps") if isinstance(gna.get("steps"), list) else [],
            "evidence": gna.get("evidence") if isinstance(gna.get("evidence"), list) else [],
        },
        "decryption_algorithm": {
            "detected": bool(da.get("detected")),
            "algorithm": str(da.get("algorithm") or "")[:2000],
            "key_hex": str(da.get("key_hex") or ""),
            "description": str(da.get("description") or "")[:4000],
            "steps": da.get("steps") if isinstance(da.get("steps"), list) else [],
            "evidence": da.get("evidence") if isinstance(da.get("evidence"), list) else [],
        },
        "notes": [str(note)[:1000] for note in notes[:16]],
        "raw": _limit(raw, max_len=6000),
    }


_UE_SYSTEM_PROMPT = (
    "You are a senior Unreal Engine reverse-engineering expert. The input is static evidence "
    "extracted from a dumped PE image of a UE game executable. Candidate addresses are RVAs "
    "inside the image (absolute address = image_base + RVA); the absolute VA of a candidate is "
    "only meaningful after the module is loaded at its preferred base. "
    "Choose the single most likely precise address for each global from the candidates and the "
    "disassembly evidence. State the FName/GetName decoding algorithm precisely (FNamePool block "
    "index bits, entry stride, header info offset, wide-bit position, length shift, and any XOR "
    "key). If decryption is required, derive the concrete algorithm and key from the evidence; "
    "otherwise set detected=false. Never invent memory values that are not supported by evidence. "
    "Respond with exactly one JSON object, no prose or markdown fences."
)

_UE_USER_TEMPLATE = (
    "Engine: {engine} (family {family}, status {version_status})\n"
    "ImageBase: {image_base}, arch: {arch}\n"
    "FName model: {fname_model}\n\n"
    "=== Evidence ===\n{evidence}\n\n"
    "Return JSON with this schema:\n"
    "{{\n"
    '  "three_majors": {{"gobjects": {{"rva": "0x..", "confidence": 0-100, "reason": ".."}}, '
    '"gnames": {{...}}, "gworld": {{...}}, "gengine": {{...}}}},\n'
    '  "getname_algorithm": {{"model": "fnamepool|direct", "block_bits": 16, "entry_stride": 2, '
    '"header_info_offset": 0, "wide_bit": 0, "length_shift": 6, "key_hex": "0x.. or empty", '
    '"description": "..", "steps": [".."], "evidence": [".."]}},\n'
    '  "decryption_algorithm": {{"detected": true|false, "algorithm": "..", "key_hex": "0x.. or empty", '
    '"description": "..", "steps": [".."], "evidence": [".."]}},\n'
    '  "notes": [".."]\n'
    "}}"
)


def assist_ue_analysis(evidence: dict, cfg: dict | None = None) -> dict:
    """调用 AI 并返回规范化结果。

    失败(未配置/请求失败)时抛 RuntimeError,由调用方决定 skip 还是失败。
    """
    cfg = dict(cfg) if cfg is not None else ai_svc.load_config()
    if not cfg.get("enabled") or not cfg.get("api_key") or not cfg.get("base_url"):
        raise RuntimeError("AI 模型未配置。请先在「AI 模型」面板配置 base_url/api_key/model 并启用。")
    user = _UE_USER_TEMPLATE.format(
        engine=evidence.get("engine_version") or evidence.get("engine_family") or "unknown",
        family=evidence.get("engine_family") or "unknown",
        version_status=evidence.get("version_status", "unconfirmed"),
        image_base=evidence.get("image_base") or "unknown",
        arch=evidence.get("arch") or "unknown",
        fname_model=evidence.get("fname_model") or "unknown",
        evidence=json.dumps(evidence, ensure_ascii=False)[:26000],
    )
    runtime = dict(cfg)
    runtime["max_tokens"] = min(int(runtime.get("max_tokens", 2000) or 2000), 4000)
    runtime["temperature"] = 0.1
    reply = ai_svc.chat(runtime, [
        {"role": "system", "content": _UE_SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ])
    parsed = _extract_json(reply)
    known_base = _parse_int_address(evidence.get("image_base"))
    normalized = normalize_ue_assist(parsed, image_base=known_base)
    normalized["raw_response"] = (reply or "")[:8000]
    normalized["model"] = cfg.get("model", "")
    normalized["configured"] = True
    normalized["ai_output"] = True
    return normalized


def _extract_json(content: Any) -> dict:
    """从模型输出中提取首个 JSON 对象(容错 fence/前后杂文)。"""
    if isinstance(content, dict):
        return content
    if not isinstance(content, str):
        return {}
    source = content.strip().lstrip("\ufeff")
    fence = re.search(r"```(?:json)?\s*(.*?)```", source, re.IGNORECASE | re.DOTALL)
    candidates = ([fence.group(1).strip()] if fence else []) + [source]
    decoder = json.JSONDecoder()
    for candidate in candidates:
        for match in re.finditer(r"\{", candidate):
            try:
                parsed, _ = decoder.raw_decode(candidate[match.start():])
                if isinstance(parsed, dict):
                    return parsed
            except (TypeError, ValueError):
                continue
    return {}


def assist_ue_analysis_safe(evidence: dict, cfg: dict | None = None) -> dict:
    """安全包装:失败返回结构化错误信息,供节点决定 skip 而非 abort。"""
    try:
        return assist_ue_analysis(evidence, cfg)
    except Exception as exc:
        return {
            "configured": False,
            "error": str(exc),
            "three_majors": {},
            "getname_algorithm": {},
            "decryption_algorithm": {},
            "notes": [],
            "raw_response": "",
            "ai_output": True,
        }
