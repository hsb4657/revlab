"""Static UE evidence helpers used by the graph workflow.

The input to this module is a PE/dump, not a live process.  It follows the
same broad strategy used by public UE dumpers: locate engine strings and
instruction references, enumerate RIP-relative globals, and rank candidates
against the expected object/name-pool shapes.  Every result is explicitly a
candidate until a runtime object walk validates it.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import re
import struct
from typing import Any


_ASCII_MARKERS: dict[str, tuple[bytes, ...]] = {
    "getname": (b"GetName", b"UObject_GetName", b"FName::ToString", b"FName::AppendString"),
    "fname": (b"FName", b"FNameEntry", b"FNamePool", b"FNameEntryId", b"NamePoolData"),
    "reflection": (b"UObject", b"UClass", b"UField", b"UStruct", b"UFunction", b"FField", b"FProperty", b"ProcessEvent"),
    "globals": (b"GWorld", b"GEngine", b"GObjects", b"GNames", b"GUObjectArray", b"ObjObjects"),
    "known_names": (b"None", b"ByteProperty", b"IntProperty", b"CoreUObject", b"/Script/CoreUObject"),
}


@dataclass(frozen=True)
class _Section:
    name: str
    raw_ptr: int
    raw_size: int
    va: int
    executable: bool
    writable: bool


def _int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (TypeError, ValueError):
        return default


def _sections(pe: dict[str, Any]) -> list[_Section]:
    out: list[_Section] = []
    for row in pe.get("sections", []) or []:
        flags = {str(item).lower() for item in row.get("flags", []) or []}
        chars = _int(row.get("characteristics"), 0)
        out.append(_Section(
            str(row.get("name", "")),
            _int(row.get("raw_ptr")),
            _int(row.get("raw_size")),
            _int(row.get("virtual_address")),
            "exec" in flags or bool(chars & 0x20000000),
            "write" in flags or bool(chars & 0x80000000),
        ))
    return out


def _section_for_raw(sections: list[_Section], offset: int) -> _Section | None:
    for section in sections:
        if section.raw_ptr <= offset < section.raw_ptr + max(section.raw_size, 1):
            return section
    return None


def _raw_to_rva(sections: list[_Section], offset: int) -> int | None:
    section = _section_for_raw(sections, offset)
    if not section:
        return None
    return section.va + (offset - section.raw_ptr)


def _marker_hits(data: bytes) -> dict[str, list[dict[str, Any]]]:
    lowered = data.lower()
    hits: dict[str, list[dict[str, Any]]] = {key: [] for key in _ASCII_MARKERS}
    for group, markers in _ASCII_MARKERS.items():
        for marker in markers:
            start = 0
            needle = marker.lower()
            while True:
                pos = lowered.find(needle, start)
                if pos < 0:
                    break
                hits[group].append({"marker": marker.decode("latin-1"), "offset": pos, "encoding": "ascii"})
                start = pos + 1
                if len(hits[group]) >= 400:
                    break
    # Many UE builds retain UTF-16 symbol/name strings even when ASCII strings
    # have been stripped.  Record a small sample rather than duplicating every
    # hit in the report.
    for group, markers in _ASCII_MARKERS.items():
        for marker in markers:
            needle = b"".join(bytes((byte, 0)) for byte in marker)
            start = 0
            while True:
                pos = data.find(needle, start)
                if pos < 0:
                    break
                hits[group].append({"marker": marker.decode("latin-1"), "offset": pos, "encoding": "utf-16le"})
                start = pos + 2
                if len(hits[group]) >= 400:
                    break
    return hits


def _xor_instruction_hits(data: bytes, sections: list[_Section]) -> list[dict[str, Any]]:
    """Find common x64 XOR opcode forms without pretending to decompile them."""
    text_ranges = [s for s in sections if s.executable and s.raw_size]
    hits: list[dict[str, Any]] = []
    # register/memory XOR forms and immediate XOR forms.  The scanner records
    # bytes and a short reason; callers still need a function-level/runtime
    # check before calling this an encryption routine.
    for section in text_ranges:
        end = min(len(data), section.raw_ptr + section.raw_size)
        blob = data[section.raw_ptr:end]
        # bytes.find is implemented in C and matters for large UE dumps.
        for opcode in (0x30, 0x31, 0x32, 0x33, 0x34, 0x35):
            start = 0
            needle = bytes((opcode,))
            while True:
                index = blob.find(needle, start)
                if index < 0:
                    break
                size = 2 if opcode in (0x34, 0x35) else 3
                if index + size <= len(blob):
                    hits.append({
                        "offset": section.raw_ptr + index,
                        "rva": section.va + index,
                        "bytes": blob[index:index + size].hex(" "),
                        "form": "xor-register-or-memory",
                    })
                start = index + 1
                if len(hits) >= 2500:
                    return hits
        for opcode in (0x80, 0x81, 0x83):
            start = 0
            needle = bytes((opcode,))
            while True:
                index = blob.find(needle, start)
                if index < 0:
                    break
                if index + 2 < len(blob) and ((blob[index + 1] >> 3) & 7) == 6:
                    imm_size = 1 if opcode in (0x80, 0x83) else 4
                    if index + 2 + imm_size <= len(blob):
                        hits.append({
                            "offset": section.raw_ptr + index,
                            "rva": section.va + index,
                            "bytes": blob[index:index + 2 + imm_size].hex(" "),
                            "form": "xor-immediate",
                        })
                start = index + 1
                if len(hits) >= 2500:
                    return hits
    return hits


def _rip_candidates(data: bytes, sections: list[_Section]) -> list[dict[str, Any]]:
    """Enumerate RIP-relative loads/leas and classify their target section."""
    out: list[dict[str, Any]] = []
    exec_sections = [s for s in sections if s.executable and s.raw_size]
    opcodes = {
        b"\x48\x8b\x05": "mov-rax",
        b"\x48\x8b\x0d": "mov-rcx",
        b"\x48\x8b\x15": "mov-rdx",
        b"\x48\x8b\x1d": "mov-rbx",
        b"\x48\x8b\x35": "mov-rsi",
        b"\x48\x8b\x3d": "mov-rdi",
        b"\x48\x8d\x05": "lea-rax",
        b"\x48\x8d\x0d": "lea-rcx",
        b"\x48\x8d\x15": "lea-rdx",
        b"\x48\x8d\x1d": "lea-rbx",
    }
    for section in exec_sections:
        end = min(len(data), section.raw_ptr + section.raw_size)
        blob = data[section.raw_ptr:end]
        for opcode, form in opcodes.items():
            start = 0
            while True:
                rel_at = blob.find(opcode, start)
                if rel_at < 0 or rel_at + 7 > len(blob):
                    break
                disp = struct.unpack_from("<i", blob, rel_at + 3)[0]
                target_rva = section.va + rel_at + 7 + disp
                target_raw = None
                target_section = None
                for candidate in sections:
                    if candidate.va <= target_rva < candidate.va + max(candidate.raw_size, 1):
                        target_section = candidate
                        target_raw = candidate.raw_ptr + (target_rva - candidate.va)
                        break
                if target_section:
                    out.append({
                        "match_offset": section.raw_ptr + rel_at,
                        "match_rva": section.va + rel_at,
                        "target_rva": target_rva,
                        "target_raw": target_raw,
                        "target_section": target_section.name,
                        "target_writable": target_section.writable,
                        "form": form,
                        "disp": disp,
                    })
                start = rel_at + 1
                if len(out) >= 10000:
                    return out
    return out


def _rank_global_candidates(rips: list[dict[str, Any]], markers: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    """Rank global slots using target section, reuse count and nearby motifs."""
    counts = Counter((row.get("target_rva"), row.get("target_raw")) for row in rips if row.get("target_rva") is not None)
    rows: list[dict[str, Any]] = []
    for row in rips:
        key = (row.get("target_rva"), row.get("target_raw"))
        repeat = counts[key]
        score = 15
        evidence = [{"kind": "rip_relative_reference", "detail": row.get("form"), "match_offset": row.get("match_offset")}]
        if row.get("target_writable"):
            score += 25
            evidence.append({"kind": "writable_global_target", "detail": "RIP target resolves into a writable image section."})
        if repeat > 1:
            score += min(30, repeat * 5)
            evidence.append({"kind": "reused_global", "detail": f"Same target referenced {repeat} times."})
        rows.append({
            "target_rva": row.get("target_rva"),
            "target_raw": row.get("target_raw"),
            "target_va": row.get("target_rva"),
            "match_offset": row.get("match_offset"),
            "match_va": row.get("match_rva"),
            "name": "RIP-relative global candidate",
            "status": "candidate",
            "validation_state": "candidate",
            "confidence": min(score, 85),
            "score": min(score, 85),
            "evidence_status": "static_candidate",
            "evidence": evidence,
            "source": "static_rip_scan",
            "required_runtime_evidence": [
                "Read the candidate slot after the module is loaded.",
                "Validate pointer range and the expected engine structure invariants.",
            ],
        })
    rows.sort(key=lambda item: (-item["confidence"], -(counts[(item.get("target_rva"), item.get("target_raw"))])))
    unique: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any]] = set()
    for row in rows:
        key = (row.get("target_rva"), row.get("target_raw"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    # Use marker presence to bias the first few slots for the matching global.
    # This is intentionally a hint, not a confirmed name assignment.
    has_world = bool(markers.get("globals"))
    result = {"gobjects": [], "gnames": [], "gworld": [], "gengine": []}
    for index, row in enumerate(unique[:96]):
        if index < 8:
            result["gobjects"].append({**row, "heuristic_role": "object-array-slot"})
        if index < 16:
            result["gnames"].append({**row, "heuristic_role": "name-pool-or-name-array-slot"})
        if has_world and index < 24:
            result["gworld"].append({**row, "heuristic_role": "world-or-engine-global-slot"})
        if index < 24:
            result["gengine"].append({**row, "heuristic_role": "engine-global-slot"})
    return result


# ================================================================
# 字符串交叉引用分析(借鉴 Dumper-7 / UE4SS / UnrealDumper 方法)
# 通过关键字符串("None"/"PersistentLevel"/"GNames"/"GObjects")找到引用
# 它们的代码,从代码中提取全局变量地址。
# ================================================================

# 每个全局变量对应的关键字符串(代码中必然会引用)
# 参考 Dumper-7 / UE4SS 方法:用全局变量自身的名字 + UE 源码中的结构名
_STRING_XREF_TARGETS: dict[str, tuple[bytes, ...]] = {
    "gnames": (b"GNames", b"FNamePool", b"NamePoolData", b"FNameEntryId"),
    "gobjects": (b"GObjects", b"GUObjectArray", b"ObjObjects", b"FUObjectArray"),
    "gworld": (b"GWorld", b"PersistentLevel", b"CurrentLevel"),
    "gengine": (b"GEngine", b"UEngine", b"GameEngine"),
}

# 字符串可用性检查(哪些关键字符串在 dump 中存在)
def check_string_availability(data: bytes) -> dict[str, bool]:
    """检查关键字符串是否在 dump 中保留(未被剥离)。"""
    check = {
        "GNames": b"GNames" in data,
        "GObjects": b"GObjects" in data,
        "GWorld": b"GWorld" in data,
        "GEngine": b"GEngine" in data,
        "FNamePool": b"FNamePool" in data,
        "GUObjectArray": b"GUObjectArray" in data,
        "ObjObjects": b"ObjObjects" in data,
        "PersistentLevel": b"PersistentLevel" in data,
        "UWorld": b"UWorld" in data,
        "UEngine": b"UEngine" in data,
        "None": data.count(b"None") < 10,  # 太常见则不可靠
    }
    return check


def _string_xref_global_candidates(data: bytes, sections: list[_Section]) -> dict[str, list[dict[str, Any]]]:
    """通过字符串交叉引用定位全局变量(核心方法)。

    算法(Dumper-7 / UE4SS 方法):
    1. 在 .rdata 节区找到关键字符串位置(如 "None" 在 GNames[0])
    2. 扫描 .text 节区,找引用这些字符串的 RIP-relative 指令
       (lea/mov reg, [rip + str_addr])
    3. 在引用字符串的函数附近(前后 128 字节),找其它 RIP-relative 指令
       指向 .data 节区(可写)的目标 — 那就是全局变量地址
    4. 按目标地址聚簇,最高引用数的 = 最可能的全局变量
    """
    rdata_sections = [s for s in sections if not s.executable and not s.writable and s.raw_size]
    exec_sections = [s for s in sections if s.executable and s.raw_size]
    data_sections = [s for s in sections if s.writable and s.raw_size]

    result: dict[str, list[dict[str, Any]]] = {k: [] for k in _STRING_XREF_TARGETS}

    # 预计算:所有 .data 节区的 VA 范围(用于快速判断目标是否在 .data)
    data_ranges = [(s.va, s.va + max(s.raw_size, 1)) for s in data_sections]

    def _in_data_section(rva: int) -> bool:
        return any(lo <= rva < hi for lo, hi in data_ranges)

    # 预计算:所有 exec 指令的 RIP-relative 目标 → (match_rva, target_rva)
    # 单次扫描,避免对每个字符串重复扫描
    all_rip_loads: list[tuple[int, int]] = []  # (match_rva, target_rva)
    for exec_sec in exec_sections:
        end = min(len(data), exec_sec.raw_ptr + exec_sec.raw_size)
        blob = data[exec_sec.raw_ptr:end]
        for prefix in (b"\x48\x8d", b"\x48\x8b"):  # lea/mov
            for modrm in range(0x05, 0x40, 8):
                if (modrm >> 6) != 0 or (modrm & 7) != 5:
                    continue
                opcode = prefix + bytes([modrm])
                scan = 0
                while True:
                    idx = blob.find(opcode, scan)
                    if idx < 0 or idx + 7 > len(blob):
                        break
                    scan = idx + 1
                    disp = struct.unpack_from("<i", blob, idx + 3)[0]
                    match_rva = exec_sec.va + idx
                    target_rva = match_rva + 7 + disp
                    all_rip_loads.append((match_rva, target_rva))

    # 按目标 RVA 建索引(用于快速查找引用某个 RVA 的指令)
    target_to_matches: dict[int, list[int]] = {}
    for match_rva, target_rva in all_rip_loads:
        target_to_matches.setdefault(target_rva, []).append(match_rva)

    for role, needles in _STRING_XREF_TARGETS.items():
        candidate_addrs: Counter = Counter()
        candidate_evidence: dict[tuple, list] = {}

        for needle in needles:
            # 1. 找字符串位置 → RVA
            str_rvas: set[int] = set()
            start = 0
            while True:
                pos = data.find(needle, start)
                if pos < 0:
                    break
                rva = _raw_to_rva(sections, pos)
                if rva is not None:
                    str_rvas.add(rva)
                start = pos + 1
                if len(str_rvas) >= 20:
                    break

            if not str_rvas:
                continue

            # 2. 找引用这些字符串的指令
            str_ref_sites: list[tuple[int, int]] = []
            for str_rva in str_rvas:
                str_ref_sites.extend((site_rva, str_rva)
                                     for site_rva in target_to_matches.get(str_rva, []))

            # 3. 在引用字符串的指令附近,找指向 .data 的 RIP loads
            for site_rva, str_rva in str_ref_sites:
                for match_rva, target_rva in all_rip_loads:
                    if abs(match_rva - site_rva) > 128:
                        continue
                    if match_rva == site_rva:
                        continue
                    if _in_data_section(target_rva):
                        key = (target_rva,)
                        candidate_addrs[key] += 1
                        if key not in candidate_evidence:
                            candidate_evidence[key] = []
                        candidate_evidence[key].append({
                            "string": needle.decode("latin-1", "ignore"),
                            "str_rva": str_rva,
                            "match_rva": match_rva,
                            "target_rva": target_rva,
                        })

        # 4. 按引用数排序
        for (target_rva,), count in candidate_addrs.most_common(8):
            evidence_list = candidate_evidence.get((target_rva,), [])
            result[role].append({
                "target_rva": target_rva,
                "target_va": target_rva,
                "name": f"string-xref-{role}",
                "status": "candidate",
                "validation_state": "candidate",
                "confidence": min(90, 50 + count * 5),
                "score": min(90, 50 + count * 5),
                "evidence_status": "static_string_xref",
                "source": "string_cross_reference",
                "xref_count": count,
                "evidence": [
                    {"kind": "string_xref", "detail": f"{count} code references to known strings near this global",
                     "string_refs": evidence_list[:8]}
                ],
                "required_runtime_evidence": [
                    "Read the candidate slot after the module is loaded.",
                    "Validate pointer range and the expected engine structure invariants.",
                ],
            })

    return result


def analyze_static_evidence(data: bytes, pe: dict[str, Any]) -> dict[str, Any]:
    """Return explainable static evidence for UE-specific workflow nodes."""
    sections = _sections(pe)
    markers = _marker_hits(data)
    rips = _rip_candidates(data, sections)
    xor_hits = _xor_instruction_hits(data, sections)
    marker_offsets = [item["offset"] for item in markers.get("getname", [])]
    # A dump that retains FName/GetName symbols and has XOR instructions in
    # executable code is a strong static signal for a name decode path.  It is
    # still called a candidate until a function-level or runtime observation
    # ties the XOR to the decoder.
    xor_near_getname = []
    if marker_offsets:
        for hit in xor_hits:
            if any(abs(int(hit["offset"]) - int(offset)) <= 0x200000 for offset in marker_offsets):
                xor_near_getname.append(hit)
    getname_xor = bool(marker_offsets and (xor_near_getname or len(xor_hits) >= 8))
    known = markers.get("known_names", [])
    reflection = markers.get("reflection", [])
    family = "UE4/UE5-compatible" if markers.get("fname") or markers.get("reflection") else "unknown"

    # 字符串交叉引用分析(核心方法:通过 "None"/"PersistentLevel" 等关键字符串
    # 找到引用它们的代码,从代码中提取全局变量地址)
    xref_globals = _string_xref_global_candidates(data, sections)

    # 启发式 RIP 扫描(作为补充)
    heuristic_globals = _rank_global_candidates(rips, markers)

    # 合并:字符串 xref 结果优先(高置信度),启发式结果作为补充
    merged_globals: dict[str, list[dict[str, Any]]] = {}
    for role in ("gobjects", "gnames", "gworld", "gengine"):
        xref_list = xref_globals.get(role, [])
        heuristic_list = heuristic_globals.get(role, [])
        # 字符串 xref 结果排在前面(已去重)
        seen_targets: set[int] = set()
        merged: list[dict[str, Any]] = []
        for item in xref_list:
            target = item.get("target_rva")
            if target is not None and target not in seen_targets:
                seen_targets.add(target)
                merged.append(item)
        for item in heuristic_list:
            target = item.get("target_rva")
            if target is not None and target not in seen_targets:
                seen_targets.add(target)
                merged.append(item)
        merged_globals[role] = merged[:96]

    return {
        "engine_family_guess": family,
        "marker_hits": markers,
        "known_name_evidence": {
            "count": len(known),
            "markers": known[:40],
            "strong": len(known) >= 2,
        },
        "reflection_entry_evidence": {
            "count": len(reflection),
            "markers": reflection[:80],
            "strong": len(reflection) >= 3,
        },
        "rip_relative_globals": {
            "count": len(rips),
            "candidates": rips[:500],
        },
        "global_candidates": merged_globals,
        "string_xref_globals": xref_globals,
        "getname": {
            "markers": markers.get("getname", [])[:120],
            "xor_candidate": getname_xor,
            "xor_hits": xor_near_getname[:120] or xor_hits[:120],
            "xor_hit_count": len(xor_near_getname) or len(xor_hits),
            "status": "candidate" if getname_xor else "not_detected",
            "evidence": [
                "GetName/FName::ToString or UObject_GetName marker retained in the dump."
            ] if marker_offsets else [],
            "validation_plan": [
                "Locate the complete GetName/AppendString function and separate name decoding from unrelated XOR instructions.",
                "Record the input FName index, XOR key/operation and decoded output for at least two known names.",
                "Promote the XOR routine only after repeatable plaintext validation.",
            ],
        },
        "static_only": True,
        "limitations": [
            "RIP-relative targets are file-image candidates; a dump does not provide live pointer contents.",
            "String presence and XOR opcode hits do not prove which function owns the global or decoder.",
            "Runtime memory/object traversal is required to promote candidates to confirmed.",
        ],
    }
