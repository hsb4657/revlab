"""Unity IL2CPP 逆向核心模块:元数据(global-metadata.dat)解析、加密检测/解密与 SDK 脱壳导出。

输出格式对齐社区工具 Il2CppDumper:
  输入: GameAssembly.dll + Data/il2cpp_data/Metadata/global-metadata.dat
  输出:
    * Dump.cs        —— C# 风格类定义(namespace / class / 方法 / 字段 / 属性)
    * script.json    —— 结构保留 Il2CppDumper 的 Addresses / Namespace / Script / StringLiteral 四键
    * sdk_cpp/*.hpp  —— 按命名空间生成的 C++ 头文件
    * sdk.json       —— 全量结构化数据(供 AI / MCP 读取)

纯标准库实现(struct / binascii / os / pathlib),不依赖 numpy、dnfile 等第三方解析库。
支持 Il2Cpp metadata 版本 24 ~ 33(头部 offset/count 布局在 24~33 基本一致)。

主要能力:
  * check_metadata_encrypted —— 检测 metadata 是否被加密(magic 校验 + 整体熵)
  * decrypt_metadata         —— 自动解密(多策略:头部搜索 / 单字节 XOR 爆破 / 仅头混淆恢复)
  * parse_metadata           —— 解析头部与全部关键表
  * dump_sdk                 —— 生成 Dump.cs / script.json / sdk_cpp / sdk.json
"""
from __future__ import annotations

import binascii
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path

from ...core.config import config


def recover_split_metadata(game_root: str, out_dir: str) -> dict:
    """Recover a recognized split IL2CPP metadata container into a run directory."""
    from .split_metadata import detect_recipe, recover

    detection = detect_recipe(game_root)
    if not detection.get("supported"):
        return {"recognized": False, "detection": detection, "output": {}, "validation": {},
                "error": detection.get("reason", "No supported split metadata descriptor was found")}
    result = recover(game_root, out_dir)
    result["recognized"] = True
    result["detection"] = detection
    result["manifest_path"] = str(Path(out_dir) / "recovery_manifest.json")
    return result


def _pe_registration_addresses(gameassembly_path: str, metadata_path: str) -> dict:
    """Locate adjacent v24.1 Code/MetadataRegistration structures in a PE.

    Protected Unity builds can remove the usual mscorlib reference chain while
    leaving the runtime registration structures intact.  The metadata
    registration is anchored by the type-definition count twice; for v24.1 the
    code registration immediately precedes it by 0x90 bytes.
    """
    try:
        import pefile
        pe = pefile.PE(gameassembly_path, fast_load=False)
        blob = Path(gameassembly_path).read_bytes()
        metadata = Path(metadata_path).read_bytes()
        type_bytes = struct.unpack_from("<I", metadata, 0xA4)[0]
        type_count = type_bytes // 0x64 if type_bytes and type_bytes % 0x64 == 0 else 0
        if not type_count:
            return {"found": False, "reason": "type definition count is unavailable"}
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        candidates = []
        for section in pe.sections:
            if not (int(section.Characteristics) & 0x40000000):
                continue
            start = int(section.PointerToRawData)
            end = min(len(blob), start + int(section.SizeOfRawData))
            for pos in range(start, max(start, end - 0x80), 8):
                if struct.unpack_from("<Q", blob, pos + 0x50)[0] != type_count:
                    continue
                if struct.unpack_from("<Q", blob, pos + 0x60)[0] != type_count:
                    continue
                code_pos = pos - 0x90
                if code_pos < start:
                    continue
                pairs = [struct.unpack_from("<QQ", blob, code_pos + i * 16) for i in range(9)]
                plausible = sum(1 for count, pointer in pairs if count < 0x1000000 and (count == 0 or pointer >= image_base))
                if plausible < 8:
                    continue
                metadata_rva = int(section.VirtualAddress) + (pos - start)
                code_rva = int(section.VirtualAddress) + (code_pos - start)
                candidates.append({
                    "code_registration": image_base + code_rva,
                    "metadata_registration": image_base + metadata_rva,
                    "type_definitions_count": type_count,
                    "section": section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                    "score": plausible,
                })
        if not candidates:
            return {"found": False, "reason": "registration structure anchor was not found"}
        best = sorted(candidates, key=lambda item: item["score"], reverse=True)[0]
        return {"found": True, **best, "candidate_count": len(candidates)}
    except Exception as exc:
        return {"found": False, "reason": str(exc)}

# ----------------------------------------------------------------------------
# Il2Cpp metadata 常量与布局
# ----------------------------------------------------------------------------

# global-metadata.dat 文件头 magic = 0xFAB11BAF(小端存储)
IL2CPP_MAGIC = b"\xaf\x1b\xb1\xfa"

# metadata 头部固定区(0x00~0xF0 内为 int32 offset + int32 count 成对,24~33 版本布局一致)
# 后续仍有 fieldRefs / referencedAssemblies / attributes / methodSpecs / stringLiteral 等扩展表,
# 但核心 offset/count 布局在 24~33 之间基本不变。
HEADER_SIZE = 0xF8

# (表名, 头部字段偏移)。offset 在 off,count 在 off+4。
_HEADER_FIELDS = [
    ("stringLiteral", 0x08),
    ("stringLiteralData", 0x10),
    ("string", 0x18),
    ("events", 0x20),
    ("properties", 0x28),
    ("methods", 0x30),
    ("parameterDefaultValues", 0x38),
    ("fieldDefaultValues", 0x40),
    ("fieldAndParameterDefaultValueData", 0x48),
    ("fieldMarshaledSizes", 0x50),
    ("parameters", 0x58),
    ("fields", 0x60),
    ("genericParameters", 0x68),
    ("genericParameterConstraints", 0x70),
    ("genericContainers", 0x78),
    ("nestedTypes", 0x80),
    ("interfaces", 0x88),
    ("vtableMethods", 0x90),
    ("interfaceOffsets", 0x98),
    ("typeDefinitions", 0xA0),
    ("images", 0xA8),
    ("assemblies", 0xB0),
    ("fieldRefs", 0xB8),
    ("referencedAssemblies", 0xC0),
    ("attributes", 0xC8),
    ("attributeTypes", 0xD0),
    ("unresolvedVirtualCallParameterTypes", 0xD8),
    ("unresolvedVirtualCallParameterRanges", 0xE0),
    ("windowsRuntimeTypeNames", 0xE8),
    ("windowsRuntimeStrings", 0xF0),
]

# Il2CppTypeDefinition 字段偏移(按版本区分)。
# 注意: 任务描述中"每个 TypeDefinition 48 字节"对应的是结构体前 48 字节的
# 索引/指针区(typeIndex/nameIndex/namespaceIndex/父类索引/方法/字段/属性/接口范围)。
# 为与 Il2CppDumper 的真实解析对齐,这里使用各版本的真实结构体长度与完整字段布局。
_TD_V24 = {  # Il2CppTypeDefinition(v24),92 字节
    "type_index": 0, "name_index": 4, "namespace_index": 8,
    "byval_type_index": 12, "declaring_type_index": 16, "parent_index": 20,
    "element_type_index": 24, "generic_container_index": 28, "flags": 32,
    "field_start": 36, "method_start": 40, "event_start": 44, "property_start": 48,
    "nested_start": 52, "interfaces_start": 56, "vtable_start": 60,
    "interface_offsets_start": 64,
    "method_count": 68, "property_count": 70, "field_count": 72,
    "event_count": 74, "nested_count": 76, "vtable_count": 78,
    "interfaces_count": 80, "interface_offsets_count": 82,
    "bitfield": 84, "token": 88,
}
_TD_SIZE_V24 = 92

_TD_V25 = {  # Il2CppTypeDefinition(v25~v33),76 字节
    "type_index": 0, "name_index": 4, "namespace_index": 8,
    "generic_container_index": 12, "flags": 16,
    "field_start": 20, "method_start": 24, "event_start": 28, "property_start": 32,
    "nested_start": 36, "interfaces_start": 40, "vtable_start": 44,
    "interface_offsets_start": 48,
    "method_count": 52, "property_count": 54, "field_count": 56,
    "event_count": 58, "nested_count": 60, "vtable_count": 62,
    "interfaces_count": 64, "interface_offsets_count": 66,
    "bitfield": 68, "token": 72,
}
_TD_SIZE_V25 = 76

# Il2CppMethodDefinition 字段偏移。
_METHOD_V24 = {  # v24,36 字节
    "method_index": 0, "name_index": 4, "signature": 8, "return_type": 12,
    "parameter_start": 16, "generic": 20, "token": 24,
    "flags": 28, "iflags": 30, "slot": 32, "parameter_count": 34,
}
_METHOD_SIZE_V24 = 36

_METHOD_V25 = {  # v25~v33,32 字节
    "name_index": 0, "signature": 4, "return_type": 8, "parameter_start": 12,
    "generic": 16, "token": 20,
    "flags": 24, "iflags": 26, "slot": 28, "parameter_count": 30,
}
_METHOD_SIZE_V25 = 32

# 字段 / 参数定义均为 12 字节:name_index(4) + type/token(4) + token/type(4)
_FIELD_DEF_SIZE = 12
_PARAM_DEF_SIZE = 12
_PROP_DEF_SIZE = 16  # name_index(4) + get(4) + set(4) + attrs(4)

# Il2CppImageDefinition:v24~26 为 32 字节,v27+ 追加 customAttributeStart/Count 为 40 字节
_IMAGE_HEAD = {
    "name_index": 0, "assembly_index": 4, "type_start": 8, "type_count": 12,
    "exported_start": 16, "exported_count": 20, "entry_point": 24, "token": 28,
}
_IMAGE_SIZE_V26 = 32
_IMAGE_SIZE_V27 = 40

# Il2CppStringLiteral:dataIndex(4) + length(4)
_STRING_LITERAL_SIZE = 8

# .NET 基元类型映射(对齐 Il2CppDumper 的 Dump.cs 输出)
_PRIMITIVE_MAP = {
    "Void": "void", "Boolean": "bool", "Char": "char", "SByte": "sbyte",
    "Byte": "byte", "Int16": "short", "UInt16": "ushort", "Int32": "int",
    "UInt32": "uint", "Int64": "long", "UInt64": "ulong", "Single": "float",
    "Double": "double", "Decimal": "decimal", "String": "string",
    "Object": "object", "Type": "Type",
}

# 合法版本区间
_MIN_VERSION = 24
_MAX_VERSION = 33

# 熵采样上限:超过该字节数则抽样计算(避免大文件全量逐字节循环过慢)
_ENTROPY_SAMPLE_CAP = 4 * 1024 * 1024


# ----------------------------------------------------------------------------
# 基础工具
# ----------------------------------------------------------------------------
def _entropy(data: bytes) -> float:
    """计算字节熵(0~8)。大文件抽样以控制耗时(启发式足够用)。"""
    if not data:
        return 0.0
    if len(data) > _ENTROPY_SAMPLE_CAP:
        step = len(data) // _ENTROPY_SAMPLE_CAP
        data = data[::step]
    n = len(data)
    if n == 0:
        return 0.0
    ent = 0.0
    for i in range(256):
        c = data.count(i)
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _int32(data: bytes, off: int) -> int:
    """带边界检查的 int32(LE)读取,越界返回 0。"""
    if off < 0 or off + 4 > len(data):
        return 0
    return struct.unpack_from("<i", data, off)[0]


def _u16(data: bytes, off: int) -> int:
    if off < 0 or off + 2 > len(data):
        return 0
    return struct.unpack_from("<H", data, off)[0]


def _read_cstr(data: bytes, off: int) -> str:
    """从 off 读取 null 结尾的 UTF-8 字符串。"""
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off)
    if end == -1 or end == off:
        return ""
    try:
        return data[off:end].decode("utf-8")
    except UnicodeDecodeError:
        return data[off:end].decode("latin-1", errors="replace")


def _primitive(full_name: str) -> str:
    """System.Int32 → int 等 .NET 基元映射;非基元原样返回。"""
    if full_name.startswith("System."):
        base = full_name[len("System."):]
        if base in _PRIMITIVE_MAP:
            return _PRIMITIVE_MAP[base]
    return full_name


def _cpp_type(t: str) -> str:
    """C# 类型名 → C++ 类型声明(引用类型加指针,namespace 转 ::)。"""
    if t in ("void", "bool", "char", "sbyte", "byte", "short", "ushort",
             "int", "uint", "long", "ulong", "float", "double", "decimal"):
        return t
    if t == "string":
        return "System::String*"
    if t == "object":
        return "System::Object*"
    if not t or t.startswith("T_"):
        return "System::Object*"
    return t.replace(".", "::") + "*"


def _record_table_sizes(version: int) -> dict[str, int]:
    """Return record sizes for the tables parsed by this module."""
    return {
        "stringLiteral": _STRING_LITERAL_SIZE,
        "events": 8,
        "properties": _PROP_DEF_SIZE,
        "methods": _METHOD_SIZE_V24 if version <= 24 else _METHOD_SIZE_V25,
        "parameters": _PARAM_DEF_SIZE,
        "fields": _FIELD_DEF_SIZE,
        "interfaces": 4,
        "typeDefinitions": _TD_SIZE_V24 if version <= 24 else _TD_SIZE_V25,
        "images": _IMAGE_SIZE_V26 if version <= 26 else _IMAGE_SIZE_V27,
    }


def _read_header_tables(data: bytes) -> dict[str, dict]:
    """Read raw offset/count pairs without assuming count semantics."""
    tables = {}
    for name, off in _HEADER_FIELDS:
        if off + 8 > len(data):
            break
        raw_count = _int32(data, off + 4)
        tables[name] = {
            "offset": _int32(data, off),
            "count": raw_count,
            "raw_count": raw_count,
        }
    return tables


def _infer_table_count_semantics(data: bytes, version: int, tables: dict) -> str:
    """Infer whether record-table counts are byte lengths or record counts.

    Official IL2CPP metadata stores byte lengths in most header count fields.
    Older REVLab fixtures used record counts.  Supporting both keeps fixtures
    useful while making real metadata parse with the official layout.
    """
    byte_score = 0
    record_score = 0
    for name, record_size in _record_table_sizes(version).items():
        table = tables.get(name) or {}
        offset = table.get("offset", 0)
        raw_count = table.get("raw_count", 0)
        if raw_count <= 0 or offset < 0:
            continue
        if raw_count % record_size == 0 and offset + raw_count <= len(data):
            byte_score += 1
        if offset + raw_count * record_size <= len(data):
            record_score += 1
    if byte_score and byte_score >= record_score:
        return "byte_length"
    if record_score:
        return "record_count_compatibility"
    return "unknown"


def _metadata_integrity(data: bytes) -> dict:
    """Validate the header enough to distinguish plaintext from bad input.

    This is intentionally conservative: a valid magic alone never proves that
    a metadata file is usable or that a recovered file was decrypted correctly.
    """
    magic_ok = len(data) >= 4 and data[:4] == IL2CPP_MAGIC
    version = _int32(data, 4) if len(data) >= 8 else 0
    supported_version = _MIN_VERSION <= version <= _MAX_VERSION
    diagnostics = []
    if len(data) < HEADER_SIZE:
        diagnostics.append(f"metadata is too small for the header ({len(data)} bytes)")
    if not magic_ok:
        diagnostics.append("metadata magic does not match 0xFAB11BAF")
    if magic_ok and not supported_version:
        diagnostics.append(
            f"metadata version {version} is outside supported range "
            f"{_MIN_VERSION}-{_MAX_VERSION}"
        )

    tables = _read_header_tables(data)
    semantics = "unknown"
    if magic_ok and supported_version:
        semantics = _infer_table_count_semantics(data, version, tables)
        sizes = _record_table_sizes(version)
        for name, table in tables.items():
            offset = table["offset"]
            raw_count = table["raw_count"]
            if offset < 0 or raw_count < 0:
                diagnostics.append(f"table {name} has a negative offset or count")
                continue
            record_size = sizes.get(name)
            if record_size and raw_count:
                count = raw_count // record_size if semantics == "byte_length" else raw_count
                table["count"] = count
                table["count_semantics"] = semantics
                payload_size = raw_count if semantics == "byte_length" else raw_count * record_size
                if offset < HEADER_SIZE or offset + payload_size > len(data):
                    diagnostics.append(f"table {name} is outside the metadata file")
            elif name == "string" and raw_count and offset:
                # The string table's count is not standardized across every Unity
                # version.  Only reject an impossible offset here.
                if offset < HEADER_SIZE or offset >= len(data):
                    diagnostics.append("string table offset is outside the metadata file")

    return {
        "magic_ok": magic_ok,
        "version": version,
        "supported_version": supported_version,
        "tables": tables,
        "table_count_semantics": semantics,
        "diagnostics": diagnostics,
        "valid": bool(magic_ok and supported_version and not diagnostics),
    }


def _single_byte_xor_header_key(data: bytes) -> int | None:
    """Return a credible whole-file XOR key based on the metadata header."""
    if len(data) < 8:
        return None
    key = data[0] ^ IL2CPP_MAGIC[0]
    if any((data[index] ^ key) != IL2CPP_MAGIC[index] for index in range(4)):
        return None
    version = struct.unpack_from("<i", bytes(value ^ key for value in data[4:8]))[0]
    return key if _MIN_VERSION <= version <= _MAX_VERSION else None


# ----------------------------------------------------------------------------
# 公开函数 1:加密检测
# ----------------------------------------------------------------------------
def check_metadata_encrypted(meta_path: str) -> dict:
    """Inspect metadata without conflating encryption, corruption and absence.

    The legacy ``encrypted`` boolean remains for callers that use it, while
    ``status`` and ``diagnostics`` provide the decision that should be shown to
    a user.  A correct magic is only considered plaintext after header and
    table-boundary validation succeeds.
    """
    p = Path(meta_path)
    if not p.is_file():
        return {
            "status": "missing",
            "encrypted": False,
            "encryption_suspected": False,
            "decrypt_required": False,
            "recovery_recommended": False,
            "parseable": False,
            "magic_ok": False,
            "magic": "",
            "entropy": 0.0,
            "diagnostics": ["metadata file not found"],
            "error": "file not found",
        }
    data = p.read_bytes()
    magic = data[:4]
    ent = round(_entropy(data), 3)
    if len(data) < 16:
        return {
            "status": "corrupt_or_unknown",
            "encrypted": False,
            "encryption_suspected": False,
            "decrypt_required": False,
            "recovery_recommended": False,
            "parseable": False,
            "magic_ok": False,
            "magic": binascii.hexlify(magic).decode(),
            "entropy": ent,
            "diagnostics": ["metadata is smaller than 16 bytes"],
        }

    integrity = _metadata_integrity(data)
    base = {
        "version": integrity["version"],
        "magic_ok": integrity["magic_ok"],
        "magic": "0xFAB11BAF" if integrity["magic_ok"] else binascii.hexlify(magic).decode(),
        "entropy": ent,
        "table_count_semantics": integrity["table_count_semantics"],
        "diagnostics": integrity["diagnostics"],
    }
    if integrity["valid"]:
        return {
            **base,
            "status": "plain",
            "encrypted": False,
            "encryption_suspected": False,
            "decrypt_required": False,
            "recovery_recommended": False,
            "parseable": True,
            "reason": "metadata header and table boundaries are valid",
        }
    if integrity["magic_ok"]:
        return {
            **base,
            "status": "plain_but_invalid",
            "encrypted": False,
            "encryption_suspected": False,
            "decrypt_required": False,
            "recovery_recommended": False,
            "parseable": False,
            "reason": "metadata magic is present but the header is not usable",
        }

    embedded_header = _find_valid_header(data)
    xor_key = _single_byte_xor_header_key(data)
    suspected = ent > 7.5 or embedded_header is not None or xor_key is not None
    diagnostics = list(base["diagnostics"])
    if ent > 7.5:
        diagnostics.append("entropy is high enough to indicate encryption or compression")
    if embedded_header is not None:
        diagnostics.append(f"recoverable metadata header found at 0x{embedded_header[0]:x}")
    if xor_key is not None:
        diagnostics.append(f"single-byte XOR header candidate: 0x{xor_key:02x}")
    status = "encrypted_or_obfuscated" if suspected else "corrupt_or_unknown"
    return {
        **base,
        "status": status,
        "encrypted": suspected,
        "encryption_suspected": suspected,
        "decrypt_required": suspected,
        "recovery_recommended": True,
        "parseable": False,
        "diagnostics": diagnostics,
        "reason": "metadata magic is not at the expected offset",
    }


# ----------------------------------------------------------------------------
# 公开函数 2:自动解密
# ----------------------------------------------------------------------------
def _find_valid_header(data: bytes):
    """在非 0 偏移处搜索被截断/移动的完整 magic+version 头。

    返回 (偏移, version) 或 None。version 需落在合法区间以降低误报。
    """
    start = 0
    while True:
        idx = data.find(IL2CPP_MAGIC, start)
        if idx == -1:
            return None
        if idx != 0 and idx + 8 <= len(data):
            ver = struct.unpack_from("<i", data, idx + 4)[0]
            if _MIN_VERSION <= ver <= _MAX_VERSION:
                return idx, ver
        start = idx + 1


def _try_parse_ok(path) -> dict | None:
    """对解密产物做二次校验:能正常解析头部与计数则视为成功。"""
    try:
        r = parse_metadata(str(path))
        if r.get("valid"):
            return r
    except Exception:
        pass
    return None


def _search_gameassembly(gameassembly_path: Path) -> list:
    """在 GameAssembly.dll 中搜索 metadata 引用线索(策略 4 的提示,不完整实现)。"""
    hints = []
    try:
        data = gameassembly_path.read_bytes()
    except OSError:
        return hints
    if IL2CPP_MAGIC in data:
        hints.append("PE 内嵌 metadata magic 偏移线索")
    for marker in (b"global-metadata", b"il2cpp::vm::MetadataLoader", b"GetMetadataVersion"):
        if marker in data:
            hints.append(f"符号线索: {marker.decode(errors='ignore')}")
    return hints[:3]


def decrypt_metadata(meta_path: str, gameassembly_path: str = "", out_path: str = None) -> dict:
    """加密 metadata 自动解密,输出到 out_path(默认 meta 同目录 *_decrypted.dat)。

    自动策略(按序尝试,命中即止):
      1) 扫描文件内被截断/移动的完整 magic+version 头(搜 4 字节 magic 的其他偏移)
      2) 单字节 XOR 爆破:对 256 个 key 试解前 16 字节,校验解出前 4 字节==magic
         且 version 合理即命中,整文件 XOR
      3) 仅头混淆:前 8 字节可读出版本号但 magic 被改 → 按偏移恢复头部
      4) 用户提供内存 dump(GameAssembly.dll 参数当前仅用于搜索引用线索)——此处仅提示

    返回:
      {"ok": True, "decrypted_path": str, "method": "头部恢复(截断前缀 N 字节)"/"XOR key=0x..",
       "version": int, "note": str}
      {"ok": False, "method": "failed", "note": "..."}  无法自动解密
    """
    p = Path(meta_path)
    if not p.is_file():
        return {
            "ok": False,
            "status": "missing",
            "verified": False,
            "decrypted": False,
            "repaired": False,
            "method": "failed",
            "decrypted_path": "",
            "note": f"文件不存在: {meta_path}",
        }
    data = p.read_bytes()
    if len(data) < 16:
        return {
            "ok": False,
            "status": "decryption_failed",
            "verified": False,
            "decrypted": False,
            "repaired": False,
            "method": "failed",
            "decrypted_path": "",
            "note": "文件过小(<16 字节),无法解密",
        }

    source_status = check_metadata_encrypted(str(p))
    if source_status.get("status") == "plain":
        return {
            "ok": True,
            "status": "not_required",
            "verified": True,
            "decrypted": False,
            "repaired": False,
            "method": "not_required",
            "decrypted_path": str(p),
            "version": source_status.get("version"),
            "note": "metadata is already verified plaintext",
        }

    if out_path is None:
        out_path = str(p.with_name(p.stem + "_decrypted" + p.suffix))
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    notes = []

    # ---- 策略 1:搜索被截断/移动的完整 magic+version 头 ----
    hit = _find_valid_header(data)
    if hit is not None:
        off, ver = hit
        dec = data[off:]
        try:
            out.write_bytes(dec)
            check = _try_parse_ok(out)
            if check:
                # A valid header at a non-zero offset means the container/prefix
                # was repaired, not that encrypted payload bytes were decrypted.
                return {"ok": True, "status": "header_repaired", "verified": True,
                        "decrypted": False, "repaired": True, "decrypted_path": str(out),
                        "method": f"头部恢复(截断前缀 {off} 字节)",
                        "version": check.get("version", ver),
                        "note": f"在偏移 0x{off:x} 找到合法 magic 头,version={ver}"}
        except OSError:
            pass
        notes.append(f"发现偏移 0x{off:x} 的 magic 但校验失败")

    # ---- 策略 2:单字节 XOR 爆破 ----
    head16 = data[:16]
    for key in range(256):
        head = bytes(b ^ key for b in head16)
        if head[:4] != IL2CPP_MAGIC:
            continue
        ver = struct.unpack_from("<i", head, 4)[0]
        if not (_MIN_VERSION <= ver <= _MAX_VERSION):
            continue
        try:
            dec = bytes(b ^ key for b in data)
            out.write_bytes(dec)
            check = _try_parse_ok(out)
            if check:
                return {"ok": True, "status": "decrypted", "verified": True,
                        "decrypted": True, "repaired": False, "decrypted_path": str(out),
                        "method": f"XOR key=0x{key:02x}",
                        "version": check.get("version", ver),
                        "note": f"整文件单字节 XOR(0x{key:02x})解密成功"}
        except OSError:
            break

    # ---- 策略 3:仅头混淆(magic 被改但 version 可读)----
    ver4 = _int32(data, 4)
    if _MIN_VERSION <= ver4 <= _MAX_VERSION and data[:4] != IL2CPP_MAGIC:
        dec = IL2CPP_MAGIC + data[4:]
        try:
            out.write_bytes(dec)
            check = _try_parse_ok(out)
            if check:
                # Structural validation proves the repaired file parses, but it
                # does not prove that any encrypted payload was decrypted.
                return {"ok": True, "status": "header_repaired", "verified": True,
                        "decrypted": False, "repaired": True, "decrypted_path": str(out),
                        "method": "头部恢复",
                        "version": check.get("version", ver4),
                        "note": "magic 被改写但 version 可读,已恢复文件头"}
        except OSError:
            pass
        notes.append("仅头混淆策略无法通过二次校验")

    # ---- 策略 4:GameAssembly.dll 线索提示(当前仅提示,不做完整还原)----
    extra = ""
    if gameassembly_path:
        ga = Path(gameassembly_path)
        if ga.is_file():
            hints = _search_gameassembly(ga)
            if hints:
                extra = "GameAssembly.dll 中搜索到线索: " + "、".join(hints)

    note = "自动解密失败"
    if notes:
        note += ";" + ";".join(notes)
    if extra:
        note += ";" + extra
    note += "。建议提供内存 dump 或人工用 Il2CppDumper 处理。"
    try:
        out.unlink(missing_ok=True)
    except OSError:
        pass
    return {
        "ok": False,
        "status": "decryption_failed",
        "verified": False,
        "decrypted": False,
        "repaired": False,
        "method": "failed",
        "decrypted_path": "",
        "diagnostics": notes,
        "note": note,
    }


# ----------------------------------------------------------------------------
# 公开函数 3:metadata 头部解析
# ----------------------------------------------------------------------------
def parse_metadata(meta_path: str) -> dict:
    """Parse verified plaintext metadata and expose normalized table counts."""
    p = Path(meta_path)
    if not p.is_file():
        return {
            "version": 0,
            "magic_ok": False,
            "valid": False,
            "status": "missing",
            "error": f"文件不存在: {meta_path}",
            "diagnostics": ["metadata file not found"],
        }
    data = p.read_bytes()
    integrity = _metadata_integrity(data)
    tables = integrity["tables"]

    def _t(name):
        return tables.get(name, {"offset": 0, "count": 0, "raw_count": 0})

    parsed = {
        "version": integrity["version"],
        "magic_ok": integrity["magic_ok"],
        "valid": integrity["valid"],
        "status": "plain" if integrity["valid"] else "invalid",
        "supported_version": integrity["supported_version"],
        "table_count_semantics": integrity["table_count_semantics"],
        "string_count": _t("string").get("count", 0),
        "type_count": _t("typeDefinitions").get("count", 0),
        "method_count": _t("methods").get("count", 0),
        "field_count": _t("fields").get("count", 0),
        "string_literal_count": _t("stringLiteral").get("count", 0),
        "sizes": {"header": HEADER_SIZE, "offset": len(data), "file_size": len(data)},
        "tables": tables,
        "warnings": integrity["diagnostics"],
        "diagnostics": integrity["diagnostics"],
    }
    if not integrity["valid"]:
        parsed["error"] = "metadata header is not a verified supported layout"
    return parsed


# ----------------------------------------------------------------------------
# MetadataParser:供 dump_sdk 使用的结构化解析器
# ----------------------------------------------------------------------------
class MetadataParser:
    """metadata 解析器:缓存字符串表与类型定义,提供类型名/方法/字段等解析。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.size = len(self.data)
        self.version = 0
        self.header = {}
        self.table_count_semantics = "unknown"
        self.warnings = []
        self._str_cache = {}
        self._td_cache = {}
        self._load_header()

    # ------------------------- 头部 -------------------------
    def _load_header(self):
        integrity = _metadata_integrity(self.data)
        if not integrity["magic_ok"]:
            raise ValueError("metadata 加密或损坏,请先 decrypt_metadata")
        if not integrity["valid"]:
            detail = "; ".join(integrity["diagnostics"][:3])
            raise ValueError(f"metadata header validation failed: {detail}")
        self.version = integrity["version"]
        self.table_count_semantics = integrity["table_count_semantics"]
        self.header = integrity["tables"]

    def _tab(self, name) -> dict:
        return self.header.get(name, {"offset": 0, "count": 0})

    # ------------------------- 基础读取 -------------------------
    def _i32(self, off: int) -> int:
        return _int32(self.data, off)

    def _u16(self, off: int) -> int:
        return _u16(self.data, off)

    def _read_cstr(self, off: int) -> str:
        return _read_cstr(self.data, off)

    # ------------------------- 字符串 -------------------------
    def string_by_index(self, name_index: int) -> str:
        """nameIndex → 字符串。nameIndex 为相对 string 表基址的偏移。"""
        if name_index in self._str_cache:
            return self._str_cache[name_index]
        base = self._tab("string").get("offset", 0)
        s = self._read_cstr(base + name_index)
        self._str_cache[name_index] = s
        return s

    def string_literals(self) -> list:
        """解析 stringLiteral 表 → [{"Index", "Length", "Value"}]。"""
        tab = self._tab("stringLiteral")
        dat = self._tab("stringLiteralData")
        out = []
        for i in range(tab["count"]):
            off = tab["offset"] + i * _STRING_LITERAL_SIZE
            data_index = self._i32(off)
            length = self._i32(off + 4)
            if length < 0 or length > (self.size - dat["offset"]):
                continue
            raw = self.data[dat["offset"] + data_index: dat["offset"] + data_index + length]
            out.append({"Index": i, "Length": length, "Value": raw.decode("utf-8", errors="replace")})
        return out

    # ------------------------- 类型定义 -------------------------
    def _td_layout(self):
        if self.version <= 24:
            return _TD_V24, _TD_SIZE_V24
        return _TD_V25, _TD_SIZE_V25

    def _td(self, index: int) -> dict | None:
        """解析单个 TypeDefinition → 字段 dict;失败返回 None。"""
        if index < 0:
            return None
        if index in self._td_cache:
            return self._td_cache[index]
        tab = self._tab("typeDefinitions")
        if index >= tab["count"]:
            return None
        lay, size = self._td_layout()
        base = tab["offset"] + index * size
        if base < 0 or base + size > self.size:
            return None
        d = {
            "index": index,
            "name": self.string_by_index(self._i32(base + lay["name_index"])),
            "namespace": self.string_by_index(self._i32(base + lay["namespace_index"])),
            "type_index": self._i32(base + lay["type_index"]),
            "flags": self._i32(base + lay["flags"]),
            "field_start": self._i32(base + lay["field_start"]),
            "field_count": self._u16(base + lay["field_count"]),
            "method_start": self._i32(base + lay["method_start"]),
            "method_count": self._u16(base + lay["method_count"]),
            "property_start": self._i32(base + lay["property_start"]),
            "property_count": self._u16(base + lay["property_count"]),
            "event_start": self._i32(base + lay["event_start"]),
            "event_count": self._u16(base + lay["event_count"]),
            "nested_start": self._i32(base + lay["nested_start"]),
            "nested_count": self._u16(base + lay["nested_count"]),
            "interfaces_start": self._i32(base + lay["interfaces_start"]),
            "interfaces_count": self._u16(base + lay["interfaces_count"]),
            "vtable_start": self._i32(base + lay["vtable_start"]),
            "vtable_count": self._u16(base + lay["vtable_count"]),
            "token": self._i32(base + lay["token"]),
        }
        # 父类:v24 直接有 parent_index;v25+ 元数据中无父类字段,
        # 需运行时 Il2CppType 表(在 GameAssembly.dll 中),此处留空并记录。
        if self.version <= 24:
            d["parent_index"] = self._i32(base + lay["parent_index"])
        else:
            d["parent_index"] = None
        self._td_cache[index] = d
        return d

    def parent_name(self, td: dict) -> str:
        """解析父类名;Object 根类返回空串。"""
        pi = td.get("parent_index")
        if pi is None:
            return ""
        if pi < 0:
            return ""
        pt = self._td(pi)
        if pt and pt.get("name"):
            ns = pt.get("namespace", "")
            return f"{ns}.{pt['name']}" if ns else pt["name"]
        return ""

    def _type_name(self, type_index: int) -> str:
        """Il2CppType 索引 → 类型名(务实解析)。

        编码说明(与 il2cpp metadata 一致):
          * bit30(0x40000000):指针/引用修饰
          * bit29(0x20000000):数组/GC 引用修饰
          * 低位数值若 < typeDefinitions.count,直接映射到 TypeDefinition 表
        无法解析的类型名以 T_<idx> 占位。
        """
        if type_index is None:
            return "void"
        raw = type_index & 0xFFFFFFFF
        mod = ""
        if raw & 0x40000000:
            mod = "*"
            raw &= 0x3FFFFFFF
        if raw & 0x20000000:
            mod = "[]" if not mod else mod
            raw &= 0x1FFFFFFF
        tab = self._tab("typeDefinitions")
        if 0 <= raw < tab["count"]:
            td = self._td(raw)
            if td and td.get("name"):
                nm = td["name"]
                ns = td.get("namespace", "")
                full = f"{ns}.{nm}" if ns else nm
                return _primitive(full) + mod
        return f"T_{type_index}{mod}"

    # ------------------------- 字段/参数/方法/属性/接口 -------------------------
    def _field(self, index: int) -> dict | None:
        tab = self._tab("fields")
        if index < 0 or index >= tab["count"]:
            return None
        base = tab["offset"] + index * _FIELD_DEF_SIZE
        if base < 0 or base + _FIELD_DEF_SIZE > self.size:
            return None
        return {
            "index": index,
            "name": self.string_by_index(self._i32(base + 0)),
            "type": self._type_name(self._i32(base + 4)),
            "token": self._i32(base + 8),
        }

    def _parameter(self, index: int) -> dict | None:
        tab = self._tab("parameters")
        if index < 0 or index >= tab["count"]:
            return None
        base = tab["offset"] + index * _PARAM_DEF_SIZE
        if base < 0 or base + _PARAM_DEF_SIZE > self.size:
            return None
        return {
            "index": index,
            "name": self.string_by_index(self._i32(base + 0)),
            "type": self._type_name(self._i32(base + 8)),
            "token": self._i32(base + 4),
        }

    def _method(self, index: int) -> dict | None:
        tab = self._tab("methods")
        if index < 0 or index >= tab["count"]:
            return None
        if self.version <= 24:
            lay, size = _METHOD_V24, _METHOD_SIZE_V24
        else:
            lay, size = _METHOD_V25, _METHOD_SIZE_V25
        base = tab["offset"] + index * size
        if base < 0 or base + size > self.size:
            return None
        name = self.string_by_index(self._i32(base + lay["name_index"]))
        ret = self._type_name(self._i32(base + lay["return_type"]))
        pcount = self._u16(base + lay["parameter_count"])
        pstart = self._i32(base + lay["parameter_start"])
        params = []
        for i in range(pcount):
            p = self._parameter(pstart + i)
            if p is None:
                params.append({"name": f"arg{i}", "type": "T_unknown"})
            else:
                params.append({"name": p["name"], "type": p["type"]})
        args = ", ".join(f"{x['type']} {x['name']}" for x in params)
        return {
            "index": index,
            "name": name,
            "return_type": ret,
            "parameters": params,
            "signature": f"{ret} {name}({args})",
            "flags": self._u16(base + lay["flags"]),
            "token": self._i32(base + lay["token"]),
        }

    def _property(self, index: int) -> dict | None:
        tab = self._tab("properties")
        if index < 0 or index >= tab["count"]:
            return None
        base = tab["offset"] + index * _PROP_DEF_SIZE
        if base < 0 or base + _PROP_DEF_SIZE > self.size:
            return None
        name = self.string_by_index(self._i32(base + 0))
        get_idx = self._i32(base + 4)
        set_idx = self._i32(base + 8)
        ptype = "T_unknown"
        g = self._method(get_idx) if get_idx >= 0 else None
        s = self._method(set_idx) if set_idx >= 0 else None
        if g:
            ptype = g["return_type"]
        elif s and s["parameters"]:
            ptype = s["parameters"][-1]["type"]
        return {
            "index": index,
            "name": name,
            "type": ptype,
            "get_method": get_idx if get_idx >= 0 else None,
            "set_method": set_idx if set_idx >= 0 else None,
            "get_method_name": g["name"] if g else "",
            "set_method_name": s["name"] if s else "",
            "attrs": self._i32(base + 12),
        }

    def _interfaces(self, start: int, count: int) -> list:
        tab = self._tab("interfaces")
        out = []
        for i in range(count):
            ti = self._i32(tab["offset"] + (start + i) * 4)
            out.append(self._type_name(ti))
        return out

    # ------------------------- images -------------------------
    def _image(self, index: int) -> dict | None:
        tab = self._tab("images")
        if index < 0 or index >= tab["count"]:
            return None
        size = _IMAGE_SIZE_V26 if self.version <= 26 else _IMAGE_SIZE_V27
        base = tab["offset"] + index * size
        if base < 0 or base + size > self.size:
            return None
        return {
            "index": index,
            "name": self.string_by_index(self._i32(base + _IMAGE_HEAD["name_index"])),
            "assembly_index": self._i32(base + _IMAGE_HEAD["assembly_index"]),
            "type_start": self._i32(base + _IMAGE_HEAD["type_start"]),
            "type_count": self._i32(base + _IMAGE_HEAD["type_count"]),
            "token": self._i32(base + _IMAGE_HEAD["token"]),
        }

    # ------------------------- 遍历 -------------------------
    def type_definitions(self) -> list:
        """遍历全部 TypeDefinition,单个失败跳过并记录 warning。"""
        tab = self._tab("typeDefinitions")
        out = []
        for i in range(tab["count"]):
            try:
                td = self._td(i)
                if td is None:
                    continue
                out.append(td)
            except Exception as e:  # noqa: BLE001
                self.warnings.append(f"typeDefinitions[{i}] 解析失败: {e}")
        return out


# ----------------------------------------------------------------------------
# 公开函数 4:SDK 脱壳导出
# ----------------------------------------------------------------------------
def _build_dump_cs(parser: MetadataParser, types: list, stats: dict) -> str:
    """生成 Dump.cs(C# 风格,对齐 Il2CppDumper)。"""
    lines = [
        "// Dump.cs generated by REVLab Unity IL2CPP module (aligned with Il2CppDumper)",
        f"// IL2CPP metadata version: {parser.version}",
        f"// TypeDefinitions: {stats['types']}  Methods: {stats['methods']}  Fields: {stats['fields']}",
        "",
    ]
    # 按命名空间分组(保持首次出现顺序)
    groups = []
    seen = set()
    for td in types:
        ns = td["namespace"] or ""
        if ns not in seen:
            seen.add(ns)
            groups.append((ns, []))
        for g in groups:
            if g[0] == ns:
                g[1].append(td)
                break
    for ns, tds in groups:
        lines.append(f"namespace {ns or 'GlobalNamespace'}")
        lines.append("{")
        for td in tds:
            base = parser.parent_name(td) or "object"
            lines.append(f"\tpublic class {td['name']} : {base} // TypeDefIndex: {td['index']}")
            lines.append("\t{")
            if td["fields"]:
                lines.append("\t\t// Fields")
                for f in td["fields"]:
                    lines.append(f"\t\tpublic {f['type']} {f['name']}; // FieldIndex: {f['index']}")
            if td["properties"]:
                lines.append("\t\t// Properties")
                for pr in td["properties"]:
                    acc = []
                    if pr["get_method"] is not None:
                        acc.append("get;")
                    if pr["set_method"] is not None:
                        acc.append("set;")
                    lines.append(f"\t\tpublic {pr['type']} {pr['name']} {{ {' '.join(acc)} }} // PropertyIndex: {pr['index']}")
            if td["methods"]:
                lines.append("\t\t// Methods")
                for m in td["methods"]:
                    args = ", ".join(f"{p['type']} {p['name']}" for p in m["parameters"])
                    lines.append(f"\t\tpublic {m['return_type']} {m['name']} ({args}) {{ }} // MethodIndex: {m['index']}")
            lines.append("\t}")
            lines.append("")
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


def _build_script_json(parser: MetadataParser, types: list, gameassembly_path: str,
                       string_literals: list) -> dict:
    """生成 script.json 结构(保留 Addresses/Namespace/Script/StringLiteral 键)。"""
    namespaces = []
    script = []
    for td in types:
        ns = td["namespace"] or ""
        if ns and ns not in namespaces:
            namespaces.append(ns)
        script.append({
            "Name": td["name"],
            "Namespace": ns,
            "TypeIndex": td["index"],
            "BaseType": parser.parent_name(td),
            "Flags": td["flags"],
            "Fields": [{"Name": f["name"], "Type": f["type"], "FieldIndex": f["index"]}
                       for f in td["fields"]],
            "Methods": [{
                "Name": m["name"], "ReturnType": m["return_type"],
                "Parameters": [{"Name": p["name"], "Type": p["type"]} for p in m["parameters"]],
                "Signature": m["signature"], "Address": "0x0", "MethodIndex": m["index"],
            } for m in td["methods"]],
            "Properties": [{
                "Name": pr["name"], "Type": pr["type"],
                "GetMethod": pr["get_method_name"], "SetMethod": pr["set_method_name"],
                "PropertyIndex": pr["index"],
            } for pr in td["properties"]],
        })
    return {
        "GameName": Path(gameassembly_path).stem if gameassembly_path else "",
        "GameAssemblyPath": gameassembly_path,
        "Addresses": {"Module": "0x0"},
        "Namespace": namespaces,
        "Script": script,
        "StringLiteral": [{
            "Index": s["Index"], "Length": s["Length"], "Value": s["Value"],
        } for s in string_literals],
    }


def _build_cpp(parser: MetadataParser, types: list, cpp_dir: Path) -> list:
    """生成 sdk_cpp/<Namespace>.hpp;返回写入的文件名列表。"""
    groups = []
    seen = set()
    for td in types:
        ns = td["namespace"] or ""
        if ns not in seen:
            seen.add(ns)
            groups.append((ns, []))
        for g in groups:
            if g[0] == ns:
                g[1].append(td)
                break
    written = []
    for ns, tds in groups:
        ns_cpp = (ns or "GlobalNamespace").replace(".", "_")
        lines = [
            "// Auto-generated C++ SDK header (aligned with Il2CppDumper SDK)",
            f"// IL2CPP metadata version: {parser.version}",
            "#pragma once",
            "",
            f"namespace {ns_cpp}",
            "{",
        ]
        for td in tds:
            base = (parser.parent_name(td) or "Object").replace(".", "::")
            lines.append(f"\tclass {td['name']} : public {base}")
            lines.append("\t{")
            lines.append("\tpublic:")
            for f in td["fields"]:
                lines.append(f"\t\t{_cpp_type(f['type'])} {f['name']};")
            for pr in td["properties"]:
                lines.append(f"\t\t{_cpp_type(pr['type'])} {pr['name']}; // property")
            for m in td["methods"]:
                args = ", ".join(f"{_cpp_type(p['type'])} {p['name']}" for p in m["parameters"])
                lines.append(f"\t\t{_cpp_type(m['return_type'])} {m['name']}({args});")
            lines.append("\t};")
            lines.append("")
        lines.append("}")
        lines.append("")
        fname = ns_cpp + ".hpp"
        (cpp_dir / fname).write_text("\n".join(lines), encoding="utf-8")
        written.append(fname)
    return written


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _artifact(kind: str, path: str | Path, *, required: bool = True) -> dict:
    p = Path(path) if path else None
    exists = bool(p and p.exists())
    item = {
        "kind": kind,
        "path": str(p) if p else "",
        "required": required,
        "exists": exists,
    }
    if exists and p and p.is_file():
        item.update({
            "size": p.stat().st_size,
            "sha256": _sha256_file(p),
        })
    return item


def _deliver_input_file(source_path: str, delivery_dir: Path, name: str) -> dict:
    """Make an SDK delivery self-contained, preferring a hard link to a copy."""
    source = Path(source_path) if source_path else None
    if not source or not source.is_file():
        return {
            "source_path": str(source) if source else "",
            "delivery_path": "",
            "delivery_method": "missing",
            "exists": False,
        }
    delivery_dir.mkdir(parents=True, exist_ok=True)
    destination = delivery_dir / name
    try:
        same_file = source.resolve() == destination.resolve()
    except OSError:
        same_file = False
    method = "existing"
    if not same_file:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            os.link(source, destination)
            method = "hardlink"
        except OSError:
            shutil.copy2(source, destination)
            method = "copy"
    artifact = _artifact("input", destination if not same_file else source)
    artifact.update({
        "source_path": str(source),
        "delivery_path": str(destination if not same_file else source),
        "delivery_method": method,
    })
    return artifact


def _official_il2cpp_dumper(
    meta_path: str,
    gameassembly_path: str,
    out_dir: Path,
    registration: dict | None = None,
) -> dict:
    """Run the official Il2CppDumper CLI and verify its real delivery surface."""
    executable = Path(config.IL2CPP_DUMPER_PATH)
    if not executable.is_file():
        return {"ok": False, "status": "official_tool_missing", "error": str(executable)}
    tool_dir = executable.parent
    config_path = tool_dir / "config.json"
    if config_path.is_file():
        try:
            settings = json.loads(config_path.read_text(encoding="utf-8"))
            settings["GenerateDummyDll"] = True
            settings["GenerateScript"] = True
            settings["GenerateStruct"] = True
            settings["RequireAnyKey"] = False
            config_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
        except (OSError, ValueError) as exc:
            return {"ok": False, "status": "official_tool_config_failed", "error": str(exc)}
    out_dir.mkdir(parents=True, exist_ok=True)
    command = [str(executable), str(Path(gameassembly_path)), str(Path(meta_path)), str(out_dir)]
    registration = registration or _pe_registration_addresses(gameassembly_path, meta_path)
    if registration.get("found"):
        command.extend([
            f"{int(registration['code_registration']):x}",
            f"{int(registration['metadata_registration']):x}",
        ])
    try:
        process = subprocess.run(
            command, cwd=str(tool_dir), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=900,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "status": "official_tool_failed", "error": str(exc), "command": command}
    log_path = out_dir / "Il2CppDumper.log"
    log_path.write_text(
        (process.stdout or "") + ("\n[stderr]\n" + process.stderr if process.stderr else ""),
        encoding="utf-8",
    )
    dummy_dir = out_dir / "DummyDll"
    dummy_dlls = sorted(str(path) for path in dummy_dir.glob("*.dll")) if dummy_dir.is_dir() else []
    expected = {
        "dump_cs": out_dir / "dump.cs",
        "script_json": out_dir / "script.json",
        "stringliteral_json": out_dir / "stringliteral.json",
        "il2cpp_h": out_dir / "il2cpp.h",
    }
    missing = [key for key, path in expected.items() if not path.is_file()]
    if not dummy_dlls:
        missing.append("DummyDll/*.dll")
    source_root = tool_dir.parents[3] if len(tool_dir.parents) >= 4 else tool_dir
    commit = ""
    try:
        commit_result = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"], capture_output=True,
            text=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if commit_result.returncode == 0:
            commit = commit_result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    official_stats = _official_dump_stats(expected["dump_cs"] if expected["dump_cs"].is_file() else None)
    return {
        "ok": process.returncode == 0 and not missing,
        "status": "completed" if process.returncode == 0 and not missing else "official_tool_incomplete",
        "return_code": process.returncode,
        "command": command,
        "stdout_tail": (process.stdout or "")[-4000:],
        "stderr_tail": (process.stderr or "")[-4000:],
        "log": str(log_path),
        "tool": str(executable),
        "tool_sha256": _sha256_file(executable),
        "tool_commit": commit,
        "license": str(source_root / "LICENSE") if (source_root / "LICENSE").is_file() else "",
        "missing": missing,
        "registration": registration,
        "dummy_dir": str(dummy_dir),
        "dummy_dlls": dummy_dlls,
        "stats": official_stats,
        **{key: str(path) if path.is_file() else "" for key, path in expected.items()},
    }


def _official_dump_stats(path: Path | None) -> dict:
    """Count the authoritative Il2CppDumper text surface for UI/reporting.

    The official CLI produces Dump.cs even when the local fallback parser is
    intentionally disabled.  Counting its stable TypeDefIndex and method RVA
    markers prevents the workflow summary from incorrectly reporting 0/0.
    """
    if not path or not path.is_file():
        return {"types": 0, "methods": 0, "fields": 0, "properties": 0, "source": "missing"}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"types": 0, "methods": 0, "fields": 0, "properties": 0, "source": "unreadable"}
    types = len(re.findall(r"^.*// TypeDefIndex:\s*\d+\s*$", text, re.MULTILINE))
    methods = len(re.findall(r"^\s*\|-RVA:\s*", text, re.MULTILINE))
    properties = len(re.findall(r"^\s*(?:public|private|protected|internal).*\{\s*get;", text, re.MULTILINE))
    fields = len(re.findall(r"^\s*(?:public|private|protected|internal|static|readonly).+;\s*//\s*0x[0-9A-Fa-f]+\s*$", text, re.MULTILINE))
    return {"types": types, "methods": methods, "fields": fields, "properties": properties, "source": "official_dump.cs"}


def _dump_sdk_builtin(meta_path: str, gameassembly_path: str, out_dir: str) -> dict:
    """核心:解析 metadata 并导出 Dump.cs / script.json / sdk_cpp / sdk.json。

    解析采用"读取 string 表后,以字符串内嵌的类/方法名构建类型名"的务实做法;
    无法解析的类型名以 T_<idx> 占位并计入 stats。单个表解析失败不中断,记录到 warnings。

    返回:
      {"ok": True, "dump_cs": str, "script_json": str, "cpp_dir": str, "sdk_json": str,
       "types": n, "methods": n, "fields": n, "version": int, "warnings": [...],
       "stats": {...}}
    """
    metadata_status = check_metadata_encrypted(meta_path)
    if metadata_status.get("status") != "plain":
        return {
            "ok": False,
            "status": "metadata_not_usable",
            "delivery_complete": False,
            "metadata_status": metadata_status,
            "error": "metadata is not verified plaintext",
            "note": "SDK output was not generated because metadata validation failed",
        }
    try:
        parser = MetadataParser(meta_path)
    except (ValueError, OSError) as e:
        return {
            "ok": False,
            "status": "metadata_not_usable",
            "delivery_complete": False,
            "metadata_status": metadata_status,
            "error": f"metadata 解析失败: {e}",
            "note": "SDK output was not generated because metadata parsing failed",
        }

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cpp_dir = out_dir / "sdk_cpp"
    cpp_dir.mkdir(exist_ok=True)

    # 解析全部类型定义与关联表
    types = []
    for td in parser.type_definitions():
        rec = dict(td)
        try:
            rec["fields"] = [
                f for f in (parser._field(td["field_start"] + i)
                            for i in range(td["field_count"])) if f is not None
            ]
        except Exception as e:  # noqa: BLE001
            parser.warnings.append(f"类型 {td.get('name')} 字段表解析失败: {e}")
            rec["fields"] = []
        try:
            rec["methods"] = [
                m for m in (parser._method(td["method_start"] + i)
                            for i in range(td["method_count"])) if m is not None
            ]
        except Exception as e:  # noqa: BLE001
            parser.warnings.append(f"类型 {td.get('name')} 方法表解析失败: {e}")
            rec["methods"] = []
        try:
            rec["properties"] = [
                p for p in (parser._property(td["property_start"] + i)
                            for i in range(td["property_count"])) if p is not None
            ]
        except Exception as e:  # noqa: BLE001
            parser.warnings.append(f"类型 {td.get('name')} 属性表解析失败: {e}")
            rec["properties"] = []
        try:
            rec["interfaces"] = parser._interfaces(td["interfaces_start"], td["interfaces_count"])
        except Exception:  # noqa: BLE001
            rec["interfaces"] = []
        types.append(rec)

    img_count = parser.header.get("images", {}).get("count", 0)
    stats = {
        "types": len(types),
        "methods": sum(len(t["methods"]) for t in types),
        "fields": sum(len(t["fields"]) for t in types),
        "properties": sum(len(t["properties"]) for t in types),
        "images": sum(1 for i in range(img_count) if parser._image(i)),
        "unresolved_types": sum(1 for t in types for f in t["fields"] if f["type"].startswith("T_"))
                            + sum(1 for t in types for m in t["methods"]
                                  if m["return_type"].startswith("T_")),
    }

    # 字符串字面量表(script.json 的 StringLiteral 键)
    string_literals = []
    try:
        string_literals = parser.string_literals()
    except Exception as e:  # noqa: BLE001
        parser.warnings.append(f"stringLiteral 表解析失败: {e}")

    # ---- 输出文件 ----
    dump_cs_path = out_dir / "Dump.cs"
    script_json_path = out_dir / "script.json"
    sdk_json_path = out_dir / "sdk.json"

    dump_cs_path.write_text(_build_dump_cs(parser, types, stats), encoding="utf-8")

    script_data = _build_script_json(parser, types, gameassembly_path, string_literals)
    script_json_path.write_text(json.dumps(script_data, ensure_ascii=False, indent=2), encoding="utf-8")

    try:
        cpp_files = _build_cpp(parser, types, cpp_dir)
    except Exception as e:  # noqa: BLE001
        parser.warnings.append(f"C++ 头文件生成失败: {e}")
        cpp_files = []

    images = []
    for i in range(parser.header.get("images", {}).get("count", 0)):
        try:
            img = parser._image(i)
            if img:
                images.append(img)
        except Exception:  # noqa: BLE001
            pass

    delivery_dir = out_dir / "inputs"
    metadata_delivery = _deliver_input_file(meta_path, delivery_dir, "global-metadata.dat")
    metadata_delivery["kind"] = "metadata"
    gameassembly_delivery = _deliver_input_file(
        gameassembly_path, delivery_dir, "GameAssembly.dll"
    )
    gameassembly_delivery["kind"] = "gameassembly"
    if not gameassembly_delivery["exists"]:
        parser.warnings.append("GameAssembly.dll was not available for SDK delivery")

    manifest_path = out_dir / "sdk_manifest.json"
    sdk_data = {
        "ok": True,
        "status": "completed",
        "version": parser.version,
        "magic_ok": True,
        "metadata_status": metadata_status,
        "table_count_semantics": parser.table_count_semantics,
        "stats": stats,
        "warnings": parser.warnings,
        "images": images,
        "namespaces": script_data["Namespace"],
        "script": script_data["Script"],
        "string_literals": script_data["StringLiteral"],
        "inputs": {
            "metadata": metadata_delivery,
            "gameassembly": gameassembly_delivery,
        },
        "outputs": {
            "dump_cs": str(dump_cs_path),
            "script_json": str(script_json_path),
            "cpp_dir": str(cpp_dir),
            "cpp_headers": [str(cpp_dir / name) for name in cpp_files],
            "sdk_json": str(sdk_json_path),
            "manifest": str(manifest_path),
        },
    }
    sdk_json_path.write_text(json.dumps(sdk_data, ensure_ascii=False, indent=2), encoding="utf-8")

    artifacts = [
        _artifact("dump_cs", dump_cs_path),
        _artifact("script_json", script_json_path),
        _artifact("sdk_json", sdk_json_path),
        _artifact("cpp_dir", cpp_dir),
        metadata_delivery,
        gameassembly_delivery,
    ]
    artifacts.extend(_artifact("cpp_header", cpp_dir / name) for name in cpp_files)
    required_kinds = {"dump_cs", "script_json", "sdk_json", "metadata", "gameassembly"}
    if types:
        required_kinds.add("cpp_header")
    missing_required = [
        item["kind"] for item in artifacts
        if item.get("kind") in required_kinds and not item.get("exists")
    ]
    if types and not cpp_files:
        missing_required.append("cpp_header")
    delivery_complete = not missing_required
    manifest = {
        "schema": "revlab.unity.sdk-manifest/v1",
        "status": "completed" if delivery_complete else "completed_with_missing_artifacts",
        "delivery_complete": delivery_complete,
        "metadata_status": metadata_status,
        "metadata_version": parser.version,
        "table_count_semantics": parser.table_count_semantics,
        "stats": stats,
        "warnings": parser.warnings,
        "missing_required": missing_required,
        "artifacts": artifacts,
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "ok": True,
        "status": manifest["status"],
        "delivery_complete": delivery_complete,
        "dump_cs": str(dump_cs_path),
        "script_json": str(script_json_path),
        "cpp_dir": str(cpp_dir),
        "cpp_headers": [str(cpp_dir / name) for name in cpp_files],
        "sdk_json": str(sdk_json_path),
        "manifest": str(manifest_path),
        "sdk_manifest": str(manifest_path),
        "dll": gameassembly_delivery.get("delivery_path", ""),
        "dll_source": gameassembly_delivery.get("source_path", ""),
        "metadata": metadata_delivery.get("delivery_path", ""),
        "metadata_source": metadata_delivery.get("source_path", ""),
        "types": stats["types"],
        "methods": stats["methods"],
        "fields": stats["fields"],
        "properties": stats["properties"],
        "version": parser.version,
        "warnings": parser.warnings,
        "stats": stats,
        "artifacts": artifacts,
        "missing_required": missing_required,
        "metadata_status": metadata_status,
    }


def dump_sdk(
    meta_path: str,
    gameassembly_path: str,
    out_dir: str,
    registration: dict | None = None,
) -> dict:
    """Generate the authoritative official Il2CppDumper delivery."""
    metadata_status = check_metadata_encrypted(meta_path)
    if metadata_status.get("status") != "plain":
        return {
            "ok": False, "status": "metadata_not_usable", "delivery_complete": False,
            "metadata_status": metadata_status,
            "error": "metadata is not verified plaintext",
        }
    out_root = Path(out_dir)
    builtin = {"status": "not_run", "note": "Official SDK delivery is authoritative."}
    registration = registration or _pe_registration_addresses(gameassembly_path, meta_path)
    official = _official_il2cpp_dumper(
        meta_path, gameassembly_path, out_root, registration=registration
    )
    delivery_dir = out_root / "inputs"
    metadata_delivery = _deliver_input_file(meta_path, delivery_dir, "global-metadata.dat")
    metadata_delivery["kind"] = "metadata"
    gameassembly_delivery = _deliver_input_file(gameassembly_path, delivery_dir, "GameAssembly.dll")
    gameassembly_delivery["kind"] = "gameassembly"
    artifacts = [metadata_delivery, gameassembly_delivery]
    for kind, raw in (
        ("dump_cs", official.get("dump_cs")), ("script_json", official.get("script_json")),
        ("stringliteral_json", official.get("stringliteral_json")),
        ("il2cpp_h", official.get("il2cpp_h")), ("dummy_dir", official.get("dummy_dir")),
        ("official_log", official.get("log")),
    ):
        if raw:
            artifacts.append(_artifact(kind, raw))
    artifacts.extend(_artifact("dummy_dll", path) for path in official.get("dummy_dlls", []))
    missing = list(official.get("missing", []))
    if not metadata_delivery.get("exists"):
        missing.append("global-metadata.dat")
    if not gameassembly_delivery.get("exists"):
        missing.append("GameAssembly.dll")
    delivery_complete = bool(official.get("ok") and not missing)
    sdk_json_path = out_root / "sdk.json"
    official_stats = official.get("stats") or {"types": 0, "methods": 0, "fields": 0, "properties": 0, "source": "missing"}
    sdk_json_path.write_text(json.dumps({
        "schema": "revlab.unity.official-sdk-index/v1",
        "delivery_complete": delivery_complete,
        "metadata": metadata_delivery,
        "gameassembly": gameassembly_delivery,
        "registration": registration,
        "stats": official_stats,
        "official_tool": {
            "path": official.get("tool", ""),
            "sha256": official.get("tool_sha256", ""),
            "commit": official.get("tool_commit", ""),
            "return_code": official.get("return_code"),
        },
        "outputs": {
            "dump_cs": official.get("dump_cs", ""),
            "script_json": official.get("script_json", ""),
            "stringliteral_json": official.get("stringliteral_json", ""),
            "il2cpp_h": official.get("il2cpp_h", ""),
            "dummy_dir": official.get("dummy_dir", ""),
            "dummy_dlls": official.get("dummy_dlls", []),
        },
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    artifacts.append(_artifact("sdk_json", sdk_json_path))
    manifest_path = out_root / "sdk_manifest.json"
    manifest = {
        "schema": "revlab.unity.sdk-manifest/v2",
        "status": "completed" if delivery_complete else "failed",
        "delivery_complete": delivery_complete,
        "metadata_status": metadata_status,
        "registration": registration,
        "stats": official_stats,
        "official_tool": official,
        "builtin_diagnostics": builtin,
        "missing_required": missing,
        "artifacts": artifacts,
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "ok": delivery_complete,
        "status": manifest["status"],
        "delivery_complete": delivery_complete,
        "dump_cs": official.get("dump_cs", ""),
        "script_json": official.get("script_json", ""),
        "stringliteral_json": official.get("stringliteral_json", ""),
        "il2cpp_h": official.get("il2cpp_h", ""),
        "sdk_json": str(sdk_json_path),
        "cpp_dir": builtin.get("cpp_dir", ""),
        "cpp_headers": builtin.get("cpp_headers", []),
        "dummy_dir": official.get("dummy_dir", ""),
        "dummy_dlls": official.get("dummy_dlls", []),
        "dll": gameassembly_delivery.get("delivery_path", ""),
        "dll_source": gameassembly_delivery.get("source_path", ""),
        "metadata": metadata_delivery.get("delivery_path", ""),
        "metadata_source": metadata_delivery.get("source_path", ""),
        "manifest": str(manifest_path),
        "sdk_manifest": str(manifest_path),
        "types": official_stats.get("types", 0),
        "methods": official_stats.get("methods", 0),
        "fields": official_stats.get("fields", 0),
        "properties": official_stats.get("properties", 0),
        "stats": official_stats,
        "metadata_status": metadata_status,
        "registration": registration,
        "official_tool": official,
        "artifacts": artifacts,
        "missing_required": missing,
        "warnings": builtin.get("warnings", []),
    }
