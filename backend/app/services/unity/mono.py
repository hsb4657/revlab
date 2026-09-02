"""Mono 托管程序集分析(Data/Managed/*.dll)。

优先使用 dnfile 读取 .NET 元数据(命名空间/类型/方法);dnfile 不可用时
降级为 pefile 解析 PE 架构/节区 + 字符串扫描提取类型名候选。

对外:
  analyze_managed_dir(managed_dir) -> [{"name","size","arch","namespace_count",
                                        "type_count","types_hint","methods_hint","method_source"}]
  analyze_assembly_dll(path) -> 同上(单程序集)
  api_usage_stats(managed_dir) -> {"counts": {kw: 命中dll数}, "matched": {kw: [dll名]}, "keywords": [...]}
"""
from __future__ import annotations
import re
from pathlib import Path

import pefile as _pefile

# 关键 API 兴趣关键词(字符串级统计)
_API_KEYWORDS = [
    "PlayerPrefs", "WWW", "UnityWebRequest", "GetComponent", "LoadScene",
    "File.", "Network", "Socket", "Encrypt", "Decrypt", "WebRequest", "HttpClient",
    "SaveGame", "Application.persistentDataPath", "Environment.GetEnvironmentVariable",
]

# dnfile 懒加载缓存
_dnfile = None
_dnfile_tried = False


def _ensure_dnfile():
    """Return the declared dependency without mutating the environment at runtime."""
    global _dnfile, _dnfile_tried
    if _dnfile_tried:
        return _dnfile
    _dnfile_tried = True
    try:
        import dnfile  # noqa
        _dnfile = dnfile
        return _dnfile
    except ImportError:
        pass
    return None


def _machine_to_arch(machine: int) -> str:
    return {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"} \
        .get(machine, f"0x{machine:x}")


def _dnfile_analyze(path: Path) -> dict:
    """用 dnfile 读取 .NET 元数据。"""
    import dnfile
    pe = dnfile.dnPE(str(path), fast_load=False)
    try:
        net = getattr(pe, "net", None)
        if net is None or getattr(net, "metadata", None) is None:
            raise ValueError("not a .NET assembly")
        tables = net.mdtables

        typedefs = list(getattr(tables, "TypeDef", []) or [])
        typedefs = [t for t in typedefs if t is not None]
        methoddefs = list(getattr(tables, "MethodDef", []) or [])
        fielddefs = list(getattr(tables, "Field", []) or [])
        propertydefs = list(getattr(tables, "Property", []) or [])
        eventdefs = list(getattr(tables, "Event", []) or [])

        namespaces = {}
        types = []
        for t in typedefs:
            ns = ""
            name = ""
            try:
                ns = str(getattr(t, "TypeNamespace", "") or "")
                name = str(getattr(t, "TypeName", "") or "")
            except Exception:
                continue
            if not name or name.startswith("<"):
                continue
            namespaces[ns] = namespaces.get(ns, 0) + 1
            types.append((ns, name))
        types = types[:1000]

        # 类型候选(命名空间.类型名)
        type_hint = [f"{ns}.{n}" if ns else n for ns, n in types[:20]]
        method_count = len([m for m in methoddefs if m is not None])
        field_count = len([f for f in fielddefs if f is not None])
        property_count = len([p for p in propertydefs if p is not None])
        event_count = len([e for e in eventdefs if e is not None])

        return {
            "name": path.name,
            "size": path.stat().st_size,
            "arch": _machine_to_arch(pe.FILE_HEADER.Machine),
            "namespace_count": len(namespaces),
            "type_count": len(types),
            "types_hint": type_hint,
            "methods_hint": method_count,
            "fields_count": field_count,
            "property_count": property_count,
            "event_count": event_count,
            "method_source": "dnfile",
        }
    finally:
        try:
            pe.close()
        except Exception:
            pass


_NS_TYPE_RE = re.compile(rb"\b[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+")
_IDENT_RE = re.compile(rb"\b[a-z_][A-Za-z0-9_]{3,}\b")


def _pefile_fallback(path: Path) -> dict:
    """降级:pefile 读 PE + 字符串扫描提取类型名候选。"""
    try:
        pe = _pefile.PE(str(path), fast_load=False)
        arch = _machine_to_arch(pe.FILE_HEADER.Machine)
        sections = [{
            "name": s.Name.rstrip(b"\x00").decode("latin-1", "replace"),
            "virtual_address": hex(s.VirtualAddress),
            "raw_size": s.SizeOfRawData,
            "entropy": round(s.get_entropy(), 4) if s.SizeOfRawData else 0.0,
        } for s in pe.sections]
        pe.close()
    except Exception:
        arch = "unknown"
        sections = []

    try:
        data = path.read_bytes()
    except OSError:
        data = b""

    candidates = []
    for m in _NS_TYPE_RE.finditer(data):
        s = m.group(0).decode("latin-1", "replace")
        if len(s) > 3 and len(s) <= 160 and any(c.isupper() for c in s):
            # 排除路径/版权等噪声:段内不得含 \ 或 / 或空格
            if "\\" in s or "/" in s or " " in s:
                continue
            candidates.append(s)
    candidates = list(dict.fromkeys(candidates))  # 去重保序

    # 类型候选评分:末段大写开头优先
    def _score(c):
        last = c.rsplit(".", 1)[-1]
        return (1 if last and last[0].isupper() else 0, len(c))

    top = sorted(candidates, key=_score, reverse=True)[:20]

    # 方法候选:小写开头标识符(近似)
    methods = set()
    for m in _IDENT_RE.finditer(data):
        s = m.group(0).decode("latin-1", "replace")
        if s.lower() in ("http", "https", "this", "that", "none", "null", "true", "false"):
            continue
        methods.add(s)
    methods_hint = len(methods)
    # 上限 5000,避免全大写噪声
    methods_hint = min(methods_hint, 5000)

    namespaces = set(c.split(".", 1)[0] for c in candidates)

    return {
        "name": path.name,
        "size": path.stat().st_size,
        "arch": arch,
        "sections": sections,
        "namespace_count": len(namespaces),
        "type_count": len(candidates),
        "types_hint": top,
        "methods_hint": methods_hint,
        "fields_count": 0,
        "property_count": 0,
        "event_count": 0,
        "method_source": "pefile-fallback",
    }


def analyze_assembly_dll(path) -> dict:
    """单 dll 分析(返回组装结构)。"""
    p = Path(path)
    if not p.exists() or not p.name.lower().endswith(".dll"):
        raise FileNotFoundError(f"not a dll: {p}")
    try:
        if _ensure_dnfile() is not None:
            try:
                return _dnfile_analyze(p)
            except Exception:
                pass  # 解析失败降级
        return _pefile_fallback(p)
    except Exception as e:
        return {
            "name": p.name, "size": p.stat().st_size, "arch": "unknown",
            "namespace_count": 0, "type_count": 0, "types_hint": [],
            "methods_hint": 0, "fields_count": 0, "property_count": 0, "event_count": 0,
            "method_source": "error", "error": str(e),
        }


def analyze_managed_dir(managed_dir) -> list:
    """遍历 Data/Managed/*.dll 分析,汇总前 30 类型名。"""
    d = Path(managed_dir)
    if not d.is_dir():
        return []
    dlls = sorted([p for p in d.iterdir() if p.is_file() and p.suffix.lower() == ".dll"],
                  key=lambda x: x.name.lower())
    results = []
    for p in dlls:
        r = analyze_assembly_dll(p)
        results.append(r)
    return results


def api_usage_stats(managed_dir) -> dict:
    """统计含关键 API 字符串的 dll。返回 {"keywords","counts","matched"}。"""
    d = Path(managed_dir)
    out = {"keywords": _API_KEYWORDS, "counts": {}, "matched": {}}
    if not d.is_dir():
        return out
    cache = {}
    for kw in _API_KEYWORDS:
        out["counts"][kw] = 0
        out["matched"][kw] = []
    for p in sorted(d.glob("*.dll")):
        try:
            data = p.read_bytes()
        except OSError:
            continue
        for kw in _API_KEYWORDS:
            if kw.encode("utf-8") in data:
                out["counts"][kw] += 1
                out["matched"][kw].append(p.name)
    return out
