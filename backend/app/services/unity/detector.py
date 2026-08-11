"""Unity 游戏目录检测与结构扫描。

输入游戏文件夹绝对路径,识别:
  - 关键文件(GameAssembly.dll / Data/il2cpp_data / Data/Managed / globalgamemanagers 等)
  - 构建类型(Mono / IL2CPP / Other)
  - Unity 版本字符串(扫描关键文件前 1MB)
输出结构:
  detect_unity(path) -> {
      "path", "exists", "unity_version", "build_type",
      "key_files": [{"path","size","kind"}],
  }
  scan_structure(path) -> {
      "root", "files": [{"path"(相对),"size","kind"}],
      "total_size", "file_count", "dir_count",
  }
"""
from __future__ import annotations
import re
from pathlib import Path

# 版本正则:优先 4 位年格式(2021.3.10f1),其次通用 3 段
_VERSION_RE_4 = re.compile(rb"20\d\d\.\d+(?:\.\d+)?[fpb]\d+")
_VERSION_RE_3 = re.compile(rb"\d{4}\.\d+\.\d+[fpb]\d+")
_VERSION_RE_GEN = re.compile(rb"\d+\.\d+(?:\.\d+)?[fpb]\d+")

_MAX_SCAN = 1024 * 1024          # 版本识别时单文件最多读取 1MB
_MAX_SKIP_SIZE = 512 * 1024 * 1024  # 超过 512MB 的文件不再读取内容(结构仍列出)
_DEPTH_LIMIT = 3                 # 目录树扫描深度

# 关键文件 → kind 映射(供 detect/scan 统一推断)
_KIND_RULES = [
    ("gameassembly", lambda p, name: name.lower() == "gameassembly.dll"),
    ("metadata", lambda p, name: "il2cpp_data" in _pl(p) and name.lower() == "global-metadata.dat"),
    ("managed", lambda p, name: "managed" in _pl(p) and name.lower().endswith(".dll")),
    ("globalgame", lambda p, name: name.lower() in ("globalgamemanagers", "globalgamemanagers.assets")),
    ("player", lambda p, name: name.lower() == "unityplayer.dll"),
    ("assets", lambda p, name: (name.lower().endswith((".assets", ".unity3d", ".resS", ".resource"))
                                or name.lower() == "data.unity3d" or "il2cpp_data" in _pl(p))),
    ("other", lambda p, name: True),
]


def _pl(p: Path) -> tuple:
    return tuple(x.lower() for x in p.parts)


def _kind_of(p: Path) -> str:
    name = p.name
    for kind, rule in _KIND_RULES:
        if rule(p, name):
            return kind
    return "other"


def _read_head(path: Path, n: int = _MAX_SCAN) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except Exception:
        return b""


def _detect_version_from(data: bytes) -> str:
    """从字节内容提取 Unity 版本串(去重取首个)。"""
    for rx in (_VERSION_RE_4, _VERSION_RE_3, _VERSION_RE_GEN):
        for m in rx.finditer(data):
            try:
                s = m.group(0).decode("latin-1")
            except Exception:
                continue
            if s and len(s) <= 32:
                return s
    return ""


def detect_unity(path: str) -> dict:
    """检测游戏文件夹是否为 Unity 构建,识别版本与构建类型。"""
    root = Path(path)
    result = {
        "path": str(root),
        "exists": root.exists(),
        "unity_version": "",
        "build_type": "Other",
        "key_files": [],
    }
    if not root.is_dir():
        return result

    seen = set()
    keys = []
    parts_lower = lambda p: tuple(x.lower() for x in p.parts)
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        low = p.name.lower()
        pl = parts_lower(p)
        if low in ("gameassembly.dll", "unityplayer.dll", "data.unity3d") or \
           low in ("globalgamemanagers", "globalgamemanagers.assets") or \
           "il2cpp_data" in pl or "managed" in pl:
            try:
                keys.append((p, p.stat().st_size))
            except OSError:
                continue
    keys.sort(key=lambda x: x[0].as_posix())

    has_il2cpp_data = any("il2cpp_data" in tuple(x.lower() for x in p.parts) for p, _ in keys)
    has_gameassembly = any(p.name.lower() == "gameassembly.dll" for p, _ in keys)
    has_managed = any("managed" in tuple(x.lower() for x in p.parts)
                      and p.name.lower().endswith(".dll") for p, _ in keys)
    has_globalgame = any(p.name.lower().startswith("globalgamemanagers") for p, _ in keys)

    # 构建类型判定
    if has_il2cpp_data or has_gameassembly:
        build_type = "IL2CPP"
    elif has_managed:
        build_type = "Mono"
    elif has_globalgame:
        build_type = "Other"
    else:
        build_type = "Other"

    # 版本识别:扫描关键文件前 1MB
    version = ""
    for p, _ in keys:
        if p.stat().st_size > _MAX_SKIP_SIZE:
            continue
        v = _detect_version_from(_read_head(p))
        if v:
            version = v
            break

    # 汇总关键文件(去重)
    for p, size in keys:
        k = _kind_of(p)
        if k in seen and k not in ("assets", "other"):
            continue
        seen.add(k)
        result["key_files"].append({
            "path": str(p),
            "size": size,
            "kind": k,
        })

    result["unity_version"] = version
    result["build_type"] = build_type
    result["key_files"].sort(key=lambda x: x["kind"])
    return result


def scan_structure(path: str) -> dict:
    """列出目录树关键文件清单(相对路径 + 大小 + kind 推断)。深度受限。"""
    root = Path(path)
    out = {
        "root": str(root),
        "exists": root.exists(),
        "files": [],
        "total_size": 0,
        "file_count": 0,
        "dir_count": 0,
    }
    if not root.is_dir():
        return out

    stack = [(root, 0)]
    dir_count = 0
    while stack:
        cur, depth = stack.pop()
        if depth > _DEPTH_LIMIT:
            continue
        try:
            entries = sorted(cur.iterdir(), key=lambda x: x.name.lower())
        except OSError:
            continue
        for e in entries:
            if e.is_dir():
                dir_count += 1
                if depth < _DEPTH_LIMIT:
                    stack.append((e, depth + 1))
            elif e.is_file():
                try:
                    size = e.stat().st_size
                except OSError:
                    size = 0
                out["files"].append({
                    "path": e.relative_to(root).as_posix(),
                    "size": size,
                    "kind": _kind_of(e),
                })
                out["total_size"] += size
                out["file_count"] += 1

    out["dir_count"] = dir_count
    out["files"].sort(key=lambda x: (x["kind"], x["path"]))
    return out
