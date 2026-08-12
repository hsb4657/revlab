"""Unity 分析器:聚合检测、结构扫描、程序集分析与资源/字符串提取。
供 unity/__init__.py 各阶段复用,也可独立使用。
"""
from __future__ import annotations
import re
from pathlib import Path

from .. import pe_parser
from .. import strings as _strings_svc
from . import detector as _detector
from . import mono as _mono

# 资源文件头特征
_RESOURCE_MAGICS = [
    ("UnityFS", b"UnityFS"),
    ("UnityRaw", b"UnityRaw"),
    ("UnityWeb", b"UnityWeb"),
]

_KEY_FILE_KINDS = ("gameassembly", "metadata", "managed", "globalgame", "player", "assets")

_GAMEASSEMBLY_METADATA_MARKERS = (
    b"global-metadata.dat",
    b"global-metadata",
    b"il2cpp::vm::MetadataLoader",
    b"MetadataLoader",
    b"MetadataCache::Initialize",
    b"il2cpp::vm::MetadataCache",
    b"GetMetadataVersion",
    b"LoadMetadataFile",
    b"il2cpp_init",
)


def _gameassembly_metadata_hints(path: Path) -> dict:
    """Extract bounded, static-only metadata-loader evidence from GameAssembly.

    Absence of a marker is not evidence that a custom loader does not exist:
    production IL2CPP binaries may strip strings and symbols.  The result is
    therefore used to guide a runtime trace, never to claim a decryption key.
    """
    out = {
        "path": str(path),
        "readable": False,
        "marker_hits": [],
        "api_hits": [],
        "standard_metadata_path_found": False,
        "loader_signal": "none",
        "limitations": [
            "Static string evidence cannot prove the active metadata loader or decryption algorithm.",
            "A stripped GameAssembly may omit all loader strings; runtime tracing is required for encrypted candidates.",
        ],
    }
    try:
        data = path.read_bytes()
    except OSError as exc:
        out["error"] = str(exc)
        return out
    out["readable"] = True
    for marker in _GAMEASSEMBLY_METADATA_MARKERS:
        positions = [match.start() for match in re.finditer(re.escape(marker), data, re.IGNORECASE)]
        if not positions:
            continue
        label = marker.decode("ascii", errors="replace")
        item = {"marker": label, "count": len(positions), "offsets": positions[:8]}
        if marker.lower().startswith(b"il2cpp_"):
            out["api_hits"].append(item)
        else:
            out["marker_hits"].append(item)
        if marker.lower() in (b"global-metadata.dat", b"global-metadata"):
            out["standard_metadata_path_found"] = True
    if out["standard_metadata_path_found"]:
        out["loader_signal"] = "standard_path_string"
    elif out["marker_hits"] or out["api_hits"]:
        out["loader_signal"] = "il2cpp_runtime_marker_only"
    return out


class UnityAnalyzer:
    """聚合 Unity 检测/结构/程序集分析逻辑。"""

    def __init__(self, path: str, version: str = ""):
        self.path = Path(path)
        self.version = version
        self.detect = None
        self.scan = None
        self._key_files = None

    # ---------------------------------------------------------- 检测
    def run_detect(self) -> dict:
        self.detect = _detector.detect_unity(str(self.path))
        if self.version and not self.detect.get("unity_version"):
            self.detect["unity_version"] = self.version
        return self.detect

    def run_scan(self) -> dict:
        self.scan = _detector.scan_structure(str(self.path))
        return self.scan

    def _ensure(self):
        """懒加载 detect/scan(独立调用 analyzer 时也能工作)。"""
        if self.detect is None:
            self.run_detect()
        if self.scan is None:
            self.run_scan()

    # ---------------------------------------------------------- 关键文件
    def key_files(self, kind: str = None) -> list:
        """按 kind 过滤关键文件列表(优先 detect.key_files,回退 scan.files)。"""
        self._ensure()
        files = []
        if self.detect and self.detect.get("key_files"):
            files = self.detect["key_files"]
        elif self.scan:
            files = self.scan.get("files", [])
        if kind:
            files = [f for f in files if f.get("kind") == kind]
        return files

    def _resolve(self, rel: str) -> str:
        p = Path(rel)
        if p.is_absolute():
            return str(p)
        if p.exists():
            return str(p.resolve())
        return str((self.path / p).resolve())

    def find_by_name(self, names: tuple) -> list:
        """按文件名(小写)查找绝对路径。"""
        self._ensure()
        out = []
        for f in (self.scan or {}).get("files", []):
            if Path(f["path"]).name.lower() in names:
                out.append(self._resolve(f["path"]))
        return out

    def gameassembly_path(self) -> str:
        files = self.key_files("gameassembly")
        return self._resolve(files[0]["path"]) if files else ""

    def metadata_path(self) -> str:
        files = self.key_files("metadata")
        return self._resolve(files[0]["path"]) if files else ""

    def metadata_candidates(self) -> dict:
        """Return evidence-only renamed/encrypted Metadata candidates."""
        self._ensure()
        return (self.detect or {}).get("metadata_candidates", {}) or {}

    def managed_dir(self) -> str:
        d = self.path / "Data" / "Managed"
        return str(d) if d.is_dir() else ""

    def il2cpp_data_dir(self) -> str:
        d = self.path / "Data" / "il2cpp_data"
        return str(d) if d.is_dir() else ""

    # ---------------------------------------------------------- 构建类型
    def build_type(self) -> str:
        if self.detect is None:
            self._ensure()
        if self.detect:
            return self.detect.get("build_type", "Other")
        has_il2cpp = any(f.get("kind") == "metadata" or "il2cpp_data" in Path(f["path"]).parts
                         for f in self.key_files())
        has_ga = any(f.get("kind") == "gameassembly" for f in self.key_files())
        has_managed = any(f.get("kind") == "managed" for f in self.key_files())
        if has_il2cpp or has_ga:
            return "IL2CPP"
        if has_managed:
            return "Mono"
        return "Other"

    # ---------------------------------------------------------- 程序集分析
    def analyze_assemblies(self) -> dict:
        """按构建类型分析程序集。"""
        bt = self.build_type()
        self._ensure()
        out = {
            "mode": bt,
            "mode_evidence": (self.detect or {}).get("build_evidence", {}),
        }
        if bt == "IL2CPP":
            ga = self.gameassembly_path()
            out["gameassembly_path"] = ga
            if ga and Path(ga).exists():
                try:
                    data = Path(ga).read_bytes()
                    pe = pe_parser.parse_pe(data, ga)
                    exports = [e for e in pe.get("exports", []) if e.get("name")]
                    il2cpp_exports = [e for e in exports if str(e.get("name", "")).startswith("il2cpp_")]
                    out["game_assembly"] = {
                        "path": ga,
                        "size": len(data),
                        "machine": pe.get("machine"),
                        "is_64bit": pe.get("is_64bit"),
                        "sections": pe.get("sections", []),
                        "export_count": len(exports),
                        "il2cpp_export_count": len(il2cpp_exports),
                        "il2cpp_exports": [e["name"] for e in il2cpp_exports[:40]],
                        "pdb": (pe.get("debug") or {}).get("pdb", ""),
                    }
                    out["gameassembly_metadata_hints"] = _gameassembly_metadata_hints(Path(ga))
                except Exception as e:
                    out["game_assembly"] = {"path": ga, "error": str(e)}
                    out["gameassembly_metadata_hints"] = _gameassembly_metadata_hints(Path(ga))
            else:
                out["gameassembly_metadata_hints"] = {
                    "path": ga,
                    "readable": False,
                    "marker_hits": [],
                    "api_hits": [],
                    "standard_metadata_path_found": False,
                    "loader_signal": "missing",
                    "limitations": ["GameAssembly.dll was not available for static loader-string inspection."],
                }
            meta = self.metadata_path()
            out["metadata_path"] = meta
            out["metadata_candidates"] = self.metadata_candidates()
            if meta and Path(meta).exists():
                try:
                    from . import il2cpp as _il2cpp
                    out["metadata_status"] = _il2cpp.check_metadata_encrypted(meta)
                    out["metadata"] = _il2cpp.parse_metadata(meta)
                except ImportError as e:
                    out["metadata"] = {"error": f"il2cpp module not ready: {e}"}
                except Exception as e:
                    out["metadata"] = {"error": str(e)}
        elif bt == "Mono":
            md = self.managed_dir()
            out["managed_dir"] = md
            if md:
                out["managed_assemblies"] = _mono.analyze_managed_dir(md)
                out["api_stats"] = _mono.api_usage_stats(md)
        return out

    # ---------------------------------------------------------- 资源
    def find_resources(self) -> list:
        """扫描 UnityFS/UnityRaw/UnityWeb 头资源文件(基于完整目录扫描清单)。"""
        if self.scan is None:
            self.run_scan()
        files = (self.scan or {}).get("files", [])
        if not files and self.detect:
            files = self.detect.get("key_files", [])
        out = []
        for f in files:
            p = f["path"]
            ap = p if Path(p).is_absolute() else self.path / p
            if not Path(ap).exists():
                continue
            try:
                with open(ap, "rb") as fh:
                    head = fh.read(8)
            except OSError:
                continue
            for name, magic in _RESOURCE_MAGICS:
                if head.startswith(magic):
                    out.append({"file": f["path"], "header": name, "size": f.get("size", 0)})
                    break
        return out

    # ---------------------------------------------------------- 字符串
    def extract_strings(self, limit_file_size: int = 64 * 1024 * 1024) -> dict:
        """遍历关键文件提取兴趣字符串(复用 strings 服务)。"""
        out = {"files": [], "strings": [], "interesting": [], "count": 0}
        for f in self.key_files():
            p = f["path"]
            ap = Path(p) if Path(p).is_absolute() else self.path / p
            if not ap.exists() or f.get("size", 0) > limit_file_size:
                continue
            try:
                data = ap.read_bytes()
            except OSError:
                continue
            strs = _strings_svc.extract_strings(data)
            out["strings"].extend(strs)
            out["files"].append({"file": f["path"], "size": len(data), "string_count": len(strs)})
        out["count"] = len(out["strings"])
        out["interesting"] = _strings_svc.interesting_strings(out["strings"])
        return out

    # ---------------------------------------------------------- 汇总
    def summary(self) -> dict:
        d = self.detect or {}
        asm = self.analyze_assemblies()
        counts = {"types": 0, "methods": 0, "fields": 0}
        for a in asm.get("managed_assemblies", []):
            counts["types"] += a.get("type_count", 0)
            counts["methods"] += a.get("methods_hint", 0)
            counts["fields"] += a.get("fields_count", 0)
        if "metadata" in asm:
            md = asm.get("metadata", {})
            counts["types"] = md.get("type_count", 0)
            counts["methods"] = md.get("method_count", 0)
            counts["fields"] = md.get("field_count", 0)
        return {
            "unity_version": d.get("unity_version", ""),
            "build_type": d.get("build_type", "Other"),
            "build_evidence": d.get("build_evidence", {}),
            "mode": asm.get("mode", ""),
            "metadata_status": (asm.get("metadata_status", {}) or {}).get("status", "not_applicable"),
            "types": counts["types"],
            "methods": counts["methods"],
            "fields": counts["fields"],
        }
