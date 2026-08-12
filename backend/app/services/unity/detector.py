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
import hashlib
import math
import re
import struct
from pathlib import Path

# 版本正则:优先 4 位年格式(2021.3.10f1),其次通用 3 段
_VERSION_RE_4 = re.compile(rb"20\d\d\.\d+(?:\.\d+)?[fpb]\d+")
_VERSION_RE_3 = re.compile(rb"\d{4}\.\d+\.\d+[fpb]\d+")
_VERSION_RE_GEN = re.compile(rb"\d+\.\d+(?:\.\d+)?[fpb]\d+")

_MAX_SCAN = 1024 * 1024          # 版本识别时单文件最多读取 1MB
_MAX_SKIP_SIZE = 512 * 1024 * 1024  # 超过 512MB 的文件不再读取内容(结构仍列出)
_DEPTH_LIMIT = 3                 # 目录树扫描深度

# Metadata is sometimes renamed by a build-time protection layer.  A hashed
# filename and high entropy are useful triage signals, but neither proves that
# a file is metadata.  Keep those signals separate from a verified metadata
# result so an arbitrary encrypted asset can never unlock the SDK stage.
_IL2CPP_METADATA_MAGIC = b"\xaf\x1b\xb1\xfa"
_METADATA_MIN_VERSION = 24
_METADATA_MAX_VERSION = 33
_METADATA_CANDIDATE_MIN_SIZE = 1024
_METADATA_CANDIDATE_LIMIT = 16
_METADATA_MAGIC_OFFSETS_LIMIT = 4
_METADATA_HASHED_NAME_RE = re.compile(r"[0-9a-f]{32}$", re.IGNORECASE)
_ENTROPY_SAMPLE_CAP = 1024 * 1024
_METADATA_MAGIC_SCAN_CAP = 32 * 1024 * 1024
_FILE_HASH_CHUNK = 1024 * 1024

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


def _entropy(data: bytes) -> float:
    """Return byte entropy for candidate ranking without reading huge files."""
    if not data:
        return 0.0
    if len(data) > _ENTROPY_SAMPLE_CAP:
        step = max(1, len(data) // _ENTROPY_SAMPLE_CAP)
        data = data[::step]
    total = len(data)
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _metadata_magic_offsets(data: bytes, base_offset: int = 0, limit: int = _METADATA_MAGIC_OFFSETS_LIMIT) -> list[int]:
    """Find a bounded set of valid IL2CPP header locations in ``data``."""
    offsets = []
    start = 0
    while len(offsets) < limit:
        offset = data.find(_IL2CPP_METADATA_MAGIC, start)
        if offset < 0:
            break
        if offset + 8 <= len(data):
            version = struct.unpack_from("<i", data, offset + 4)[0]
            if _METADATA_MIN_VERSION <= version <= _METADATA_MAX_VERSION:
                offsets.append(base_offset + offset)
        start = offset + 1
    return offsets


def _scan_metadata_magic(path: Path, size: int) -> tuple[list[int], int, bool]:
    """Search a bounded amount of a candidate for a valid Metadata header."""
    scan_size = min(size, _METADATA_MAGIC_SCAN_CAP)
    offsets = []
    consumed = 0
    overlap = b""
    try:
        with path.open("rb") as handle:
            while consumed < scan_size and len(offsets) < _METADATA_MAGIC_OFFSETS_LIMIT:
                chunk = handle.read(min(_FILE_HASH_CHUNK, scan_size - consumed))
                if not chunk:
                    break
                combined = overlap + chunk
                base = consumed - len(overlap)
                offsets.extend(_metadata_magic_offsets(
                    combined,
                    base,
                    _METADATA_MAGIC_OFFSETS_LIMIT - len(offsets),
                ))
                # Keep enough bytes to validate a header crossing a chunk boundary.
                overlap = combined[-7:]
                consumed += len(chunk)
    except OSError:
        return [], 0, False
    return offsets, consumed, consumed >= size


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                block = handle.read(_FILE_HASH_CHUNK)
                if not block:
                    break
                digest.update(block)
    except OSError:
        return ""
    return digest.hexdigest()


def _metadata_version_at(path: Path, offset: int) -> int:
    try:
        with path.open("rb") as handle:
            handle.seek(offset + 4)
            raw = handle.read(4)
    except OSError:
        return 0
    return struct.unpack("<i", raw)[0] if len(raw) == 4 else 0


def _metadata_candidate_record(path: Path, size: int, rel_path: str, *, full_evidence: bool = True) -> dict | None:
    """Inspect a possible renamed metadata file without modifying it.

    A candidate only records direct file facts.  ``candidate_reason`` is
    intentionally not a decryption verdict; a caller must still validate the
    recovered bytes before treating it as a usable metadata input.
    """
    if size < _METADATA_CANDIDATE_MIN_SIZE:
        return None
    try:
        data = _read_head(path, _MAX_SCAN)
    except OSError:
        return None
    if not data:
        return None
    entropy = round(_entropy(data), 3)
    hashed_name = bool(_METADATA_HASHED_NAME_RE.fullmatch(path.name))
    direct_il2cpp_file = "il2cpp_data" in _pl(path)
    # Files below il2cpp_data are the normal location for metadata.  Restrict
    # the weak high-entropy/hashed-name signal to that directory so common
    # Unity asset bundles elsewhere in the target are not reported as metadata.
    likely_renamed = direct_il2cpp_file and hashed_name and entropy >= 7.5
    if not likely_renamed:
        return None
    # A full-file magic search and SHA256 are relatively expensive.  First
    # rank cheap filename/location/head/entropy signals, then collect deep
    # evidence only for a bounded number of strong candidates.
    magic_offsets, magic_scan_bytes, magic_scan_complete = ([], 0, False)
    if full_evidence:
        magic_offsets, magic_scan_bytes, magic_scan_complete = _scan_metadata_magic(path, size)
    first_version = _metadata_version_at(path, magic_offsets[0]) if magic_offsets else 0
    reasons = []
    if direct_il2cpp_file:
        reasons.append("located under il2cpp_data")
    if hashed_name:
        reasons.append("32-hex filename")
    if entropy >= 7.5:
        reasons.append("high entropy")
    if magic_offsets:
        reasons.append("valid metadata magic/version found")
    elif not full_evidence:
        reasons.append("deep magic scan pending candidate ranking")
    return {
        "path": str(path),
        "relative_path": rel_path,
        "size": size,
        "sha256": _sha256_file(path) if full_evidence else "",
        "head_hex": data[:16].hex(),
        "entropy": entropy,
        "entropy_sample_bytes": len(data),
        "hashed_filename": hashed_name,
        "magic_found": bool(magic_offsets),
        "magic_offsets": magic_offsets,
        "magic_scan_bytes": magic_scan_bytes,
        "magic_scan_complete": magic_scan_complete,
        "metadata_version_hint": first_version,
        "candidate_reason": reasons,
        "classification": "renamed_plain_candidate" if magic_offsets else "renamed_or_encrypted_candidate",
        "verified": False,
        "sdk_eligible": False,
    }


def scan_metadata_candidates(path: str) -> dict:
    """Discover plaintext and renamed/encrypted IL2CPP metadata candidates.

    The return schema deliberately distinguishes ``plain``, ``renamed``,
    ``encrypted_or_obfuscated`` and ``missing``.  Only the normal filename or
    a candidate whose bytes pass ``il2cpp.check_metadata_encrypted`` may be
    promoted by a later stage.  This scanner is read-only and never attempts
    to decrypt or rename source files.
    """
    root = Path(path)
    base = {
        "status": "metadata_missing",
        "standard_path": "",
        "candidates": [],
        "candidate_count": 0,
        "candidate_summary": "No IL2CPP metadata candidates were found.",
        "evidence": [],
    }
    if not root.is_dir():
        base.update({"status": "path_missing", "candidate_summary": "Target directory is not accessible."})
        return base

    il2cpp_dirs = []
    try:
        for directory in root.rglob("il2cpp_data"):
            if directory.is_dir():
                il2cpp_dirs.append(directory)
    except OSError:
        return base
    if not il2cpp_dirs:
        base["candidate_summary"] = "No il2cpp_data directory was found."
        return base

    standard = []
    candidates = []
    for base_dir in sorted(il2cpp_dirs, key=lambda item: item.as_posix().lower()):
        try:
            entries = sorted(base_dir.rglob("*"), key=lambda item: item.as_posix().lower())
        except OSError:
            continue
        for item in entries:
            if not item.is_file():
                continue
            try:
                size = item.stat().st_size
            except OSError:
                continue
            rel = item.relative_to(root).as_posix()
            if item.name.lower() == "global-metadata.dat":
                standard.append((item, size, rel))
                continue
            record = _metadata_candidate_record(item, size, rel, full_evidence=False)
            if record:
                candidates.append(record)

    if standard:
        item, size, rel = standard[0]
        base.update({
            "status": "metadata_named",
            "standard_path": str(item),
            "candidate_summary": "Found standard global-metadata.dat; validation is performed by the metadata stage.",
            "evidence": [{"path": str(item), "relative_path": rel, "size": size, "kind": "standard_name"}],
        })
    candidates.sort(key=lambda item: (
        not item["magic_found"],
        -item["entropy"],
        -item["size"],
        item["relative_path"].lower(),
    ))
    if len(candidates) > _METADATA_CANDIDATE_LIMIT:
        candidates = candidates[:_METADATA_CANDIDATE_LIMIT]
    # Upgrade the bounded top candidates with full SHA256 and a complete
    # magic scan.  Original sample files are still never modified.
    detailed_candidates = []
    for candidate in candidates:
        detailed = _metadata_candidate_record(
            Path(candidate["path"]),
            int(candidate["size"]),
            candidate["relative_path"],
            full_evidence=True,
        )
        if detailed:
            detailed_candidates.append(detailed)
    candidates = detailed_candidates
    candidates.sort(key=lambda item: (
        not item["magic_found"],
        -item["entropy"],
        -item["size"],
        item["relative_path"].lower(),
    ))
    base["candidates"] = candidates
    base["candidate_count"] = len(candidates)
    if candidates and not standard:
        has_plain = any(item["magic_found"] for item in candidates)
        base["status"] = "metadata_renamed_candidate" if has_plain else "metadata_renamed_or_obfuscated_candidate"
        base["candidate_summary"] = (
            "A renamed plaintext-metadata candidate was found; structural validation is still required."
            if has_plain else
            "High-entropy renamed files were found under il2cpp_data; encryption/obfuscation is suspected but not proven."
        )
        base["evidence"] = [
            {
                "path": item["path"],
                "relative_path": item["relative_path"],
                "size": item["size"],
                "entropy": item["entropy"],
                "head_hex": item["head_hex"],
                "magic_found": item["magic_found"],
                "candidate_reason": item["candidate_reason"],
            }
            for item in candidates
        ]
    return base


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


def _validation_evidence(key_files: list[dict], kinds: tuple[str, ...]) -> list[dict]:
    """Return a stable, compact evidence list for the Unity build verdict."""
    records = []
    for kind in kinds:
        for item in key_files:
            if item.get("kind") != kind:
                continue
            records.append({
                "kind": kind,
                "path": item.get("path", ""),
                "size": item.get("size", 0),
            })
    return records


def _validate_unity_structure(root: Path, detection: dict) -> dict:
    """Authenticate the discovered files as a usable Unity build.

    Detection and authentication intentionally remain separate.  A directory
    containing a copied ``GameAssembly.dll`` is an IL2CPP *signal*, but it is
    not enough evidence to treat the directory as a complete Unity target or
    to create an SDK export.
    """
    key_files = detection.get("key_files", []) or []
    has_gameassembly = any(item.get("kind") == "gameassembly" for item in key_files)
    has_metadata = any(item.get("kind") == "metadata" for item in key_files)
    has_managed = any(item.get("kind") == "managed" for item in key_files)
    has_globalgame = any(item.get("kind") == "globalgame" for item in key_files)
    has_player = any(item.get("kind") == "player" for item in key_files)
    has_runtime_marker = has_player or has_globalgame
    metadata_candidates = detection.get("metadata_candidates", {}) or {}
    candidate_status = metadata_candidates.get("status", "metadata_missing")
    candidate_count = int(metadata_candidates.get("candidate_count", 0) or 0)

    evidence = _validation_evidence(
        key_files,
        ("gameassembly", "metadata", "managed", "globalgame", "player"),
    )
    common_runtime_missing = "UnityPlayer.dll 或 <游戏名>_Data/globalgamemanagers"

    if not root.exists() or not root.is_dir():
        return {
            "valid": False,
            "status": "path_missing",
            "confidence": "none",
            "build_type": "Other",
            "sdk_eligible": False,
            "evidence": evidence,
            "missing": ["可访问的 Unity 游戏根目录"],
            "reason": "目标目录不存在，或目标不是目录。",
        }

    # A complete IL2CPP SDK input pair is sufficient evidence even when a
    # platform-specific package does not retain UnityPlayer.dll beside it.
    if has_gameassembly and has_metadata:
        return {
            "valid": True,
            "status": "valid_il2cpp",
            "confidence": "high" if has_runtime_marker else "medium",
            "build_type": "IL2CPP",
            "sdk_eligible": True,
            "evidence": evidence,
            "missing": [] if has_runtime_marker else [common_runtime_missing],
            "reason": (
                "检测到 GameAssembly.dll 与 global-metadata.dat，"
                "IL2CPP 结构已认证，可进入元数据检查和 SDK 导出。"
                if has_runtime_marker else
                "检测到 IL2CPP SDK 所需的 GameAssembly.dll 与 global-metadata.dat；"
                "未找到典型运行时标记，但输入对仍可进行离线分析。"
            ),
        }

    # A runnable IL2CPP layout with a missing metadata file is still a valid
    # Unity build.  It must stay visible to the user, but the SDK stage is
    # ineligible until the metadata file is recovered.
    if has_gameassembly and has_runtime_marker:
        candidate_note = ""
        if candidate_count:
            candidate_note = (
                f" Detected {candidate_count} renamed/encrypted metadata candidate(s) under il2cpp_data; "
                "none is SDK-eligible until structural/decryption validation succeeds."
            )
        return {
            "valid": True,
            "status": "valid_il2cpp_metadata_missing",
            "confidence": "medium",
            "build_type": "IL2CPP",
            "sdk_eligible": False,
            "evidence": evidence,
            "missing": ["<游戏名>_Data/il2cpp_data/Metadata/global-metadata.dat"],
            "metadata_candidate_status": candidate_status,
            "metadata_candidate_count": candidate_count,
            "reason": (
                "检测到 GameAssembly.dll 和 Unity 运行时标记，已认证为 IL2CPP 构建；"
                "但没有找到 global-metadata.dat，因此不会生成 SDK。" + candidate_note
            ),
        }

    if has_metadata and has_runtime_marker:
        return {
            "valid": True,
            "status": "valid_il2cpp_gameassembly_missing",
            "confidence": "medium",
            "build_type": "IL2CPP",
            "sdk_eligible": False,
            "evidence": evidence,
            "missing": ["GameAssembly.dll"],
            "reason": (
                "检测到 global-metadata.dat 和 Unity 运行时标记，已认证为 IL2CPP 布局；"
                "但缺少 GameAssembly.dll，因此不会生成 SDK。"
            ),
        }

    if has_managed and has_runtime_marker:
        return {
            "valid": True,
            "status": "valid_mono",
            "confidence": "high",
            "build_type": "Mono",
            "sdk_eligible": False,
            "evidence": evidence,
            "missing": [],
            "reason": "检测到 Data/Managed 程序集和 Unity 运行时标记，已认证为 Mono 构建。",
        }

    if has_player and has_globalgame:
        return {
            "valid": True,
            "status": "valid_unclassified_unity",
            "confidence": "medium",
            "build_type": "Other",
            "sdk_eligible": False,
            "evidence": evidence,
            "missing": ["可识别的 IL2CPP 或 Mono 脚本后端文件"],
            "reason": "检测到 UnityPlayer.dll 和 globalgamemanagers，但未识别出可用脚本后端。",
        }

    if has_gameassembly or has_metadata:
        missing = []
        if not has_gameassembly:
            missing.append("GameAssembly.dll")
        if not has_metadata:
            missing.append("<游戏名>_Data/il2cpp_data/Metadata/global-metadata.dat")
        if not has_runtime_marker:
            missing.append(common_runtime_missing)
        return {
            "valid": False,
            "status": "incomplete_il2cpp_layout",
            "confidence": "low",
            "build_type": "IL2CPP",
            "sdk_eligible": False,
            "evidence": evidence,
            "missing": missing,
            "reason": (
                "发现 IL2CPP 相关文件，但缺少足以认证为完整 Unity 构建的结构证据；"
                "后续 SDK 阶段将被阻止。"
            ),
        }

    if has_managed:
        return {
            "valid": False,
            "status": "incomplete_mono_layout",
            "confidence": "low",
            "build_type": "Mono",
            "sdk_eligible": False,
            "evidence": evidence,
            "missing": [common_runtime_missing],
            "reason": "发现 Managed 程序集，但没有 Unity 运行时标记，无法认证为完整 Mono 构建。",
        }

    return {
        "valid": False,
        "status": "not_unity_build",
        "confidence": "none",
        "build_type": "Other",
        "sdk_eligible": False,
        "evidence": evidence,
        "missing": [
            "GameAssembly.dll 或 Data/Managed/*.dll",
            "UnityPlayer.dll 或 <游戏名>_Data/globalgamemanagers",
        ],
        "reason": "目录存在，但没有发现可确认 Unity 构建的关键文件结构。",
    }


def validate_unity_structure(path: str, detection: dict | None = None) -> dict:
    """Return an explainable Unity build authentication verdict for ``path``."""
    root = Path(path)
    if detection is None:
        detection = detect_unity(path)
    return _validate_unity_structure(root, detection)


def detect_unity(path: str) -> dict:
    """检测游戏文件夹是否为 Unity 构建,识别版本与构建类型。"""
    root = Path(path)
    result = {
        "path": str(root),
        "exists": root.exists(),
        "unity_version": "",
        "build_type": "Other",
        "build_evidence": {
            "selected": "Other",
            "confidence": "none",
            "candidate_modes": [],
            "il2cpp": [],
            "mono": [],
            "mixed": False,
        },
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

    # Preserve the facts used for mode selection.  A managed directory may
    # contain plugins in an IL2CPP build, so it is intentionally secondary to
    # the IL2CPP layout signals.
    il2cpp_evidence = []
    mono_evidence = []
    if has_gameassembly:
        il2cpp_evidence.append("GameAssembly.dll")
    if has_il2cpp_data:
        il2cpp_evidence.append("Data/il2cpp_data")
    if any(p.name.lower() == "global-metadata.dat" for p, _ in keys):
        il2cpp_evidence.append("global-metadata.dat")
    if has_managed:
        mono_evidence.append("Data/Managed/*.dll")

    if build_type == "IL2CPP" and has_il2cpp_data and has_gameassembly:
        confidence = "high"
    elif build_type == "IL2CPP" and has_il2cpp_data:
        confidence = "high"
    elif build_type == "IL2CPP" and has_gameassembly:
        confidence = "medium"
    elif build_type == "Mono" and has_managed:
        confidence = "high"
    else:
        confidence = "low" if has_globalgame else "none"
    candidates = []
    if il2cpp_evidence:
        candidates.append("IL2CPP")
    if mono_evidence:
        candidates.append("Mono")
    result["build_evidence"] = {
        "selected": build_type,
        "confidence": confidence,
        "candidate_modes": candidates,
        "il2cpp": il2cpp_evidence,
        "mono": mono_evidence,
        "mixed": bool(il2cpp_evidence and mono_evidence),
        "note": (
            "Managed assemblies may be plugins in an IL2CPP build"
            if il2cpp_evidence and mono_evidence else ""
        ),
    }

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
    # Candidate scan is evidence-only.  It never promotes an arbitrary blob
    # to ``metadata`` and never changes SDK eligibility by itself.  Run it
    # after the lightweight build/Unity version detection so detection stays
    # responsive even when a game has a large il2cpp_data directory.
    result["metadata_candidates"] = scan_metadata_candidates(str(root))
    result["key_files"].sort(key=lambda x: x["kind"])
    result["structure_validation"] = _validate_unity_structure(root, result)
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
