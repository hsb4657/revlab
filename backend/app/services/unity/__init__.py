"""Unity 引擎专项分析 —— 引擎阶段式工作流
供 engine_runner.EngineRunner 调用的模块契约:
  STAGES         阶段名列表(顺序执行)
  TITLES         {stage: 中文名}
  execute_stage(stage, ctx, result) -> dict  执行单阶段,返回要并入 result 的 dict
  summarize(result) -> dict                  生成精简 summary

ctx = {"params": {...}, "target_path": 游戏文件夹绝对路径, "sample_path": str|None,
       "data": bytes|None, "analysis_id": int, "workdir": Path}
result 为已执行阶段结果 dict(可读前序阶段输出)。
内部复用 detector(目录/版本/构建类型)、mono(.NET 程序集)、il2cpp(metadata 解析/解密/SDK dump,
由并行任务创建,按需懒加载)、analyzer(聚合辅助)。
"""
from __future__ import annotations
import logging
from pathlib import Path

from ...core.config import config
from .. import hash as _hash_svc
from .. import report as _report_svc
from . import detector as _detector
from . import mono as _mono
from .analyzer import UnityAnalyzer

log = logging.getLogger("revlab.engine.unity")

STAGES = ["scan", "version", "buildtype", "assembly", "resource", "strings", "decrypt", "sdk", "report"]
TITLES = {
    "scan": "目录扫描",
    "version": "版本识别",
    "buildtype": "构建类型判定",
    "assembly": "程序集/DLL分析",
    "resource": "资源文件分析",
    "strings": "关键字符串",
    "decrypt": "Metadata 解密",
    "sdk": "SDK Dump",
    "report": "报告生成",
}


# ---------------------------------------------------------------- 入口契约
def execute_stage(stage: str, ctx: dict, result: dict) -> dict:
    """执行单个阶段,返回该阶段结果 dict。EngineRunner 会 result[stage] = 返回 dict。"""
    fn = {
        "scan": _stage_scan,
        "version": _stage_version,
        "buildtype": _stage_buildtype,
        "assembly": _stage_assembly,
        "resource": _stage_resource,
        "strings": _stage_strings,
        "decrypt": _stage_decrypt,
        "sdk": _stage_sdk,
        "report": _stage_report,
    }.get(stage)
    if fn is None:
        raise ValueError(f"unknown stage: {stage}")
    return fn(ctx, result)


def summarize(result: dict) -> dict:
    """精简汇总,写入 result['summary']。"""
    v = result.get("version", {}) or {}
    bt = result.get("buildtype", {}) or {}
    asm = result.get("assembly", {}) or {}
    dec = result.get("decrypt", {}) or {}
    sdk = result.get("sdk", {}) or {}

    counts = {"types": 0, "methods": 0, "fields": 0}
    for a in asm.get("managed_assemblies", []) or []:
        counts["types"] += a.get("type_count", 0)
        counts["methods"] += a.get("methods_hint", 0)
        counts["fields"] += a.get("fields_count", 0)
    md = asm.get("metadata", {}) or {}
    if md.get("type_count") is not None:
        counts["types"] = md.get("type_count", counts["types"])
        counts["methods"] = md.get("method_count", counts["methods"])
        counts["fields"] = md.get("field_count", counts["fields"])
    # 避免 dict 直接转 JSON 时 count 字段非 int
    counts = {k: (int(v) if isinstance(v, (int, float)) else v) for k, v in counts.items()}

    return {
        "unity_version": v.get("version") or v.get("detected_version") or "",
        "build_type": bt.get("build_type") or "",
        "mode": asm.get("mode") or "",
        "types": counts["types"],
        "methods": counts["methods"],
        "fields": counts["fields"],
        "metadata_encrypted": bool(dec.get("encrypted")),
        "metadata_status": dec.get("status", "not_checked"),
        "decryption_required": bool(dec.get("decryption_required")),
        "decryption_attempted": bool(dec.get("decryption_attempted")),
        "decryption_status": dec.get("decryption_status", "not_checked"),
        "runtime_validation_required": bool((dec.get("runtime_validation") or {}).get("required")),
        "sdk_dumped": bool(sdk.get("ok")),
        "sdk_delivery_complete": bool(sdk.get("delivery_complete")),
        "sdk_manifest": sdk.get("manifest", ""),
    }


# ---------------------------------------------------------------- 工具
def _get_params(ctx: dict) -> dict:
    return ctx.get("params") or {}


def _target_name(ctx: dict) -> str:
    """目标文件夹名(不含路径),用于报告/sdk 输出命名。"""
    p = Path(ctx.get("target_path") or "")
    return p.name or "unity"


def _report_source_name(ctx: dict, result: dict) -> str:
    """Return the primary analyzed file for report identity.

    Unity input is normally a directory.  Prefer the executable that matches
    the directory name, then fall back to another root executable and finally
    the directory itself.  This keeps report names tied to the build the user
    selected instead of to a task id or a generic ``unity`` label.
    """
    root = Path(ctx.get("target_path") or "")
    if root.is_dir():
        # The user supplied the game/application directory, so its name is the
        # delivery identity. Executable names remain evidence inside the report.
        return root.name
    for kind in ("gameassembly", "metadata"):
        path = _find_kind_path(result, ctx, kind)
        if path:
            return Path(path).name
    return _target_name(ctx)


def _dynamic_validation_contract(*, reason: str, metadata: str = "", gameassembly: str = "") -> dict:
    """Describe the evidence required when static metadata recovery is not enough."""
    return {
        "required": True,
        "status": "pending",
        "reason": reason,
        "inputs": {
            "metadata": metadata,
            "gameassembly": gameassembly,
            "same_build_required": True,
        },
        "steps": [
            "Capture the metadata-loading/decryption call in the same build and record module base plus build hashes.",
            "Record the decoder entry, input/output buffers, key/operation, and the first valid metadata header bytes.",
            "Re-run the decoder for at least two independent reads and retain before/after hashes and lengths.",
            "Parse the recovered bytes with the metadata validator and compare type/method/string table bounds.",
        ],
        "evidence": [
            "module/build hash pair",
            "decoder call trace and key/operation",
            "recovered metadata SHA-256",
            "validated header version and table-boundary report",
        ],
        "acceptance": [
            "The recovered bytes parse as a supported metadata version.",
            "Two repeated reads produce identical hashes and table counts.",
            "Only a verified decrypted file is passed to SDK export; header repair alone does not qualify.",
        ],
    }


def _new_analyzer(ctx: dict, version: str = "") -> UnityAnalyzer:
    return UnityAnalyzer(ctx["target_path"], version=version)


def _reports_unity_dir() -> Path:
    d = config.REPORTS_DIR / "unity"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _run_output_dir(ctx: dict, bucket: str | None = None) -> Path | None:
    """Resolve an engine run's output directory, when called by a runner."""
    raw = ctx.get("output_dir")
    if not raw:
        return None
    root = Path(raw)
    return root / bucket if bucket else root


def _il2cpp():
    """懒加载 il2cpp 模块(并行任务创建)。缺失时抛 ImportError。"""
    from . import il2cpp  # noqa: F401
    import importlib
    return importlib.import_module(".il2cpp", __package__)


def _metadata_path(result: dict, ctx: dict) -> str:
    """当前可用的 metadata 绝对路径(原版或解密后)。"""
    dec = (result.get("decrypt", {}) or {})
    if dec.get("decrypted") and dec.get("verified") and dec.get("decrypted_path"):
        p = Path(dec["decrypted_path"])
        if p.exists():
            return str(p)
    return _find_kind_path(result, ctx, "metadata")


def _metadata_candidates(result: dict, ctx: dict) -> dict:
    """Return renamed/encrypted Metadata evidence collected during scan.

    This is deliberately separate from ``_metadata_path``.  Candidates must
    not silently become SDK inputs just because their names and entropy look
    suspicious.
    """
    scan = result.get("scan", {}) or {}
    detect = scan.get("detect", {}) or {}
    candidates = detect.get("metadata_candidates", {}) or {}
    if candidates:
        return candidates
    try:
        return _detector.scan_metadata_candidates(str(ctx.get("target_path") or ""))
    except Exception as exc:
        return {
            "status": "inspection_failed",
            "candidate_count": 0,
            "candidates": [],
            "candidate_summary": f"Metadata candidate scan failed: {exc}",
        }


def _scan_version(scan: dict) -> str:
    d = scan.get("detect", {}) or {}
    return d.get("unity_version") or ""


def _scan_buildtype(scan: dict) -> str:
    d = scan.get("detect", {}) or {}
    return d.get("build_type") or "Other"


def _find_kind_path(result: dict, ctx: dict, kind: str) -> str:
    """从 scan 阶段结果中找指定 kind 的绝对路径(detect.key_files 或 structure.files)。"""
    scan = result.get("scan", {}) or {}
    candidates = []
    d = scan.get("detect", {}) or {}
    candidates.extend(d.get("key_files", []) or [])
    st = scan.get("structure", {}) or {}
    candidates.extend(st.get("files", []) or [])
    for f in candidates:
        if f.get("kind") == kind:
            p = Path(f["path"])
            if p.is_absolute():
                return str(p)
            # detector paths are normally absolute when the target is
            # absolute, but a relative target makes rglob return a path that
            # already includes the target prefix.  Check that form before
            # joining it again.
            if p.exists():
                return str(p.resolve())
            candidate = Path(ctx["target_path"]) / p
            if candidate.exists():
                return str(candidate.resolve())
            return str(candidate)
    return ""


# ---------------------------------------------------------------- 阶段:目录扫描
def _stage_scan(ctx: dict, result: dict) -> dict:
    a = _new_analyzer(ctx)
    a.run_scan()
    a.run_detect()
    return {
        "detect": a.detect,
        "build_evidence": (a.detect or {}).get("build_evidence", {}),
        "structure": a.scan,
    }


# ---------------------------------------------------------------- 阶段:版本识别
def _stage_version(ctx: dict, result: dict) -> dict:
    params = _get_params(ctx)
    scan = result.get("scan", {}) or {}
    detected = _scan_version(scan)
    user_ver = str(params.get("version") or "")
    if user_ver:
        return {"version": user_ver, "detected_version": detected, "source": "user-params", "overridden": True}
    if detected:
        return {"version": detected, "detected_version": detected, "source": "scan", "overridden": False}
    # 兜底:独立再扫描一次
    a = _new_analyzer(ctx)
    det = a.run_detect()
    v = det.get("unity_version") or ""
    return {"version": v, "detected_version": v, "source": "rescan", "overridden": False}


# ---------------------------------------------------------------- 阶段:构建类型判定
def _stage_buildtype(ctx: dict, result: dict) -> dict:
    scan = result.get("scan", {}) or {}
    bt = _scan_buildtype(scan)
    evidence = (scan.get("detect", {}) or {}).get("build_evidence", {}) or {}
    if bt not in ("Mono", "IL2CPP"):
        a = _new_analyzer(ctx)
        det = a.run_detect()
        bt = det.get("build_type", "Other")
        evidence = det.get("build_evidence", {}) or {}
    return {
        "build_type": bt,
        "confidence": evidence.get("confidence", "none"),
        "evidence": evidence,
        "mixed_layout": bool(evidence.get("mixed")),
        "note": "IL2CPP: GameAssembly.dll / Data/il2cpp_data; Mono: Data/Managed/*.dll",
    }


# ---------------------------------------------------------------- 阶段:程序集/DLL分析
def _stage_assembly(ctx: dict, result: dict) -> dict:
    bt = (result.get("buildtype", {}) or {}).get("build_type", "Other")
    if bt == "Mono":
        md = _new_analyzer(ctx).managed_dir()
        evidence = (result.get("buildtype", {}) or {}).get("evidence", {})
        if md:
            return {
                "mode": "Mono",
                "mode_evidence": evidence,
                "managed_dir": md,
                "managed_assemblies": _mono.analyze_managed_dir(md),
                "api_stats": _mono.api_usage_stats(md),
            }
        return {
            "mode": "Mono",
            "mode_evidence": evidence,
            "managed_dir": "",
            "managed_assemblies": [],
            "note": "未找到 Data/Managed",
        }
    if bt == "IL2CPP":
        return _new_analyzer(ctx).analyze_assemblies()
    a = _new_analyzer(ctx)
    return a.analyze_assemblies()


# ---------------------------------------------------------------- 阶段:资源文件分析
def _stage_resource(ctx: dict, result: dict) -> dict:
    a = _new_analyzer(ctx)
    res = a.find_resources()
    return {"resources": res, "count": len(res)}


# ---------------------------------------------------------------- 阶段:关键字符串
def _stage_strings(ctx: dict, result: dict) -> dict:
    a = _new_analyzer(ctx)
    r = a.extract_strings()
    # 兴趣字符串截断,避免结果过大
    r["interesting"] = r["interesting"][:200]
    return r


# ---------------------------------------------------------------- 阶段:Metadata 解密
def _stage_decrypt(ctx: dict, result: dict) -> dict:
    build_type = (result.get("buildtype", {}) or {}).get("build_type", "Other")
    if build_type == "Mono":
        return {
            "ok": True,
            "status": "not_applicable",
            "decryption_status": "not_applicable",
            "decryption_required": False,
            "decryption_attempted": False,
            "encrypted": None,
            "decrypted": False,
            "verified": False,
            "metadata": "",
            "usable_metadata_path": "",
            "note": "Mono build: IL2CPP global-metadata.dat is not applicable",
        }
    if build_type != "IL2CPP":
        return {
            "ok": False,
            "status": "not_applicable",
            "decryption_status": "not_applicable",
            "decryption_required": False,
            "decryption_attempted": False,
            "encrypted": None,
            "decrypted": False,
            "verified": False,
            "metadata": "",
            "usable_metadata_path": "",
            "note": "Unity build type was not confirmed as IL2CPP",
        }
    meta = _metadata_path(result, ctx)
    if not meta or not Path(meta).exists():
        # Some protected IL2CPP games replace global-metadata.dat with a
        # descriptor plus encrypted parts.  Recipes are fingerprinted and
        # fail closed; only a structurally verified reconstruction can become
        # the SDK input.
        from . import split_metadata

        split_detection = split_metadata.detect_recipe(ctx.get("target_path") or "")
        if split_detection.get("supported"):
            out_dir = _run_output_dir(ctx, "decryption") or (
                _reports_unity_dir() / f"{_target_name(ctx)}_decrypted"
            )
            try:
                recovery = split_metadata.recover(
                    ctx.get("target_path") or "",
                    out_dir,
                    recipe=split_detection["recipe"],
                )
                recovered_path = str((recovery.get("output") or {}).get("path") or "")
                il2cpp = _il2cpp()
                inspection = il2cpp.check_metadata_encrypted(recovered_path)
                if inspection.get("status") != "plain" or not inspection.get("parseable"):
                    raise ValueError(
                        "reconstructed metadata did not pass the IL2CPP structural validator"
                    )
                return {
                    "ok": True,
                    "status": "decrypted",
                    "decryption_status": "decrypted",
                    "decryption_required": True,
                    "decryption_attempted": True,
                    "encrypted": True,
                    "encryption_suspected": True,
                    "decrypted": True,
                    "repaired": False,
                    "verified": True,
                    "method": "fingerprinted_split_metadata_recipe",
                    "recipe": recovery.get("recipe", ""),
                    "metadata": "",
                    "source_metadata_path": recovery.get("source_root", ""),
                    "decrypted_path": recovered_path,
                    "usable_metadata_path": recovered_path,
                    "recovery_manifest": recovery.get("manifest_path", ""),
                    "split_container_detection": split_detection,
                    "recovery": recovery,
                    "version": inspection.get("version"),
                    "diagnostics": inspection.get("diagnostics", []),
                    "note": (
                        "Encrypted split IL2CPP metadata was recovered and passed descriptor, "
                        "table-boundary, string-anchor and metadata parser validation."
                    ),
                    "runtime_validation": {
                        "required": False,
                        "status": "satisfied_by_reproducible_static_recovery",
                        "reason": (
                            "The complete reversible loader format was reconstructed and the "
                            "result passed independent structural validation."
                        ),
                    },
                }
            except Exception as exc:
                return {
                    "ok": False,
                    "status": "decryption_failed",
                    "decryption_status": "failed",
                    "decryption_required": True,
                    "decryption_attempted": True,
                    "encrypted": True,
                    "encryption_suspected": True,
                    "decrypted": False,
                    "verified": False,
                    "usable_metadata_path": "",
                    "split_container_detection": split_detection,
                    "error": str(exc),
                    "note": f"Supported split metadata recovery failed: {exc}",
                    "runtime_validation": _dynamic_validation_contract(
                        reason="The recognized encrypted container did not pass strict recovery validation.",
                        gameassembly=_find_kind_path(result, ctx, "gameassembly"),
                    ),
                }
        candidates = _metadata_candidates(result, ctx)
        candidate_status = candidates.get("status", "metadata_missing")
        candidate_count = int(candidates.get("candidate_count", 0) or 0)
        ga = _find_kind_path(result, ctx, "gameassembly")
        assembly = result.get("assembly", {}) or {}
        loader_hints = assembly.get("gameassembly_metadata_hints", {}) or {}
        candidate_paths = [
            item.get("path", "")
            for item in (candidates.get("candidates", []) or [])
            if isinstance(item, dict)
        ]
        encrypted_candidate = candidate_status == "metadata_renamed_or_obfuscated_candidate"
        recovery_dir = _run_output_dir(ctx, "decryption") or (
            _reports_unity_dir() / f"{_target_name(ctx)}_decrypted"
        )
        try:
            split = _il2cpp().recover_split_metadata(ctx["target_path"], str(recovery_dir))
        except Exception as exc:
            split = {"recognized": True, "error": str(exc), "output": {}, "validation": {}}
        if split.get("recognized") and split.get("output", {}).get("path"):
            recovered = split["output"]["path"]
            verification = _il2cpp().check_metadata_encrypted(recovered)
            if verification.get("status") == "plain":
                return {
                    "ok": True,
                    "status": "decrypted",
                    "decryption_status": "decrypted",
                    "decryption_required": True,
                    "decryption_attempted": True,
                    "encrypted": True,
                    "encryption_suspected": True,
                    "decrypted": True,
                    "verified": True,
                    "metadata": recovered,
                    "source_metadata_path": split.get("descriptor", {}).get("path", ""),
                    "usable_metadata_path": recovered,
                    "decrypted_path": recovered,
                    "method": "AES-128-ECB split container recovery and bounded table normalization",
                    "recipe": split.get("recipe", ""),
                    "recovery_manifest": split.get("manifest_path", ""),
                    "recovery": split,
                    "runtime_validation": {
                        "required": False,
                        "status": "not_required",
                        "reason": "Static loader format was identified and the recovered metadata passed structural validation.",
                    },
                    "note": "Supported split metadata container recovered into the current workflow run.",
                }
            split["verification"] = verification
        note = "IL2CPP layout was detected but global-metadata.dat was not found"
        if candidate_count:
            note += (
                f"; {candidate_count} renamed/encrypted candidate(s) were recorded under il2cpp_data. "
                "They are not treated as decrypted metadata and SDK export remains blocked."
            )
        return {
            "ok": False,
            "status": candidate_status,
            # High entropy and a hashed name are a reason to investigate, not
            # proof that this is encrypted Metadata.  Do not start a decoder
            # or claim "encrypted" until bytes are tied to the loader and a
            # recovered payload passes the structural validator.
            "decryption_status": "not_attempted_unverified_candidate" if candidate_count else "not_started",
            "decryption_required": False,
            "decryption_attempted": False,
            "encrypted": False,
            "encryption_suspected": encrypted_candidate,
            "decrypted": False,
            "verified": False,
            "metadata": "",
            "source_metadata_path": "",
            "usable_metadata_path": "",
            "metadata_candidates": candidates,
            "metadata_candidate_status": candidate_status,
            "metadata_candidate_count": candidate_count,
            "gameassembly_loader_hints": loader_hints,
            "recovery_detection": split.get("detection", {}),
            "note": note,
            "runtime_validation": _dynamic_validation_contract(
                reason=(
                    "No standard metadata file was found; high-entropy renamed candidates require a build-matched "
                    "runtime metadata-loader/decryption trace before any candidate can be accepted. Static evidence "
                    "does not establish that the candidates are encrypted Metadata."
                    if encrypted_candidate else
                    "No standard metadata file was found. Verify whether metadata was renamed, packed externally, "
                    "or omitted from the supplied directory before attempting SDK export."
                ),
                metadata="; ".join(candidate_paths),
                gameassembly=ga,
            ) if candidate_count else {},
        }
    try:
        il2cpp = _il2cpp()
    except ImportError as e:
        return {
            "ok": False,
            "status": "analyzer_unavailable",
            "decryption_status": "not_started",
            "decryption_required": False,
            "decryption_attempted": False,
            "encrypted": None,
            "decrypted": False,
            "verified": False,
            "metadata": meta,
            "usable_metadata_path": "",
            "note": f"il2cpp module is unavailable: {e}",
        }

    try:
        chk = il2cpp.check_metadata_encrypted(meta)
    except Exception as e:
        return {
            "ok": False,
            "status": "inspection_failed",
            "decryption_status": "not_started",
            "decryption_required": False,
            "decryption_attempted": False,
            "encrypted": None,
            "decrypted": False,
            "verified": False,
            "metadata": meta,
            "usable_metadata_path": "",
            "note": f"metadata inspection failed: {e}",
            "error": str(e),
        }

    encrypted = bool(chk.get("encrypted"))
    out = {
        "encrypted": encrypted,
        "encryption_suspected": bool(chk.get("encryption_suspected", encrypted)),
        "decryption_required": bool(chk.get("decrypt_required") and encrypted),
        "decryption_attempted": False,
        "ok": bool(chk.get("parseable")),
        "status": chk.get("status", "inspection_failed"),
        "decryption_status": "not_started",
        "metadata": meta,
        "source_metadata_path": meta,
        "usable_metadata_path": "",
        "version": chk.get("version"),
        "reason": chk.get("reason"),
        "magic": chk.get("magic"),
        "entropy": chk.get("entropy"),
        "diagnostics": chk.get("diagnostics", []),
        "decrypted": False,
        "repaired": False,
        "verified": False,
        "method": "",
        "decrypted_path": "",
    }
    if chk.get("status") == "plain":
        out.update({
            "ok": True,
            "decryption_status": "not_required",
            "decryption_required": False,
            "verified": True,
            "usable_metadata_path": meta,
            "note": "metadata is verified plaintext and ready for SDK export",
        })
        return out

    # A corrupt/unknown file may be unrecoverable without containing any
    # encryption evidence.  Do not invoke a decoder merely because a generic
    # recovery hint was returned; report the inspection result directly.
    if not encrypted or not chk.get("decrypt_required"):
        out.update({
            "ok": False,
            "decryption_status": "not_required",
            "decryption_required": False,
            "note": "metadata is not verified plaintext, but no encryption evidence was found; decryption was not attempted",
        })
        return out

    if not chk.get("recovery_recommended"):
        out.update({
            "ok": False,
            "decryption_status": "not_recommended",
            "decryption_required": True,
            "note": "encryption evidence was found, but no reversible recovery strategy is available",
            "runtime_validation": _dynamic_validation_contract(
                reason="Encrypted/obfuscated metadata needs a build-matched runtime decoder trace.",
                metadata=meta,
            ),
        })
        return out

    ga = _find_kind_path(result, ctx, "gameassembly")
    out_dir = _run_output_dir(ctx, "decryption") or (
        _reports_unity_dir() / f"{_target_name(ctx)}_decrypted"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "global-metadata.dat"
    try:
        out["decryption_attempted"] = True
        dr = il2cpp.decrypt_metadata(meta, gameassembly_path=ga, out_path=str(out_path))
    except Exception as e:
        return {
            **out,
            "ok": False,
            "status": "decryption_failed",
            "decryption_status": "failed",
            "decryption_required": True,
            "runtime_validation": _dynamic_validation_contract(
                reason="Automatic metadata recovery raised an exception.",
                metadata=meta,
                gameassembly=ga,
            ),
            "note": f"metadata recovery failed: {e}",
            "error": str(e),
        }
    validated = bool(dr.get("ok") and dr.get("verified"))
    decrypted = bool(validated and dr.get("decrypted"))
    repaired = bool(validated and (dr.get("repaired") or dr.get("status") == "header_repaired"))
    result_status = str(dr.get("status") or "decryption_failed")
    decrypted_path = dr.get("decrypted_path") if validated else ""
    # A repaired header is useful evidence, but it is not an authenticated
    # plaintext/decryption result. Keep the path for inspection while leaving
    # usable_metadata_path empty so SDK export remains blocked.
    usable_path = decrypted_path if decrypted else ""
    out.update({
        "ok": validated,
        "status": result_status if validated else "decryption_failed",
        "decryption_status": result_status if validated else "failed",
        "decrypted": decrypted,
        "repaired": repaired,
        "verified": validated,
        "method": dr.get("method") or "",
        "decrypted_path": decrypted_path,
        "usable_metadata_path": usable_path,
        "note": dr.get("note") or ("metadata header repaired; SDK export remains blocked" if repaired else ""),
        "decryption_diagnostics": dr.get("diagnostics", []),
    })
    if not decrypted:
        out["runtime_validation"] = _dynamic_validation_contract(
            reason=(
                "Metadata recovery produced no verified decrypted payload; a runtime decoder trace is required."
                if result_status in ("decryption_failed", "header_repaired")
                else "Metadata recovery status requires runtime confirmation."
            ),
            metadata=meta,
            gameassembly=ga,
        )
    else:
        out["runtime_validation"] = {
            "required": False,
            "status": "not_required",
            "reason": "Metadata was decoded and passed the structural validator; no runtime decryption step remains.",
        }
    return out


# ---------------------------------------------------------------- 阶段:SDK Dump
def _stage_sdk(ctx: dict, result: dict) -> dict:
    build_type = (result.get("buildtype", {}) or {}).get("build_type", "Other")
    if build_type == "Mono":
        return {
            "ok": True,
            "status": "not_applicable",
            "delivery_complete": False,
            "mode": "Mono",
            "manifest": "",
            "note": "Mono build: use managed assembly analysis; IL2CPP Dump.cs export is not applicable",
        }
    if build_type != "IL2CPP":
        return {
            "ok": False,
            "status": "not_applicable",
            "delivery_complete": False,
            "mode": build_type,
            "manifest": "",
            "note": "IL2CPP SDK export requires a confirmed IL2CPP build",
        }
    dec = result.get("decrypt", {}) or {}
    if dec.get("status") not in ("plain", "decrypted") or not dec.get("verified"):
        return {
            "ok": False,
            "status": "blocked_by_metadata",
            "delivery_complete": False,
            "mode": "IL2CPP",
            "manifest": "",
            "metadata_status": dec,
            "note": "SDK export is blocked until metadata is verified plaintext",
        }
    meta = _metadata_path(result, ctx)
    if not meta or not Path(meta).exists():
        return {
            "ok": False,
            "status": "metadata_missing",
            "delivery_complete": False,
            "mode": "IL2CPP",
            "manifest": "",
            "note": "No verified metadata is available for SDK export",
        }
    try:
        il2cpp = _il2cpp()
    except ImportError as e:
        return {
            "ok": False,
            "status": "analyzer_unavailable",
            "delivery_complete": False,
            "mode": "IL2CPP",
            "manifest": "",
            "note": f"il2cpp module is unavailable: {e}",
        }

    ga = _find_kind_path(result, ctx, "gameassembly")

    out_dir = _run_output_dir(ctx, "sdk") or (
        _reports_unity_dir() / f"sdk_{_target_name(ctx)}"
    )
    try:
        registration = il2cpp._pe_registration_addresses(ga, meta)
        r = il2cpp.dump_sdk(meta, ga, str(out_dir), registration=registration)
    except Exception as e:
        log.exception("sdk dump failed")
        return {
            "ok": False,
            "status": "failed",
            "delivery_complete": False,
            "mode": "IL2CPP",
            "manifest": "",
            "note": f"SDK dump failed: {e}",
            "error": str(e),
        }
    r["meta_path"] = meta
    r["gameassembly_path"] = ga or ""
    r["out_dir"] = str(out_dir)
    r["mode"] = "IL2CPP"
    r["registration"] = r.get("registration") or registration
    r["ok"] = bool(r.get("ok"))
    return r


# ---------------------------------------------------------------- 阶段:报告生成
def _stage_report(ctx: dict, result: dict) -> dict:
    a = _new_analyzer(ctx)
    a.run_scan()
    total = a.scan.get("total_size", 0)
    # SHA256:优先 GameAssembly.dll,其次 metadata,其次首个关键文件
    blob = b""
    for kind in ("gameassembly", "metadata"):
        for f in a.scan.get("files", []):
            if f.get("kind") == kind:
                p = Path(f["path"])
                if not p.is_absolute() and not p.exists():
                    p = Path(ctx["target_path"]) / p
                try:
                    blob = p.read_bytes()
                except OSError:
                    blob = b""
                if blob:
                    break
        if blob:
            break
    source_name = _report_source_name(ctx, result)
    name = _target_name(ctx)
    sample = {
        "file_name": source_name,
        "target_name": name,
        "target_path": str(ctx.get("target_path") or ""),
        "file_size": total,
        "sha256": _hash_svc.compute_hashes(blob)["sha256"] if blob else "",
    }
    rep = _report_svc.build_report(sample, {"unity": result})
    out = _run_output_dir(ctx, "report") or _reports_unity_dir()
    report_name = _report_svc.analysis_report_name(source_name, "unity")
    paths = _report_svc.save_report(rep, out, report_name)
    return {
        "name": source_name,
        "target_name": name,
        "report_name": report_name,
        "total_size": total,
        "report_paths": paths,
    }
