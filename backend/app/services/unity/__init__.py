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
        "sdk_dumped": bool(sdk.get("ok")),
    }


# ---------------------------------------------------------------- 工具
def _get_params(ctx: dict) -> dict:
    return ctx.get("params") or {}


def _target_name(ctx: dict) -> str:
    """目标文件夹名(不含路径),用于报告/sdk 输出命名。"""
    p = Path(ctx.get("target_path") or "")
    return p.name or "unity"


def _new_analyzer(ctx: dict, version: str = "") -> UnityAnalyzer:
    return UnityAnalyzer(ctx["target_path"], version=version)


def _reports_unity_dir() -> Path:
    d = config.REPORTS_DIR / "unity"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _il2cpp():
    """懒加载 il2cpp 模块(并行任务创建)。缺失时抛 ImportError。"""
    from . import il2cpp  # noqa: F401
    import importlib
    return importlib.import_module(".il2cpp", __package__)


def _metadata_path(result: dict, ctx: dict) -> str:
    """当前可用的 metadata 绝对路径(原版或解密后)。"""
    dec = (result.get("decrypt", {}) or {})
    if dec.get("decrypted_path"):
        p = Path(dec["decrypted_path"])
        if p.exists():
            return str(p)
    return _find_kind_path(result, ctx, "metadata")


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
            return str(p if p.is_absolute() else Path(ctx["target_path"]) / p)
    return ""


# ---------------------------------------------------------------- 阶段:目录扫描
def _stage_scan(ctx: dict, result: dict) -> dict:
    a = _new_analyzer(ctx)
    a.run_scan()
    a.run_detect()
    return {
        "detect": a.detect,
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
    if bt not in ("Mono", "IL2CPP"):
        a = _new_analyzer(ctx)
        det = a.run_detect()
        bt = det.get("build_type", "Other")
    return {
        "build_type": bt,
        "note": "IL2CPP: GameAssembly.dll / Data/il2cpp_data; Mono: Data/Managed/*.dll",
    }


# ---------------------------------------------------------------- 阶段:程序集/DLL分析
def _stage_assembly(ctx: dict, result: dict) -> dict:
    bt = (result.get("buildtype", {}) or {}).get("build_type", "Other")
    if bt == "Mono":
        md = _new_analyzer(ctx).managed_dir()
        if md:
            return {
                "mode": "Mono",
                "managed_assemblies": _mono.analyze_managed_dir(md),
                "api_stats": _mono.api_usage_stats(md),
            }
        return {"mode": "Mono", "managed_assemblies": [], "note": "未找到 Data/Managed"}
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
    meta = _metadata_path(result, ctx)
    if not meta or not Path(meta).exists():
        return {"encrypted": False, "ok": False, "note": "未找到 global-metadata.dat(可能为 Mono 或无 il2cpp metadata)"}
    try:
        il2cpp = _il2cpp()
    except ImportError as e:
        return {"encrypted": False, "ok": False, "note": f"il2cpp 模块尚未就绪: {e}"}

    try:
        chk = il2cpp.check_metadata_encrypted(meta)
    except Exception as e:
        return {"encrypted": False, "ok": False, "note": f"检查失败: {e}", "error": str(e)}

    encrypted = bool(chk.get("encrypted"))
    out = {
        "encrypted": encrypted,
        "ok": True,
        "metadata": meta,
        "version": chk.get("version"),
        "reason": chk.get("reason"),
        "magic": chk.get("magic"),
        "entropy": chk.get("entropy"),
        "decrypted": False,
        "method": "",
        "decrypted_path": "",
    }
    if encrypted:
        ga = _find_kind_path(result, ctx, "gameassembly")
        out_dir = _reports_unity_dir() / f"{_target_name(ctx)}_decrypted"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "global-metadata.dat"
        try:
            dr = il2cpp.decrypt_metadata(meta, gameassembly_path=ga, out_path=str(out_path))
        except Exception as e:
            return {**out, "ok": False, "note": f"解密失败: {e}", "error": str(e)}
        out.update({
            "decrypted": bool(dr.get("ok")),
            "method": dr.get("method") or "",
            "decrypted_path": dr.get("decrypted_path") or "",
            "note": dr.get("note") or "",
        })
    else:
        out["note"] = "metadata 未加密,可直接解析/SDK dump"
    return out


# ---------------------------------------------------------------- 阶段:SDK Dump
def _stage_sdk(ctx: dict, result: dict) -> dict:
    meta = _metadata_path(result, ctx)
    if not meta or not Path(meta).exists():
        return {"ok": False, "note": "无可用 metadata"}
    try:
        il2cpp = _il2cpp()
    except ImportError as e:
        return {"ok": False, "note": f"il2cpp 模块尚未就绪: {e}"}

    ga = _find_kind_path(result, ctx, "gameassembly")

    out_dir = _reports_unity_dir() / f"sdk_{_target_name(ctx)}"
    try:
        r = il2cpp.dump_sdk(meta, ga, str(out_dir))
    except Exception as e:
        log.exception("sdk dump failed")
        return {"ok": False, "note": f"SDK dump 失败: {e}", "error": str(e)}
    r["meta_path"] = meta
    r["gameassembly_path"] = ga or ""
    r["out_dir"] = str(out_dir)
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
                p = Path(ctx["target_path"]) / f["path"]
                try:
                    blob = p.read_bytes()
                except OSError:
                    blob = b""
                if blob:
                    break
        if blob:
            break
    name = _target_name(ctx)
    sample = {
        "file_name": name,
        "file_size": total,
        "sha256": _hash_svc.compute_hashes(blob)["sha256"] if blob else "",
    }
    rep = _report_svc.build_report(sample, {"unity": result})
    out = _reports_unity_dir()
    paths = _report_svc.save_report(rep, out, f"unity_{name}")
    return {"name": name, "total_size": total, "report_paths": paths}
