"""UE 虚幻引擎专项分析 —— 引擎阶段式工作流
供 engine_runner.EngineRunner 调用的模块契约:
  STAGES         阶段名列表(顺序执行)
  TITLES         {stage: 中文名}
  execute_stage(stage, ctx, result) -> dict  执行单阶段,返回要并入 result 的 dict
  summarize(result) -> dict                  生成精简 summary

ctx = {"params": {...}, "target_path": 样本exe路径, "sample_path": str|None,
       "data": bytes|None, "analysis_id": int, "workdir": Path}
result 为已执行阶段结果 dict(可读前序阶段输出)。
内部复用 analyzer(版本/三大件/加密)、signatures(签名扫描)、versions(版本知识库)、
source_fetcher(源码轻量拉取)。
"""
from __future__ import annotations
from pathlib import Path

from ...core.config import config
from .. import hash as _hash_svc
from .. import report as _report_svc
from . import analyzer as _analyzer
from . import signatures as _signatures
from . import source_fetcher as _source_fetcher
from . import versions as _versions

STAGES = ["version", "source", "majors", "reflection", "encryption", "report"]
TITLES = {
    "version": "版本识别",
    "source": "源码轻量拉取",
    "majors": "三大件定位",
    "reflection": "反射系统分析",
    "encryption": "加密解密",
    "report": "报告生成",
}

# 反射系统特征标记(字节)
_REFLECTION_MARKERS = [
    ("ProcessEvent", b"ProcessEvent"),
    ("GetDefaultObject", b"GetDefaultObject"),
    ("UClass", b"UClass"),
    ("UFunction", b"UFunction"),
    ("FProperty", b"FProperty"),
    ("UStruct", b"UStruct"),
    ("Serialize", b"Serialize"),
    ("UObject", b"UObject"),
]
_REFLECTION_STRUCTS = ["UObject", "UClass", "UFunction", "FProperty", "UStruct"]


# ---------------------------------------------------------------- 入口契约
def execute_stage(stage: str, ctx: dict, result: dict) -> dict:
    """执行单个阶段,返回该阶段结果 dict。EngineRunner 会 result[stage] = 返回 dict。"""
    fn = {
        "version": _stage_version,
        "source": _stage_source,
        "majors": _stage_majors,
        "reflection": _stage_reflection,
        "encryption": _stage_encryption,
        "report": _stage_report,
    }.get(stage)
    if fn is None:
        raise ValueError(f"unknown stage: {stage}")
    return fn(ctx, result)


def summarize(result: dict) -> dict:
    """精简汇总,写入 result['summary']。"""
    v = result.get("version", {}) or {}
    m = (result.get("majors", {}) or {}).get("three_majors", {}) or {}
    e = result.get("encryption", {}) or {}
    r = result.get("reflection", {}) or {}

    def _va(x):
        d = x or {}
        t = d.get("target_va")
        return hex(t) if isinstance(t, int) else (t or None)

    return {
        "engine": v.get("engine_version") or v.get("engine_family") or "未识别",
        "version": v.get("engine_version") or v.get("detected_version") or "",
        "gobjects": _va(m.get("gobjects")),
        "gnames": _va(m.get("gnames")),
        "gworld": _va(m.get("gworld")),
        "fname": v.get("fname") or "",
        "reflection_detected": bool(r.get("detected")),
        "needs_decryption": bool(e.get("needs_decryption")),
    }


# ---------------------------------------------------------------- 工具
def _get_data(ctx: dict) -> bytes:
    """ctx['data'] 优先;否则读取 target_path。"""
    data = ctx.get("data")
    if data is None:
        data = Path(ctx["target_path"]).read_bytes()
    return data


def _get_params(ctx: dict) -> dict:
    return ctx.get("params") or {}


def _new_analyzer(ctx: dict) -> "_analyzer.UEAnalyzer":
    return _analyzer.UEAnalyzer(ctx["target_path"], data=_get_data(ctx))


def _version_used(result: dict) -> str:
    v = result.get("version", {}) or {}
    return v.get("engine_version") or v.get("detected_version") or ""


# ---------------------------------------------------------------- 阶段:版本识别
def _stage_version(ctx: dict, result: dict) -> dict:
    params = _get_params(ctx)
    data = _get_data(ctx)
    ver = str(params.get("version") or "")
    a = _analyzer.UEAnalyzer(ctx["target_path"], version=ver, data=data)
    a.detect_version()
    r = a.result
    return {
        "engine_version": r["engine_version"],
        "engine_family": r["engine_family"],
        "version_method": r["version_method"],
        "fname": r["fname"],
        "fname_detail": r["fname_detail"],
        "detected_version": r["detected_version"],
        "suggestions": r["suggestions"],
    }


# ---------------------------------------------------------------- 阶段:源码轻量拉取
def _stage_source(ctx: dict, result: dict) -> dict:
    params = _get_params(ctx)
    if not params.get("fetch_source"):
        return {"skipped": True, "note": "未要求拉取源码"}
    version = _version_used(result)
    if not version:
        return {"skipped": True, "note": "未识别到精确版本,无法确定源码分支"}
    try:
        loc = _source_fetcher.fetch_version_sources(version, cache=True)
    except Exception as e:
        return {"skipped": True, "note": f"源码拉取失败: {e}"}
    try:
        hints = _source_fetcher.analyze_all_cached(version)
    except Exception:
        hints = []
    return {"skipped": False, "version": version, "sources": loc, "structure_hints": hints}


# ---------------------------------------------------------------- 阶段:三大件定位
def _stage_majors(ctx: dict, result: dict) -> dict:
    a = _new_analyzer(ctx)
    v = result.get("version", {}) or {}
    a.result["engine_version"] = v.get("engine_version") or ""
    a.result["engine_family"] = v.get("engine_family") or ""
    tm = a.locate_three_majors()
    return {
        "three_majors": tm,
        "signature_hits": a.result.get("signature_hits", []),
        "source_hints": a.result.get("source_hints", []),
    }


# ---------------------------------------------------------------- 阶段:反射系统分析
def _stage_reflection(ctx: dict, result: dict) -> dict:
    data = _get_data(ctx)
    found = {name: (raw in data) for name, raw in _REFLECTION_MARKERS}
    detected = any(found.values())
    structures = [n for n in _REFLECTION_STRUCTS if found.get(n)]
    methods = [n for n in ("ProcessEvent", "GetDefaultObject", "Serialize") if found.get(n)]
    has_uobject = found.get("UObject")
    has_core = found.get("ProcessEvent") or found.get("GetDefaultObject")
    # confused: 出现 UObject 但核心分发/取默认对象缺失 → 疑似反射混淆/精简
    confused = bool(has_uobject and not has_core)
    # uobject_vftable: 具备 UObject 对象体系且可还原 vftable 布局的标记
    uobject_vftable = bool(has_uobject and (has_core or found.get("UClass") or found.get("UFunction")))

    if not detected:
        note = "未检测到 UE 反射系统特征,可能为非 UE 引擎、被压缩/混淆或精简版反射"
    elif confused:
        note = "检测到 UObject 对象体系但缺失 ProcessEvent/GetDefaultObject,疑似反射混淆/精简,需运行时确认"
    else:
        note = f"检测到 UE 反射系统:{', '.join(structures or ['UObject'])}{' ,' if structures else ''}含 {', '.join(methods)}"

    tm = (result.get("majors", {}) or {}).get("three_majors", {}) or {}

    def _va(m):
        d = m or {}
        t = d.get("target_va")
        return hex(t) if isinstance(t, int) else (str(t) if t else "未定位")

    gobjects = _va(tm.get("gobjects"))
    gnames = _va(tm.get("gnames"))
    fname = (result.get("version", {}) or {}).get("fname") or ""

    dump_plan = [
        f"1. 附加目标进程,定位 TUObjectArray(GObjects) 基址 {gobjects}",
        "2. 解析 FChunkedFixedUObjectArray:读取 NumElements/NumChunks 决定遍历范围,按 chunk 读取 UObject 指针",
        "3. 对每个 UObject 读取 ClassPrivate 字段(结合 fname={fname or 'pool'} 验证)定位 UClass",
        "4. 由 UClass 的 ChildProperties/Children 遍历 UFunction 与 FProperty,生成函数/属性表",
        f"5. 结合 FNamePool(GNames){'(' + gnames + ')' if gnames != '未定位' else ''} 将 FName 索引解码为字符串",
        "6. 提取 UObject/AActor 等 vftable 布局,输出 DUMPER 风格 SDK 数据",
    ]
    return {
        "detected": detected,
        "uobject_vftable": uobject_vftable,
        "structures": structures,
        "markers": found,
        "confused": confused,
        "note": note,
        "dump_plan": dump_plan,
    }


# ---------------------------------------------------------------- 阶段:加密解密
def _stage_encryption(ctx: dict, result: dict) -> dict:
    a = _new_analyzer(ctx)
    v = result.get("version", {}) or {}
    a.result["engine_version"] = v.get("engine_version") or ""
    a.result["engine_family"] = v.get("engine_family") or ""
    a.result["fname"] = v.get("fname") or ""
    det = a.encryption_analysis()
    needs = bool(a.result.get("needs_decryption"))

    if needs:
        ver = v.get("engine_version") or ""
        fname = v.get("fname") or ""
        tm = (result.get("majors", {}) or {}).get("three_majors", {}) or {}
        steps = _decryption_plan(ver, fname, tm)
        decryption = {"required": True, "note": "检测到加密特征,需结合运行时数据解密", "steps": steps}
    else:
        decryption = {"required": False, "note": "未检测到加密,无需解密"}

    return {"needs_decryption": needs, "encryption": det, "decryption": decryption}


def _decryption_plan(version: str, fname: str, three_majors: dict) -> list:
    """FNamePool 等解密方案步骤。"""
    gnames = (three_majors.get("gnames") or {}).get("target_va")
    gnames_s = hex(gnames) if isinstance(gnames, int) else (gnames or "未定位")
    steps = [
        f"1. 定位 FNamePool(GNames) 基址 {gnames_s} 与 Blocks 数组",
        f"2. 解析 FNameEntry:Index 高 6 bit 为 Block 号,低 18 bit 为块内偏移(fname={fname or 'pool'})",
        "3. 若 FName::IndexToName 加速表存在,优先读取其中已解混淆的名字",
        "4. 如为字节异或/位移混淆,结合引擎版本还原密钥逐字节解码(UE5.2+ 可选加密)",
        "5. dump 全部 FName 至 JSON,供 SDK 与内存读取复用",
    ]
    return steps


# ---------------------------------------------------------------- 阶段:报告生成
def _stage_report(ctx: dict, result: dict) -> dict:
    data = _get_data(ctx)
    sample_name = Path(ctx["target_path"]).name
    sample = {
        "file_name": sample_name,
        "file_size": len(data),
        "sha256": _hash_svc.compute_hashes(data)["sha256"],
    }
    rep = _report_svc.build_report(sample, {"ue": result})
    out = config.REPORTS_DIR / "ue"
    out.mkdir(parents=True, exist_ok=True)
    paths = _report_svc.save_report(rep, out, f"ue_{sample_name}")
    return {"name": sample_name, "report_paths": paths}
