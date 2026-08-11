"""分析类节点:包装现有分析引擎(PE/壳/脱壳/反汇编/字符串/UE/Unity/SDK)。
每个节点读取 params(支持 {{var}} 占位符),调用既有服务,输出写变量池。
"""
from __future__ import annotations
from pathlib import Path

from ...core.config import resolve_sample_path
from ...services import pe_parser, packer, strings
from ...services.unpacker import unpack_known
from ...services.disassembler import disassemble_entry
from ...services import hash as hash_svc
from ..variables import find_in_pool
from .base import BaseNode, NodeResult, register


def _sample_path(params: dict, pool: dict = None) -> str:
    """解析样本路径:优先变量池 sample_path,再 params.sample_path / sample_id。"""
    if pool is not None:
        p = find_in_pool(pool, "sample_path")
        if p:
            return str(resolve_sample_path(p))
    p = params.get("sample_path", "")
    if p:
        return str(resolve_sample_path(p))
    sid = params.get("sample_id")
    if sid:
        from ...core.database import SessionLocal
        from ...models.sample import Sample
        db = SessionLocal()
        try:
            s = db.query(Sample).filter(Sample.id == int(sid)).first()
            return str(resolve_sample_path(s.stored_path)) if s else ""
        finally:
            db.close()
    return ""


def _pool_val(pool: dict, key: str, default=""):
    v = find_in_pool(pool, key)
    return v if v is not None else default


def _read(path: str):
    return Path(path).read_bytes() if path and Path(path).exists() else b""


@register
class PEIdentifyNode(BaseNode):
    node_type = "pe_identify"
    label = "PE 识别与静态解析"
    icon = "🔍"
    category = "分析"
    params_schema = [
        {"key": "sample_path", "label": "样本路径", "type": "text", "default": "", "required": True,
         "desc": "PE 文件路径或 {{前序节点.sample_path}}"},
    ]

    async def execute(self, ctx) -> NodeResult:
        path = _sample_path(ctx["params"], ctx["pool"])
        if not path:
            return NodeResult(status="failed", error="未提供样本路径 sample_path")
        data = _read(path)
        if not data:
            return NodeResult(status="failed", error=f"无法读取样本: {path}")
        try:
            pe_result = pe_parser.parse_pe(data, path)
            pe_result["packer"] = packer.detect_packer(pe_result, None, data)
        except Exception as e:
            return NodeResult(status="failed", error=f"PE 解析失败: {e}")
        strs = strings.extract_strings(data, min_len=6)
        hashes = hash_svc.compute_hashes(data, None)
        return NodeResult(outputs={
            "sample_path": path, "file_name": Path(path).name,
            "is_pe": pe_result.get("is_pe"), "machine": pe_result.get("machine"),
            "arch": "x64" if pe_result.get("is_64bit") else "x86",
            "entry_point": pe_result.get("entry_point"), "image_base": pe_result.get("image_base"),
            "subsystem": pe_result.get("subsystem"), "sections": pe_result.get("sections"),
            "imports": pe_result.get("imports"), "exports": pe_result.get("exports"),
            "packer": pe_result.get("packer"), "security": pe_result.get("security"),
            "hashes": hashes, "string_count": len(strs), "strings": strs[:500],
            "pe": pe_result,
        }, summary=f"PE {pe_result.get('machine','')} · {pe_result.get('subsystem','')} · 壳:{pe_result.get('packer',{}).get('verdict','')}")


@register
class PackerDetectNode(BaseNode):
    node_type = "packer_detect"
    label = "壳检测"
    icon = "📦"
    category = "分析"
    params_schema = []

    async def execute(self, ctx) -> NodeResult:
        path = _sample_path(ctx["params"], ctx["pool"])
        data = _read(path)
        if not data:
            return NodeResult(status="failed", error="无样本可检测(需先执行 pe_identify 或提供 sample_path)")
        pe_result = pe_parser.parse_pe(data, path) if data else {}
        pk = packer.detect_packer(pe_result, None, data)
        return NodeResult(outputs={"verdict": pk["verdict"], "packed": pk["packed"],
                                   "confidence": pk["confidence"], "hits": pk["hits"]},
                          summary=f"判定: {pk['verdict']} (conf {pk['confidence']}%)")


@register
class UnpackNode(BaseNode):
    node_type = "unpack"
    label = "自动脱壳(UPX 等)"
    icon = "📦"
    category = "分析"
    params_schema = [
        {"key": "out_dir", "label": "输出目录", "type": "text", "default": "", "required": False},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...core.config import config
        verdict = _pool_val(ctx["pool"], "verdict", "")
        path = _sample_path(ctx["params"], ctx["pool"])
        out = ctx["params"].get("out_dir") or str(config.UNPACKED_DIR)
        if not path:
            return NodeResult(status="failed", error="无样本路径")
        if verdict and verdict not in ("Not packed (likely)", "Packed/Protected (unknown)"):
            r = unpack_known(path, verdict, out)
            return NodeResult(outputs={"ok": r.get("ok"), "path": r.get("path", ""),
                                       "message": r.get("message", ""), "verdict": verdict},
                              summary=f"{'已脱壳' if r.get('ok') else '无需/失败'} · {verdict}")
        return NodeResult(outputs={"ok": False, "path": "", "verdict": verdict,
                                   "message": "未检测到已知壳,跳过脱壳"},
                          summary="未检测到已知壳,跳过")


@register
class DisassembleNode(BaseNode):
    node_type = "disassemble"
    label = "反汇编入口"
    icon = "🔬"
    category = "分析"
    params_schema = [
        {"key": "max_insns", "label": "指令上限", "type": "number", "default": 3000},
        {"key": "address", "label": "起始地址(VA,留空=入口)", "type": "text", "default": ""},
    ]

    async def execute(self, ctx) -> NodeResult:
        path = _sample_path(ctx["params"], ctx["pool"])
        data = _read(path)
        arch = _pool_val(ctx["pool"], "arch", "x64")
        image_base = int(_pool_val(ctx["pool"], "image_base", "0x140000000"), 16)
        ep = int(_pool_val(ctx["pool"], "entry_point", "0x0"), 16) - image_base
        addr = ctx["params"].get("address")
        if addr:
            try:
                ep = int(addr, 16) - image_base
            except ValueError:
                pass
        sections = _pool_val(ctx["pool"], "sections", [])
        dis = disassemble_entry(data, ep, image_base, arch, max_insns=int(ctx["params"].get("max_insns", 3000)),
                                sections=sections or None)
        return NodeResult(outputs={"arch": arch, "count": dis.get("count", 0),
                                   "insns": dis.get("insns", [])[:2000]},
                          summary=f"反汇编 {dis.get('count',0)} 条指令")


@register
class StringsNode(BaseNode):
    node_type = "strings"
    label = "字符串提取"
    icon = "🔤"
    category = "分析"
    params_schema = [
        {"key": "min_len", "label": "最小长度", "type": "number", "default": 6},
        {"key": "interesting_only", "label": "仅兴趣项", "type": "bool", "default": True},
    ]

    async def execute(self, ctx) -> NodeResult:
        path = _sample_path(ctx["params"], ctx["pool"])
        data = _read(path)
        alls = strings.extract_strings(data, min_len=int(ctx["params"].get("min_len", 6)))
        if ctx["params"].get("interesting_only", True):
            alls = strings.interesting_strings(alls)
        return NodeResult(outputs={"count": len(alls), "strings": alls[:800],
                                   "pdb": strings.pdb_hint(alls)},
                          summary=f"{len(alls)} 条字符串")


@register
class UEAnalyzeNode(BaseNode):
    node_type = "ue_analyze"
    label = "UE 虚幻引擎分析"
    icon = "🎮"
    category = "引擎专项"
    params_schema = [
        {"key": "version", "label": "UE 版本(留空自动识别)", "type": "text", "default": ""},
    ]

    async def execute(self, ctx) -> NodeResult:
        path = _sample_path(ctx["params"], ctx["pool"])
        if not path:
            return NodeResult(status="failed", error="无样本路径")
        from ...services.ue.analyzer import UEAnalyzer
        a = UEAnalyzer(path, version=ctx["params"].get("version", ""))
        res = a.run()
        return NodeResult(outputs={"engine_version": res.get("engine_version"),
                                   "engine_family": res.get("engine_family"),
                                   "three_majors": res.get("three_majors"),
                                   "signature_hits": res.get("signature_hits"),
                                   "reflection": res.get("reflection"),
                                   "needs_decryption": res.get("needs_decryption"),
                                   "encryption": res.get("encryption"),
                                   "decryption": res.get("decryption"),
                                   "suggestions": res.get("suggestions")},
                          summary=f"UE {res.get('engine_version') or res.get('engine_family','')} · "
                                  f"GObjects:{res.get('three_majors',{}).get('gobjects',{}).get('target_va') or '-'}")


@register
class UnityAnalyzeNode(BaseNode):
    node_type = "unity_analyze"
    label = "Unity 引擎分析(游戏目录)"
    icon = "🎮"
    category = "引擎专项"
    params_schema = [
        {"key": "target_path", "label": "游戏文件夹路径", "type": "text", "default": "", "required": True},
        {"key": "version", "label": "Unity 版本(留空自动识别)", "type": "text", "default": ""},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...services import unity as unity_mod
        target = ctx["params"].get("target_path", "")
        if not target:
            return NodeResult(status="failed", error="请提供游戏文件夹路径 target_path")
        result = {}
        uctx = {"params": {"path": target, "version": ctx["params"].get("version", "")},
                "target_path": target, "data": None, "analysis_id": 0, "workdir": Path(target)}
        for stage in unity_mod.STAGES:
            try:
                result[stage] = unity_mod.execute_stage(stage, uctx, result)
            except Exception as e:
                return NodeResult(status="failed", error=f"Unity 阶段 {stage} 失败: {e}")
        return NodeResult(outputs={"unity_version": result.get("version", {}).get("unity_version"),
                                   "build_type": result.get("buildtype", {}).get("build_type"),
                                   "metadata": result.get("assembly", {}).get("metadata"),
                                   "managed_assemblies": result.get("assembly", {}).get("managed_assemblies"),
                                   "decrypt": result.get("decrypt"), "sdk": result.get("sdk"),
                                   "resources": result.get("resource"), "result": result},
                          summary=f"Unity {result.get('version',{}).get('unity_version','')} · "
                                  f"{result.get('buildtype',{}).get('build_type','')}")


@register
class SDKDumpNode(BaseNode):
    node_type = "sdk_dump"
    label = "Unity SDK Dump"
    icon = "🛠️"
    category = "引擎专项"
    params_schema = [
        {"key": "target_path", "label": "游戏文件夹路径", "type": "text", "default": ""},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...services.unity import il2cpp
        from ...core.config import config
        target = ctx["params"].get("target_path")
        if not target:
            prev = _pool_val(ctx["pool"], "unity_analyze", {})
            prev2 = prev.get("result", {}) if isinstance(prev, dict) else {}
            target = prev2.get("target_path", "") or (prev.get("target_path") or "")
        if not target:
            return NodeResult(status="failed", error="无游戏目录(需先 unity_analyze 或提供 target_path)")
        meta = Path(target) / "Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
        ga = Path(target) / "GameAssembly.dll"
        if not meta.exists():
            return NodeResult(status="failed", error="未找到 global-metadata.dat")
        out = config.SDK_DIR / f"sdk_{Path(target).name}"
        out.mkdir(parents=True, exist_ok=True)
        r = il2cpp.dump_sdk(str(meta), str(ga), str(out))
        return NodeResult(outputs={"ok": r.get("ok"), "types": r.get("types"),
                                   "methods": r.get("methods"), "fields": r.get("fields"),
                                   "dump_cs": r.get("dump_cs"), "script_json": r.get("script_json"),
                                   "sdk_json": r.get("sdk_json"), "cpp_dir": r.get("cpp_dir")},
                          summary=f"SDK: {r.get('types',0)} 类 / {r.get('methods',0)} 方法")
