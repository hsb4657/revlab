"""分析类节点:包装现有分析引擎(PE/壳/脱壳/反汇编/字符串/UE/Unity/SDK)。
每个节点读取 params(支持 {{var}} 占位符),调用既有服务,输出写变量池。
"""
from __future__ import annotations
import json
import time
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


def _ue_report_dir(ctx: dict) -> Path:
    """Resolve the task-scoped UE report directory.

    Graph executions may provide ``output_dir`` directly (useful for API and
    test callers).  Normal graph runs derive the same stable run directory
    used by the artifact manifest and place reports under ``report``.  The
    global ``reports/ue`` directory is intentionally not used here.
    """
    params = ctx.get("params") or {}
    # Explicit node parameter may already point at ``report``; the runner's
    # ``ctx.output_dir`` is the task run root and gets the conventional child.
    param_output = params.get("output_dir")
    context_output = ctx.get("output_dir")
    explicit = param_output or context_output
    if explicit:
        candidate = Path(str(explicit)).expanduser()
        if context_output and not param_output:
            return candidate if candidate.name.lower() == "report" else candidate / "report"
        return candidate if candidate.name.lower() == "report" else candidate / "report"

    task_id = ctx.get("task_id")
    if task_id:
        try:
            from ...core.database import SessionLocal
            from ...models.sample import GraphTask, GraphWorkflow
            from ...services.artifacts import run_directory
            db = SessionLocal()
            try:
                task = db.query(GraphTask).filter(GraphTask.id == int(task_id)).first()
                workflow = db.query(GraphWorkflow).filter(
                    GraphWorkflow.id == task.workflow_id
                ).first() if task else None
                if task:
                    return run_directory(task, workflow) / "report"
            finally:
                db.close()
        except Exception:
            # Keep the node usable for lightweight/direct callers.  The
            # explicit output root fallback below is still task-independent.
            pass

    from ...core.config import config
    return config.OUTPUT_ROOT / "runs" / f"task_{task_id or 'adhoc'}" / "report"


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
                                   "confidence": pk["confidence"], "hits": pk["hits"],
                                   "families": pk.get("families", []), "strategies": pk.get("strategies", []),
                                   "known_unpacker": pk.get("known_unpacker", ""),
                                   "requires_memory_dump": pk.get("requires_memory_dump", False),
                                   "evidence_summary": pk.get("evidence_summary", {})},
                          summary=f"判定: {pk['verdict']} (conf {pk['confidence']}%)")


@register
class PEProtectionMatrixNode(BaseNode):
    node_type = "pe_protection_matrix"
    label = "PE 多壳/保护证据矩阵"
    icon = "🧰"
    category = "分析"
    params_schema = [{"key": "sample_path", "label": "样本路径", "type": "text", "default": ""}]

    async def execute(self, ctx) -> NodeResult:
        path = _sample_path(ctx["params"], ctx["pool"])
        data = _read(path)
        if not data:
            return NodeResult(status="failed", error="没有可检测的样本")
        pe = pe_parser.parse_pe(data, path)
        matrix = packer.detect_packer(pe, None, data)
        return NodeResult(
            outputs={
                "verdict": matrix.get("verdict"), "packed": matrix.get("packed"),
                "confidence": matrix.get("confidence", 0), "hits": matrix.get("hits", []),
                "families": matrix.get("families", []), "strategies": matrix.get("strategies", []),
                "known_unpacker": matrix.get("known_unpacker", ""),
                "requires_memory_dump": matrix.get("requires_memory_dump", False),
                "evidence_summary": matrix.get("evidence_summary", {}),
                "branch_contract": {
                    "known_unpacker": "known_unpacker",
                    "memory_dump": "memory_dump",
                    "manual_review": "manual_review",
                },
            },
            summary=f"保护矩阵: {matrix.get('verdict', 'unknown')} · {len(matrix.get('strategies', []))} 条策略",
        )


@register
class PEUnpackStrategyNode(BaseNode):
    node_type = "pe_unpack_strategy"
    label = "PE 脱壳策略分派"
    icon = "🧭"
    category = "分析"
    params_schema = [{"key": "sample_path", "label": "样本路径", "type": "text", "default": ""}]

    async def execute(self, ctx) -> NodeResult:
        matrix = _pool_val(ctx["pool"], "pe_protection_matrix", {})
        if not isinstance(matrix, dict) or not matrix:
            matrix = _pool_val(ctx["pool"], "packer_detect", {})
        strategies = list(matrix.get("strategies") or []) if isinstance(matrix, dict) else []
        applicable = [item for item in strategies if item.get("applicable")]
        known = matrix.get("known_unpacker", "") if isinstance(matrix, dict) else ""
        selected = "known_unpacker" if known else ("memory_dump" if applicable else "manual_review")
        return NodeResult(
            outputs={"selected_strategy": selected, "known_unpacker": known,
                     "strategies": strategies, "requires_approval": selected in {"memory_dump", "manual_review"},
                     "reason": next((item.get("reason", "") for item in strategies if item.get("id") == selected), "")},
            summary=f"脱壳策略: {selected}",
        )


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
        out = ctx["params"].get("out_dir")
        if not out and ctx.get("output_dir"):
            out = str(Path(ctx["output_dir"]) / "unpacked")
        out = out or str(config.UNPACKED_DIR)
        if not path:
            return NodeResult(status="failed", error="无样本路径")
        if verdict and verdict not in ("Not packed (likely)", "Packed/Protected (unknown)"):
            r = unpack_known(path, verdict, out)
            unpacked_path = r.get("path", "")
            verified = False
            hashes = {}
            if r.get("ok") and unpacked_path:
                unpacked_data = _read(unpacked_path)
                parsed = pe_parser.parse_pe(unpacked_data, unpacked_path) if unpacked_data else {}
                verified = bool(parsed.get("is_pe"))
                hashes = hash_svc.compute_hashes(unpacked_data, None) if verified else {}
            return NodeResult(status="success" if (not r.get("ok") or verified) else "failed",
                              outputs={"ok": bool(r.get("ok") and verified), "path": unpacked_path,
                                       "verified": verified, "hashes": hashes,
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
class DecompileNode(BaseNode):
    node_type = "decompile"
    label = "Ghidra 反编译"
    icon = "🧩"
    category = "分析"
    params_schema = [
        {"key": "max_functions", "label": "函数上限", "type": "number", "default": 200},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...core.config import config
        from ...services.ghidra_bridge import decompile_with_ghidra, ghidra_available, load_decompile

        path = _sample_path(ctx["params"], ctx["pool"])
        if not path:
            return NodeResult(status="failed", error="无样本路径")
        if not config.ENABLE_GHIDRA or not ghidra_available():
            return NodeResult(outputs={"ok": False, "available": False, "functions": []},
                              summary="Ghidra 未配置，记录为能力缺失")
        output_root = ctx.get("output_dir")
        if output_root:
            out_json = Path(str(output_root)) / "decompile" / f"{Path(path).stem}_decompile.json"
        else:
            out_json = config.GHIDRA_DIR / "decomp" / f"wf_{ctx['task_id']}_{Path(path).stem}.json"
        out_json.parent.mkdir(parents=True, exist_ok=True)
        result = decompile_with_ghidra(path, str(out_json))
        if not result.get("ok"):
            return NodeResult(status="failed", error=result.get("message", "Ghidra 执行失败"))
        functions = load_decompile(str(out_json))
        limit = int(ctx["params"].get("max_functions", 200))
        rows = [{"address": address, "name": item.get("name"),
                 "signature": item.get("signature"), "c": item.get("c", "")[:4000]}
                for address, item in functions.items()][:limit]
        return NodeResult(outputs={"ok": True, "available": True, "path": str(out_json),
                                   "function_count": len(functions), "functions": rows},
                          summary=f"Ghidra 导出 {len(functions)} 个函数")


@register
class DynamicAnalyzeNode(BaseNode):
    node_type = "dynamic_analyze"
    label = "动态行为分析"
    icon = "▶"
    category = "动态"
    params_schema = [
        {"key": "timeout", "label": "运行超时(秒)", "type": "number", "default": 60},
        {"key": "capture_network", "label": "抓取宿主网络会话", "type": "bool", "default": True},
        {"key": "capture_memory_dump", "label": "启动后进行 PE-sieve 转储", "type": "bool", "default": False},
        {"key": "dump_delay_seconds", "label": "转储前等待秒数", "type": "number", "default": 2},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...core.config import config
        from ...services import sandbox

        if not config.USE_SANDBOX_VM and not config.ALLOW_HOST_EXECUTION:
            return NodeResult(
                outputs={
                    "executed": False,
                    "execution_status": "blocked_by_policy",
                    "network": {"ok": False, "error": "host execution disabled"},
                },
                summary="动态执行被本机安全策略阻止",
            )
        path = _sample_path(ctx["params"], ctx["pool"])
        if not path:
            return NodeResult(status="failed", error="无样本路径")
        timeout = int(ctx["params"].get("timeout", 60))
        runner = sandbox.create_sandbox()
        if isinstance(runner, sandbox.VMSandbox):
            capture_dir = Path(ctx.get("output_dir") or config.OUTPUT_ROOT) / "captures"
            result = runner.run_and_capture(path, str(capture_dir),
                                            config.SANDBOX_RUN_ARGS, timeout)
            return NodeResult(status="success" if result.get("ok") else "failed",
                              outputs={"runner": "vmware", "result": result},
                              summary="VMware 动态分析完成",
                              error=result.get("error", ""))
        capture_dir = Path(ctx.get("output_dir") or config.OUTPUT_ROOT) / "captures"
        capture_dir.mkdir(parents=True, exist_ok=True)
        task_label = str(ctx.get("task_id") or "adhoc")
        monitor = sandbox.BehaviorMonitor(watch_dirs=[str(Path(path).parent), str(capture_dir)])
        runner = sandbox.LocalSandbox(timeout=timeout, monitor=monitor)
        capture = None
        if ctx["params"].get("capture_network", True):
            from ...services import pcap
            capture = pcap.start_capture_session(str(capture_dir / f"task_{task_label}.pcap"))

        def _dump_after_start(pid: int) -> dict:
            if not ctx["params"].get("capture_memory_dump", False):
                return {"ok": True, "status": "not_requested"}
            from ...services import unpacker
            delay = min(30, max(0, int(ctx["params"].get("dump_delay_seconds", 2) or 0)))
            if delay:
                time.sleep(delay)
            return unpacker.dump_with_pesieve(pid, str(capture_dir / "memory_dump"), label=f"task_{task_label}")

        result = runner.run(path, config.SANDBOX_RUN_ARGS, on_started=_dump_after_start)
        network = {"ok": False, "error": "not_requested"}
        if capture:
            network = pcap.finish_capture_session(capture)
        return NodeResult(status="success" if result.get("ok") else "failed",
                          outputs={"runner": "local", "executed": True, "result": result,
                                   "network": network,
                                   "memory_dump": result.get("startup_observer", {})},
                          summary=f"动态分析运行 {result.get('ran_seconds', 0)} 秒",
                          error=result.get("error", ""))


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
        return NodeResult(outputs={"sample_path": path, "_analysis": res,
                                   "engine_version": res.get("engine_version"),
                                   "engine_family": res.get("engine_family"),
                                   "three_majors": res.get("three_majors"),
                                   "major_candidates": res.get("major_candidates"),
                                   "signature_hits": res.get("signature_hits"),
                                   "fname_analysis": res.get("fname_analysis"),
                                   "reflection": res.get("reflection"),
                                   "layout_profiles": res.get("layout_profiles"),
                                   "get_name_xor": res.get("get_name_xor"),
                                   "plaintext_candidates": res.get("plaintext_candidates"),
                                   "needs_decryption": res.get("needs_decryption"),
                                   "encryption": res.get("encryption"),
                                   "decryption": res.get("decryption"),
                                   "decryption_plan": {
                                       "required": bool(res.get("needs_decryption")),
                                       "status": "待处理" if res.get("needs_decryption") else "无需处理",
                                       "signals": [x.get("name") for x in (res.get("encryption") or [])],
                                       "next_step": "提供对应版本运行时/内存 dump 后执行解密校验" if res.get("needs_decryption") else "可直接进入 SDK/反射读取",
                                   },
                                   "suggestions": res.get("suggestions")},
                          summary=f"UE {res.get('engine_version') or res.get('engine_family','')} · "
                                  f"GObjects:{res.get('three_majors',{}).get('gobjects',{}).get('target_va') or '-'}")


def _ue_analysis(ctx) -> tuple[dict | None, str, str]:
    """Reuse the first UE analysis in a graph instead of rescanning the dump."""
    pool = ctx.get("pool") or {}
    for key in ("ue_version", "ue_static_evidence", "ue_globals", "ue_fname", "ue_getname_xor", "ue_reflection", "ue_protection", "ue_encryption", "ue_analyze"):
        cached = pool.get(key)
        if isinstance(cached, dict) and isinstance(cached.get("_analysis"), dict):
            return cached["_analysis"], str(cached.get("sample_path") or ""), ""
    path = _sample_path(ctx["params"], pool)
    if not path:
        return None, "", "无样本路径"
    try:
        from ...services.ue.analyzer import UEAnalyzer
        result = UEAnalyzer(path, version=str(ctx["params"].get("version") or "")).run()
        return result, path, ""
    except Exception as exc:
        return None, path, f"UE 分析失败: {exc}"


def _ue_result(ctx, output: dict, summary: str) -> NodeResult:
    result, path, error = _ue_analysis(ctx)
    if error:
        return NodeResult(status="failed", error=error)
    output = dict(output)
    output.update({"sample_path": path, "_analysis": result})
    return NodeResult(outputs=output, summary=summary)


@register
class UEVersionNode(BaseNode):
    node_type = "ue_version"
    label = "UE 版本与引擎家族"
    icon = "🏷"
    category = "引擎专项"
    params_schema = [
        {"key": "sample_path", "label": "Dump 后的 EXE 路径", "type": "text", "default": ""},
        {"key": "version", "label": "指定版本(留空自动识别)", "type": "text", "default": ""},
    ]

    async def execute(self, ctx) -> NodeResult:
        result, path, error = _ue_analysis(ctx)
        if error:
            return NodeResult(status="failed", error=error)
        return NodeResult(
            outputs={
                "sample_path": path, "_analysis": result,
                "engine_version": result.get("engine_version"),
                "engine_family": result.get("engine_family"),
                "detected_version": result.get("detected_version"),
                "version_method": result.get("version_method"),
                "fname_model": result.get("fname"),
                "fname_detail": result.get("fname_detail"),
                "version_layout": result.get("version_layout"),
                "evidence": result.get("suggestions", []),
            },
            summary=f"UE {result.get('engine_version') or result.get('engine_family') or '版本未确认'} · {result.get('version_method') or 'static'}",
        )


@register
class UEGlobalsNode(BaseNode):
    node_type = "ue_globals"
    label = "UE 三大件与全局候选"
    icon = "◎"
    category = "引擎专项"
    params_schema = [{"key": "sample_path", "label": "Dump 后的 EXE 路径", "type": "text", "default": ""}]

    async def execute(self, ctx) -> NodeResult:
        result, _, error = _ue_analysis(ctx)
        if error:
            return NodeResult(status="failed", error=error)
        majors = result.get("three_majors") or {}
        return _ue_result(
            ctx,
            {
                "gobjects": majors.get("gobjects"), "gnames": majors.get("gnames"),
                "gworld": majors.get("gworld"), "gengine": majors.get("gengine"),
                "three_majors": majors, "major_candidates": result.get("major_candidates", {}),
                "plaintext_candidates": result.get("plaintext_candidates", {}),
                "version_layout": result.get("version_layout"),
                "validation_state": {k: (v or {}).get("validation_state", "unconfirmed") for k, v in majors.items()},
            },
            "GObjects/GNames/GWorld/GEngine 静态候选已分离，等待运行时验证",
        )


@register
class UEStaticEvidenceNode(BaseNode):
    node_type = "ue_static_evidence"
    label = "UE 字符串引用与全局候选扫描"
    icon = "🧭"
    category = "引擎专项"
    params_schema = [{"key": "sample_path", "label": "Dump 后的 EXE 路径", "type": "text", "default": ""}]

    async def execute(self, ctx) -> NodeResult:
        result, _, error = _ue_analysis(ctx)
        if error:
            return NodeResult(status="failed", error=error)
        evidence = result.get("static_evidence") or {}
        globals_ = evidence.get("global_candidates") or {}
        plaintext_candidates = {
            key: [
                {
                    "kind": "name" if key == "gnames" else "pointer",
                    "address": item.get("target_va"),
                    "status": item.get("validation_state", "candidate"),
                    "validation_state": item.get("validation_state", "candidate"),
                    "decoded_names": [],
                    "reason": "Static RIP-relative candidate; runtime memory/name decoding is still required.",
                }
                for item in (values or [])
                if isinstance(item, dict)
            ]
            for key, values in globals_.items()
        }
        return _ue_result(
            ctx,
            {
                "engine_family_guess": evidence.get("engine_family_guess", "unknown"),
                "marker_hits": evidence.get("marker_hits", {}),
                "known_name_evidence": evidence.get("known_name_evidence", {}),
                "reflection_entry_evidence": evidence.get("reflection_entry_evidence", {}),
                "rip_relative_count": (evidence.get("rip_relative_globals") or {}).get("count", 0),
                 "global_candidates": globals_,
                 "plaintext_candidates": plaintext_candidates,
                 "selected_globals": evidence.get("selected_globals", {}),
                "static_only": True,
                "limitations": evidence.get("limitations", []),
            },
            f"静态字符串/RIP 扫描完成：{(evidence.get('rip_relative_globals') or {}).get('count', 0)} 个全局访问候选",
        )


@register
class UEFNameNode(BaseNode):
    node_type = "ue_fname"
    label = "FName / GNames 算法候选"
    icon = "N"
    category = "引擎专项"
    params_schema = [{"key": "sample_path", "label": "Dump 后的 EXE 路径", "type": "text", "default": ""}]

    async def execute(self, ctx) -> NodeResult:
        result, _, error = _ue_analysis(ctx)
        if error:
            return NodeResult(status="failed", error=error)
        fname = result.get("fname_analysis") or {}
        return _ue_result(
            ctx,
            {"model": fname.get("model"), "algorithm": fname.get("algorithm"),
             "algorithm_candidates": fname.get("algorithm_candidates", []),
             "entry_layout_candidates": fname.get("entry_layout_candidates", []),
             "gnames": fname.get("gnames"), "validation_state": fname.get("validation_state"),
             "version_layout": fname.get("version_layout") or result.get("version_layout"),
             "encryption_signals": fname.get("encryption_signals"),
             "get_name_xor": fname.get("get_name_xor", {}),
             "plaintext_candidates": (result.get("plaintext_candidates") or {}).get("gnames", []),
             "validation_plan": fname.get("validation_plan", [])},
            f"FName 模型 {fname.get('model') or 'unknown'} · {fname.get('validation_state', 'unconfirmed')}",
        )


@register
class UEGetNameXorNode(BaseNode):
    node_type = "ue_getname_xor"
    label = "GetName XOR / 明文候选"
    icon = "X"
    category = "引擎专项"
    params_schema = [{"key": "sample_path", "label": "Dump 后的 EXE 路径", "type": "text", "default": ""}]

    async def execute(self, ctx) -> NodeResult:
        result, _, error = _ue_analysis(ctx)
        if error:
            return NodeResult(status="failed", error=error)
        fname = result.get("fname_analysis") or {}
        evidence = fname.get("get_name_xor") or result.get("get_name_xor") or {}
        return _ue_result(
            ctx,
            {
                "status": evidence.get("status", "unconfirmed"),
                "validation_state": evidence.get("validation_state", "unconfirmed"),
                "function_markers": evidence.get("function_markers", []),
                "xor_candidates": evidence.get("xor_candidates", []),
                "key_candidates": evidence.get("key_candidates", []),
                "plaintext_candidates": evidence.get("plaintext_candidates", []),
                "evidence": evidence.get("evidence", []),
                "runtime_validation_required": True,
                "validation_plan": evidence.get("validation_plan", []),
            },
            f"GetName XOR 候选 {len(evidence.get('xor_candidates') or [])} 项 / {evidence.get('status', 'unconfirmed')}",
        )


@register
class UEReflectionNode(BaseNode):
    node_type = "ue_reflection"
    label = "反射结构与字段偏移候选"
    icon = "⌗"
    category = "引擎专项"
    params_schema = [{"key": "sample_path", "label": "Dump 后的 EXE 路径", "type": "text", "default": ""}]

    async def execute(self, ctx) -> NodeResult:
        result, _, error = _ue_analysis(ctx)
        if error:
            return NodeResult(status="failed", error=error)
        reflection = result.get("reflection") or {}
        return _ue_result(
            ctx,
            {"detected": reflection.get("detected"), "markers": reflection.get("markers"),
             "selected_profile": reflection.get("selected_profile"),
             "profile_candidates": reflection.get("profile_candidates", []),
             "structures": reflection.get("structures", {}),
             "field_offset_candidates": reflection.get("field_offset_candidates", []),
             "gnames_dependency": reflection.get("gnames_dependency"),
             "validation_state": reflection.get("validation_state", "unconfirmed"),
             "validation_plan": reflection.get("validation_plan", [])},
            f"反射结构 {len(reflection.get('field_offset_candidates') or [])} 个字段候选 · {reflection.get('validation_state', 'unconfirmed')}",
        )


@register
class UEProtectionNode(BaseNode):
    node_type = "ue_protection"
    label = "UE 壳与保护信号"
    icon = "⛨"
    category = "引擎专项"
    params_schema = [{"key": "sample_path", "label": "Dump 后的 EXE 路径", "type": "text", "default": ""}]

    async def execute(self, ctx) -> NodeResult:
        result, _, error = _ue_analysis(ctx)
        if error:
            return NodeResult(status="failed", error=error)
        signals = result.get("encryption") or []
        return _ue_result(
            ctx,
            {"signals": signals, "signal_count": len(signals), "needs_decryption": bool(result.get("needs_decryption")),
             "packed": any(item.get("name") in {"PackedSections", "UPX", "ASPack", "VMProtect", "MPRESS", "Themida"} for item in signals if isinstance(item, dict)),
             "evidence": result.get("suggestions", [])},
            f"保护/加密信号 {len(signals)} 项 · {'需要后续验证' if result.get('needs_decryption') else '未发现明确解密要求'}",
        )


@register
class UEEncryptionNode(BaseNode):
    node_type = "ue_encryption"
    label = "UE 加密与解密证据"
    icon = "🔐"
    category = "引擎专项"
    params_schema = [{"key": "sample_path", "label": "Dump 后的 EXE 路径", "type": "text", "default": ""}]

    async def execute(self, ctx) -> NodeResult:
        result, _, error = _ue_analysis(ctx)
        if error:
            return NodeResult(status="failed", error=error)
        dec = result.get("decryption") or {}
        return _ue_result(
            ctx,
            {"needs_decryption": bool(result.get("needs_decryption")), "encryption": result.get("encryption", []),
             "decryption": dec, "status": dec.get("status", "unconfirmed"),
             "runtime_evidence_required": True, "validation_plan": dec.get("validation_plan", [])},
            f"解密状态: {dec.get('status', 'unconfirmed')}",
        )


@register
class UERuntimeValidationNode(BaseNode):
    node_type = "ue_runtime_validation"
    label = "UE 运行时证据验证清单"
    icon = "✓"
    category = "引擎专项"
    params_schema = [{"key": "sample_path", "label": "Dump 后的 EXE 路径", "type": "text", "default": ""}]

    async def execute(self, ctx) -> NodeResult:
        result, _, error = _ue_analysis(ctx)
        if error:
            return NodeResult(status="failed", error=error)
        fname = result.get("fname_analysis") or {}
        reflection = result.get("reflection") or {}
        checks = list((result.get("decryption") or {}).get("validation_plan") or [])
        checks.extend(reflection.get("validation_plan") or [])
        checks.extend(fname.get("validation_plan") or [])
        checks = list(dict.fromkeys(checks))
        runtime = result.get("runtime_validation") or {}
        evidence_status = runtime.get("evidence_status", "not_collected")
        node_status = "runtime_evidence_provided" if evidence_status == "provided" else "awaiting_runtime_evidence"
        return _ue_result(
            ctx,
            {"status": node_status, "required": True,
             "analysis_mode": runtime.get("analysis_mode", "static_dump_only"),
             "execution_available": bool(runtime.get("execution_available", False)),
             "requires_runtime_execution": bool(runtime.get("requires_runtime_execution", True)),
             "evidence_status": evidence_status,
             "evidence_source": runtime.get("evidence_source", "none"),
             "reason": runtime.get("reason", "Dump 只能提供静态证据，未执行目标进程"),
             "static_limitations": runtime.get("static_limitations", []),
             "collection_plan": runtime.get("collection_plan", []),
             "checks": checks, "gobjects": (result.get("three_majors") or {}).get("gobjects"),
             "gnames": (result.get("three_majors") or {}).get("gnames"),
             "reflection_state": reflection.get("validation_state", "unconfirmed"),
             "fname_state": fname.get("validation_state", "unconfirmed")},
            f"Dump 仅静态，运行时证据未采集: {len(checks)} 项校验清单",
        )


@register
class UEReportNode(BaseNode):
    node_type = "ue_report"
    label = "UE 结构化证据报告"
    icon = "📄"
    category = "输出"
    params_schema = [
        {"key": "title", "label": "报告标题", "type": "text", "default": "UE 专项分析报告"},
        {"key": "sample_path", "label": "Dump 后的 EXE 路径", "type": "text", "default": ""},
        {"key": "output_dir", "label": "任务输出目录(可选)", "type": "text", "default": "",
         "desc": "默认使用 runs/<task>/report；可传入任务级 output_dir"},
    ]

    async def execute(self, ctx) -> NodeResult:
        result, path, error = _ue_analysis(ctx)
        if error:
            return NodeResult(status="failed", error=error)
        from ...services import report as report_svc

        source = Path(path)
        sample = {
            "file_name": source.name,
            "file_size": source.stat().st_size if source.exists() else 0,
        }
        hashes = _pool_val(ctx.get("pool") or {}, "hashes", {})
        if isinstance(hashes, dict):
            sample.update({key: hashes.get(key, "") for key in ("sha256", "md5")})
        pool = ctx.get("pool") or {}
        pe = _pool_val(pool, "pe", {})
        extracted_strings = _pool_val(pool, "strings", [])

        # 合并画布上 UE AI 辅助节点(ue_ai_assist)的结论进报告
        ai_assist = _pool_val(pool, "ue_ai_assist", {})
        if isinstance(ai_assist, dict) and ai_assist.get("ai_output"):
            result = dict(result)
            result["ai_assist"] = ai_assist

        report = report_svc.build_report(
            sample,
            {
                "pe": pe if isinstance(pe, dict) else {},
                "strings": extracted_strings if isinstance(extracted_strings, list) else [],
                "ue": result,
                "workflow": {
                    "task_id": ctx.get("task_id"),
                    "title": ctx["params"].get("title", "UE 专项分析报告"),
                    "runtime_evidence_required": True,
                    "analysis_mode": result.get("analysis_mode", "static_dump_only"),
                    "runtime_validation": result.get("runtime_validation", {}),
                },
            },
        )
        out_dir = _ue_report_dir(ctx)
        # The sample basename is the report stem; task identity lives in the
        # surrounding run directory and manifest rather than replacing it.
        paths = report_svc.save_report(report, out_dir, source.name)

        # The UE workflow's user-facing deliverable is the sample-named
        # Markdown at the run root.  Do not mark the report node successful if
        # only the nested HTML/JSON bundle exists.
        root_markdown = Path(str(paths.get("root_markdown") or ""))
        if not root_markdown.is_file():
            return NodeResult(
                status="failed",
                error=("UE report delivery failed: the run-root Markdown was "
                       f"not created under {out_dir.parent}"),
            )

        # Persist a small execution log beside JSON/HTML/MD.  It is a normal
        # task artifact and gives the UI a durable record of the report node's
        # input, output directory, and static/runtime evidence boundary.
        log_path = out_dir / f"{report_svc.analysis_report_name(source.name, 'ue')}.log"
        log_path.write_text(
            json.dumps({
                "task_id": ctx.get("task_id"),
                "sample": source.name,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "output_dir": str(out_dir),
                "report_paths": paths,
                "analysis_mode": result.get("analysis_mode", "static_dump_only"),
                "runtime_evidence_status": result.get("runtime_evidence_status", "not_collected"),
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        paths["log"] = str(log_path)
        paths["report_dir"] = str(out_dir)
        return NodeResult(
            outputs={"report_paths": paths, "analysis_json": paths.get("json", ""),
                     "root_markdown": str(root_markdown),
                     "report_dir": str(out_dir), "log_path": str(log_path),
                     "runtime_evidence_required": True,
                     "analysis_mode": result.get("analysis_mode", "static_dump_only"),
                     "runtime_evidence_status": result.get("runtime_evidence_status", "not_collected"),
                     "runtime_execution_available": bool(result.get("runtime_execution_available", False)),
                     "runtime_validation": result.get("runtime_validation", {}),
                     "three_majors": result.get("three_majors", {})},
            summary=f"UE 结构化报告已生成: {paths.get('html', '')}",
        )


@register
class UEDeliveryGateNode(BaseNode):
    """Fail closed unless the complete UE report bundle was delivered."""

    node_type = "ue_delivery_gate"
    label = "UE 报告最终交付门禁"
    icon = "✓"
    category = "输出"
    params_schema = []

    async def execute(self, ctx) -> NodeResult:
        report = _pool_val(ctx.get("pool") or {}, "report", {})
        report = report if isinstance(report, dict) else {}
        paths = report.get("report_paths") or {}
        paths = paths if isinstance(paths, dict) else {}

        expected = {
            "root_markdown": report.get("root_markdown") or paths.get("root_markdown", ""),
            "markdown": paths.get("markdown", ""),
            "html": paths.get("html", ""),
            "json": paths.get("json", ""),
            "log": report.get("log_path") or paths.get("log", ""),
        }
        required_suffixes = {
            "root_markdown": ".md",
            "markdown": ".md",
            "html": ".html",
            "json": ".json",
            "log": ".log",
        }
        delivered = {
            key: bool(value and Path(str(value)).is_file()
                      and Path(str(value)).suffix.lower() == required_suffixes[key])
            for key, value in expected.items()
        }

        root_path = Path(str(expected["root_markdown"])) if expected["root_markdown"] else None
        nested_path = Path(str(expected["markdown"])) if expected["markdown"] else None
        delivered["root_location"] = bool(
            root_path and nested_path
            and delivered["root_markdown"] and delivered["markdown"]
            and root_path.parent == nested_path.parent.parent
        )

        missing = [key for key, ok in delivered.items() if not ok]
        outputs = {
            "delivery_complete": not missing,
            "required": delivered,
            "missing": missing,
            "report_paths": expected,
            "root_markdown": expected["root_markdown"],
        }
        if missing:
            return NodeResult(
                status="failed",
                outputs=outputs,
                error="UE report delivery incomplete; missing or invalid: " + ", ".join(missing),
            )
        return NodeResult(
            outputs=outputs,
            summary=f"UE 报告交付已验证: {expected['root_markdown']}",
        )


def _unity_target(ctx, *preferred_nodes: str) -> str:
    target = str(ctx["params"].get("target_path") or "")
    if target:
        return target
    for node_name in preferred_nodes:
        previous = _pool_val(ctx["pool"], node_name, {})
        if isinstance(previous, dict) and previous.get("target_path"):
            return str(previous["target_path"])
    found = _pool_val(ctx["pool"], "target_path", "")
    return str(found or "")


def _run_unity_stages(target: str, version: str, stages: tuple[str, ...], output_dir=None,
                      analysis_id: int = 0) -> dict:
    from ...services import unity as unity_mod

    result = {}
    uctx = {
        "params": {"path": target, "version": version},
        "target_path": target,
        "data": None,
        "analysis_id": 0,
        "workdir": Path(target),
        "output_dir": output_dir,
    }
    uctx["analysis_id"] = analysis_id
    for stage in stages:
        result[stage] = unity_mod.execute_stage(stage, uctx, result)
    return result


@register
class UnityScanNode(BaseNode):
    node_type = "unity_scan"
    label = "Unity 目录与构建识别"
    icon = "🔎"
    category = "引擎专项"
    params_schema = [
        {"key": "target_path", "label": "游戏文件夹路径", "type": "text", "default": "", "required": True},
        {"key": "version", "label": "Unity 版本(留空自动识别)", "type": "text", "default": ""},
    ]

    async def execute(self, ctx) -> NodeResult:
        target = _unity_target(ctx)
        if not target:
            return NodeResult(status="failed", error="请提供游戏文件夹路径 target_path")
        try:
            result = _run_unity_stages(
                target, str(ctx["params"].get("version") or ""),
                ("scan", "version", "buildtype"), ctx.get("output_dir"), ctx.get("task_id", 0),
            )
        except Exception as e:
            return NodeResult(status="failed", error=f"Unity 目录/构建识别失败: {e}")
        detect = (result.get("scan", {}) or {}).get("detect", {}) or {}
        build = result.get("buildtype", {}) or {}
        outputs = {
            "target_path": target,
            "unity_version": (result.get("version", {}) or {}).get("version", ""),
            "build_type": build.get("build_type", "Other"),
            "build_confidence": build.get("confidence", "none"),
            "build_evidence": build.get("evidence", {}),
            "mixed_layout": bool(build.get("mixed_layout")),
            "key_files": detect.get("key_files", []),
            "metadata_detected": any(item.get("kind") == "metadata" for item in detect.get("key_files", [])),
            "gameassembly_detected": any(item.get("kind") == "gameassembly" for item in detect.get("key_files", [])),
            "result": result,
        }
        return NodeResult(
            outputs=outputs,
            summary=(f"Unity {outputs['unity_version'] or '版本未知'} · "
                     f"{outputs['build_type']} ({outputs['build_confidence']})"),
        )


@register
class UnityAssemblyNode(BaseNode):
    node_type = "unity_assembly"
    label = "Unity 程序集与关键文件"
    icon = "🧱"
    category = "引擎专项"
    params_schema = [
        {"key": "target_path", "label": "游戏文件夹路径", "type": "text", "default": ""},
        {"key": "version", "label": "Unity 版本(留空自动识别)", "type": "text", "default": ""},
    ]

    async def execute(self, ctx) -> NodeResult:
        target = _unity_target(ctx, "unity_scan", "unity_analyze")
        if not target:
            return NodeResult(status="failed", error="无游戏目录(需先执行 Unity 目录识别或提供 target_path)")
        try:
            result = _run_unity_stages(
                target, str(ctx["params"].get("version") or ""),
                ("scan", "version", "buildtype", "assembly"), ctx.get("output_dir"), ctx.get("task_id", 0),
            )
        except Exception as e:
            return NodeResult(status="failed", error=f"Unity 程序集分析失败: {e}")
        assembly = result.get("assembly", {}) or {}
        build = result.get("buildtype", {}) or {}
        game_assembly = assembly.get("game_assembly", {}) or {}
        outputs = {
            "target_path": target,
            "unity_version": (result.get("version", {}) or {}).get("version", ""),
            "build_type": build.get("build_type", "Other"),
            "build_evidence": build.get("evidence", {}),
            "mode": assembly.get("mode", build.get("build_type", "Other")),
            "gameassembly_path": assembly.get("gameassembly_path") or game_assembly.get("path", ""),
            "gameassembly": game_assembly,
            "metadata_path": assembly.get("metadata_path", ""),
            "metadata": assembly.get("metadata", {}),
            "metadata_status": assembly.get("metadata_status", {}),
            "managed_dir": assembly.get("managed_dir", ""),
            "managed_assemblies": assembly.get("managed_assemblies", []),
            "api_stats": assembly.get("api_stats", {}),
            "result": result,
        }
        return NodeResult(
            outputs=outputs,
            summary=(f"{outputs['mode']} · GameAssembly:"
                     f"{'已定位' if outputs['gameassembly_path'] else '未定位'} · "
                     f"Metadata:{'已定位' if outputs['metadata_path'] else '未定位'}"),
        )


@register
class UnityMetadataCandidatesNode(BaseNode):
    node_type = "unity_metadata_candidates"
    label = "Metadata 候选与分片扫描"
    icon = "🔎"
    category = "引擎专项"
    params_schema = [
        {"key": "target_path", "label": "游戏文件夹路径", "type": "text", "default": ""},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...services.unity import detector

        target = _unity_target(ctx, "unity_assembly", "unity_scan")
        if not target:
            return NodeResult(status="failed", error="无游戏目录，无法扫描 Metadata 候选")
        try:
            candidates = detector.scan_metadata_candidates(target)
        except Exception as exc:
            return NodeResult(status="failed", error=f"Metadata 候选扫描失败: {exc}")
        items = candidates.get("candidates", []) or []
        return NodeResult(
            outputs={
                "target_path": target,
                "status": candidates.get("status", "metadata_missing"),
                "candidate_count": len(items),
                "candidates": items,
                "metadata_candidates": candidates,
                "has_verified_plaintext": bool(candidates.get("verified_plaintext")),
                "needs_recovery": candidates.get("status") != "metadata_plaintext_verified",
            },
            summary=(f"Metadata 候选: {len(items)} · "
                     f"{candidates.get('status', 'metadata_missing')}")
        )


@register
class UnityLoaderAnalysisNode(BaseNode):
    node_type = "unity_loader_analysis"
    label = "Loader 与解密链定位"
    icon = "🧭"
    category = "引擎专项"
    params_schema = [
        {"key": "target_path", "label": "游戏文件夹路径", "type": "text", "default": ""},
    ]

    async def execute(self, ctx) -> NodeResult:
        target = _unity_target(ctx, "unity_metadata_candidates", "unity_assembly", "unity_scan")
        if not target:
            return NodeResult(status="failed", error="无游戏目录，无法定位 Loader")
        assembly = _pool_val(ctx.get("pool") or {}, "unity_assembly", {})
        assembly_result = (assembly.get("result", {}) or {}).get("assembly", {}) if isinstance(assembly, dict) else {}
        hints = assembly_result.get("gameassembly_metadata_hints", {}) or {}
        root = Path(target)
        dll_list = root / "dlllist.txt"
        preload_modules = []
        if dll_list.is_file():
            preload_modules = [line.strip() for line in dll_list.read_text(
                encoding="utf-8", errors="replace").splitlines() if line.strip()]
        protected_modules = []
        for name in preload_modules:
            candidate = root / name
            if candidate.is_file():
                protected_modules.append({"name": name, "path": str(candidate), "size": candidate.stat().st_size})
        candidates = _pool_val(ctx.get("pool") or {}, "unity_metadata_candidates", {})
        candidate_count = int((candidates or {}).get("candidate_count", 0)) if isinstance(candidates, dict) else 0
        strategy = "verified_plaintext"
        if candidate_count:
            strategy = "static_loader_recovery_then_runtime_trace_if_required"
        return NodeResult(
            outputs={
                "target_path": target,
                "gameassembly_path": (assembly or {}).get("gameassembly_path", "") if isinstance(assembly, dict) else "",
                "loader_hints": hints,
                "preload_modules": preload_modules,
                "protected_modules": protected_modules,
                "recovery_strategy": strategy,
                "runtime_trace_required": bool(candidate_count and not hints.get("standard_metadata_path_found")),
                "evidence_status": "static_loader_evidence_collected",
            },
            summary=(f"Loader 证据: {len(preload_modules)} 个预加载模块 · 策略 {strategy}")
        )


@register
class UnityMetadataNode(BaseNode):
    node_type = "unity_metadata"
    label = "IL2CPP Metadata 检测与解密"
    icon = "🔐"
    category = "引擎专项"
    params_schema = [
        {"key": "target_path", "label": "游戏文件夹路径", "type": "text", "default": ""},
        {"key": "version", "label": "Unity 版本(留空自动识别)", "type": "text", "default": ""},
    ]

    async def execute(self, ctx) -> NodeResult:
        target = _unity_target(ctx, "unity_assembly", "unity_scan", "unity_analyze")
        if not target:
            return NodeResult(status="failed", error="无游戏目录(需先执行程序集定位或提供 target_path)")
        try:
            result = _run_unity_stages(
                target, str(ctx["params"].get("version") or ""),
                ("scan", "version", "buildtype", "assembly", "decrypt"), ctx.get("output_dir"), ctx.get("task_id", 0),
            )
        except Exception as e:
            return NodeResult(status="failed", error=f"Unity Metadata 分析失败: {e}")
        decrypt = result.get("decrypt", {}) or {}
        assembly = result.get("assembly", {}) or {}
        status = decrypt.get("status", "not_checked")
        metadata_ready = bool(
            decrypt.get("verified") and status in ("plain", "decrypted")
        )
        outputs = {
            "target_path": target,
            "build_type": (result.get("buildtype", {}) or {}).get("build_type", "Other"),
            "gameassembly_path": assembly.get("gameassembly_path") or (assembly.get("game_assembly", {}) or {}).get("path", ""),
            "source_metadata_path": decrypt.get("source_metadata_path") or decrypt.get("metadata", ""),
            "metadata_path": decrypt.get("usable_metadata_path") or "",
            "metadata_status": status,
            "metadata_ready": metadata_ready,
            "metadata_encrypted": decrypt.get("encrypted"),
            "metadata_decrypted": bool(decrypt.get("decrypted")),
            "decryption_required": bool(decrypt.get("decryption_required")),
            "decryption_attempted": bool(decrypt.get("decryption_attempted")),
            "decryption_status": decrypt.get("decryption_status", "not_checked"),
            "decryption_method": decrypt.get("method", ""),
            "decryption_recipe": decrypt.get("recipe", ""),
            "recovery_manifest": decrypt.get("recovery_manifest", ""),
            "diagnostics": decrypt.get("diagnostics", []),
            "decryption_diagnostics": decrypt.get("decryption_diagnostics", []),
            "runtime_validation": decrypt.get("runtime_validation", {}),
            "decrypt": decrypt,
            "result": result,
        }
        return NodeResult(
            outputs=outputs,
            summary=(f"Metadata: {status} · "
                     f"{'已验证可用于 SDK' if metadata_ready else '未验证，SDK 将被阻止'}"),
        )


@register
class UnityMetadataValidationNode(BaseNode):
    node_type = "unity_metadata_validation"
    label = "Metadata 结构与重复哈希验证"
    icon = "✓"
    category = "引擎专项"
    params_schema = [
        {"key": "target_path", "label": "游戏文件夹路径", "type": "text", "default": ""},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...services.unity import il2cpp
        import hashlib

        metadata = _pool_val(ctx.get("pool") or {}, "unity_metadata", {})
        path = str((metadata or {}).get("metadata_path") or "") if isinstance(metadata, dict) else ""
        if not path or not Path(path).is_file():
            return NodeResult(outputs={
                "target_path": _unity_target(ctx, "unity_metadata", "unity_assembly"),
                "metadata_path": "", "metadata_verified": False,
                "status": "metadata_not_recovered", "sha256_first": "", "sha256_second": "",
                "repeat_hash_match": False,
            }, summary="Metadata 未恢复，结构验证未通过")
        try:
            first = hashlib.sha256(Path(path).read_bytes()).hexdigest()
            parsed = il2cpp.parse_metadata(path)
            second = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        except Exception as exc:
            return NodeResult(status="failed", error=f"Metadata 验证失败: {exc}")
        verified = bool(parsed.get("valid") and first == second)
        return NodeResult(outputs={
            "target_path": _unity_target(ctx, "unity_metadata", "unity_assembly"),
            "metadata_path": path,
            "metadata_verified": verified,
            "status": "verified" if verified else "invalid",
            "metadata_version": parsed.get("version"),
            "table_count_semantics": parsed.get("table_count_semantics", ""),
            "type_count": parsed.get("type_count", 0),
            "method_count": parsed.get("method_count", 0),
            "field_count": parsed.get("field_count", 0),
            "sha256_first": first, "sha256_second": second,
            "repeat_hash_match": first == second,
            "validation": parsed,
        }, summary=(f"Metadata {'验证通过' if verified else '验证失败'} · "
                    f"v{parsed.get('version', '?')} · SHA-256 重复一致:{first == second}"))


@register
class UnityReportNode(BaseNode):
    """Render a complete Unity engine report from the graph's cached stages."""

    node_type = "unity_report"
    label = "Unity 结构化证据报告"
    icon = "📄"
    category = "输出"
    params_schema = [
        {"key": "title", "label": "报告标题", "type": "text", "default": "Unity 专项分析报告"},
        {"key": "target_path", "label": "游戏文件夹路径", "type": "text", "default": ""},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...services import unity as unity_mod

        target = _unity_target(ctx, "unity_metadata", "unity_assembly", "unity_scan", "unity_analyze")
        if not target:
            return NodeResult(status="failed", error="无游戏目录(需先执行 Unity 前序节点或提供 target_path)")
        pool = ctx.get("pool") or {}
        # Graph nodes store flattened outputs; build the stage-shaped result
        # expected by the Unity report service without rescanning metadata.
        scan_out = _pool_val(pool, "unity_scan", {})
        assembly_out = _pool_val(pool, "unity_assembly", {})
        metadata_out = _pool_val(pool, "unity_metadata", {})
        sdk_out = _pool_val(pool, "sdk_dump", {})
        staged = {
            "scan": (scan_out or {}).get("result", {}).get("scan", {}) if isinstance(scan_out, dict) else {},
            "version": {
                "version": (scan_out or {}).get("unity_version", "") if isinstance(scan_out, dict) else "",
            },
            "buildtype": {
                "build_type": (metadata_out or assembly_out or scan_out or {}).get("build_type", "Other"),
                "confidence": (scan_out or {}).get("build_confidence", "") if isinstance(scan_out, dict) else "",
                "evidence": (scan_out or {}).get("build_evidence", {}) if isinstance(scan_out, dict) else {},
            },
            "assembly": (assembly_out or {}).get("result", {}).get("assembly", {}) if isinstance(assembly_out, dict) else {},
            "decrypt": (metadata_out or {}).get("decrypt", {}) if isinstance(metadata_out, dict) else {},
            "sdk": sdk_out if isinstance(sdk_out, dict) else {},
        }
        # If the flattened nodes were used independently, retain their key
        # fields rather than emitting a blank report section.
        if not staged["assembly"] and isinstance(assembly_out, dict):
            staged["assembly"] = {
                "mode": assembly_out.get("mode"),
                "gameassembly_path": assembly_out.get("gameassembly_path", ""),
                "metadata_path": assembly_out.get("metadata_path", ""),
            }
        if not staged["decrypt"] and isinstance(metadata_out, dict):
            staged["decrypt"] = {
                key: metadata_out.get(key)
                for key in (
                    "metadata_status", "metadata_encrypted", "metadata_decrypted",
                    "decryption_required", "decryption_attempted", "decryption_status",
                    "decryption_method", "runtime_validation", "source_metadata_path",
                    "metadata_path", "diagnostics", "decryption_diagnostics",
                )
            }
            staged["decrypt"]["status"] = staged["decrypt"].pop("metadata_status", "not_checked")
            staged["decrypt"]["encrypted"] = staged["decrypt"].pop("metadata_encrypted", None)
            staged["decrypt"]["decrypted"] = staged["decrypt"].pop("metadata_decrypted", False)
            staged["decrypt"]["method"] = staged["decrypt"].pop("decryption_method", "")
            staged["decrypt"]["metadata"] = staged["decrypt"].get("source_metadata_path", "")

        uctx = {
            "params": {"path": target},
            "target_path": target,
            "data": None,
            "analysis_id": ctx.get("task_id", 0),
            "workdir": Path(target),
            "output_dir": ctx.get("output_dir"),
        }
        # 合并画布上 AI 辅助节点(unity_ai_assist)的输出进 Unity 报告
        ai_review = _pool_val(pool, "unity_ai_assist", {})
        if not isinstance(ai_review, dict) or not ai_review.get("ai_output"):
            ai_review = _pool_val(pool, "ai_review", {})
        if isinstance(ai_review, dict) and ai_review.get("ai_output"):
            staged["ai_review"] = ai_review
        try:
            generated = unity_mod.execute_stage("report", uctx, staged)
        except Exception as exc:
            return NodeResult(status="failed", error=f"Unity 报告生成失败: {exc}")
        return NodeResult(
            outputs={
                "report_paths": generated.get("report_paths", {}),
                "report_name": generated.get("report_name", ""),
                "source_name": generated.get("name", ""),
                "target_path": target,
                "runtime_validation": staged.get("decrypt", {}).get("runtime_validation", {}),
                "root_markdown": (generated.get("report_paths") or {}).get("root_markdown", ""),
            },
            summary=f"Unity 结构化报告已生成: {(generated.get('report_paths') or {}).get('html', '')}",
        )


@register
class UnityAnalyzeNode(BaseNode):
    node_type = "unity_analyze"
    label = "Unity 引擎分析(游戏目录)"
    icon = "🎮"
    category = "引擎专项"
    params_schema = [
        {"key": "target_path", "label": "游戏文件夹路径", "type": "text", "default": "", "required": True},
        {"key": "version", "label": "Unity 版本(留空自动识别)", "type": "text", "default": ""},
        {"key": "include_sdk", "label": "在本节点生成 SDK", "type": "bool", "default": False},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...services import unity as unity_mod
        target = ctx["params"].get("target_path", "")
        if not target:
            return NodeResult(status="failed", error="请提供游戏文件夹路径 target_path")
        result = {}
        uctx = {"params": {"path": target, "version": ctx["params"].get("version", "")},
                "target_path": target, "data": None, "analysis_id": ctx.get("task_id", 0),
                "workdir": Path(target), "output_dir": ctx.get("output_dir")}
        stages = [s for s in unity_mod.STAGES if s not in ("report",) and
                  (ctx["params"].get("include_sdk") or s != "sdk")]
        for stage in stages:
            try:
                result[stage] = unity_mod.execute_stage(stage, uctx, result)
            except Exception as e:
                return NodeResult(status="failed", error=f"Unity 阶段 {stage} 失败: {e}")
        dec = result.get("decrypt", {}) or {}
        scan = result.get("scan", {}) or {}
        sdk = result.get("sdk", {}) or {}
        assembly = result.get("assembly", {}) or {}
        build = result.get("buildtype", {}) or {}
        metadata_status = dec.get("status", "not_checked")
        metadata_ready = bool(
            dec.get("verified") and metadata_status in ("plain", "decrypted")
        )
        return NodeResult(outputs={
            "target_path": target,
            "unity_version": (result.get("version", {}) or {}).get("version")
            or (result.get("version", {}) or {}).get("detected_version"),
            "build_type": build.get("build_type"),
            "build_evidence": build.get("evidence", {}),
            "metadata": assembly.get("metadata"),
            "source_metadata_path": dec.get("source_metadata_path") or dec.get("metadata") or "",
            "metadata_path": dec.get("usable_metadata_path") or "",
            "metadata_status": metadata_status,
            "metadata_ready": metadata_ready,
            "metadata_encrypted": dec.get("encrypted"),
            "metadata_decrypted": bool(dec.get("decrypted")),
            "decryption_required": bool(dec.get("decryption_required")),
            "decryption_attempted": bool(dec.get("decryption_attempted")),
            "decryption_status": dec.get("decryption_status", "not_checked"),
            "decryption_method": dec.get("method", ""),
            "gameassembly_path": assembly.get("gameassembly_path")
            or (assembly.get("game_assembly", {}) or {}).get("path", ""),
            "managed_assemblies": assembly.get("managed_assemblies", []),
            "decrypt": dec,
            "runtime_validation": dec.get("runtime_validation", {}),
            "sdk": sdk,
            "resources": result.get("resource"),
            "result": result,
        }, summary=(f"Unity {(result.get('version', {}) or {}).get('version', '')} · "
                    f"{build.get('build_type', '')} · Metadata:{metadata_status}"))


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
        target = _unity_target(ctx, "unity_metadata", "unity_assembly", "unity_analyze", "unity_scan")
        if not target:
            return NodeResult(status="failed", error="无游戏目录(需先执行 Unity 前序节点或提供 target_path)")
        previous = {}
        for node_name in ("unity_metadata", "unity_analyze", "unity_assembly"):
            candidate = _pool_val(ctx["pool"], node_name, {})
            if isinstance(candidate, dict) and candidate:
                previous = candidate
                break
        build_type = previous.get("build_type", "")
        if build_type and build_type != "IL2CPP":
            outputs = {
                "ok": True,
                "status": "not_applicable",
                "delivery_complete": False,
                "mode": build_type,
                "manifest": "",
                "target_path": target,
                "note": "Mono build: IL2CPP SDK export is not applicable",
            }
            return NodeResult(outputs=outputs, summary="SDK 不适用: Mono/非 IL2CPP")
        meta = Path(previous.get("metadata_path")) if previous.get("metadata_path") else (
            Path(target) / "Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
        )
        ga = Path(previous.get("gameassembly_path")) if previous.get("gameassembly_path") else Path(target) / "GameAssembly.dll"
        if not meta.exists():
            outputs = {
                "ok": False,
                "status": "metadata_missing",
                "delivery_complete": False,
                "target_path": target,
                "metadata": "",
                "dll": str(ga) if ga.exists() else "",
                "manifest": "",
                "note": "global-metadata.dat was not found",
            }
            return NodeResult(outputs=outputs, summary="SDK 被阻止: Metadata 缺失")
        metadata_status = il2cpp.check_metadata_encrypted(str(meta))
        if metadata_status.get("status") != "plain":
            outputs = {
                "ok": False,
                "status": "blocked_by_metadata",
                "delivery_complete": False,
                "target_path": target,
                "metadata": str(meta),
                "dll": str(ga) if ga.exists() else "",
                "manifest": "",
                "metadata_status": metadata_status,
                "note": "SDK export requires verified plaintext metadata",
            }
            return NodeResult(outputs=outputs, summary="SDK 被阻止: Metadata 未验证")
        output_root = ctx.get("output_dir")
        out = (Path(str(output_root)) / "sdk") if output_root else (
            config.SDK_DIR / f"wf_{ctx['task_id']}_{Path(target).name}"
        )
        out.mkdir(parents=True, exist_ok=True)
        r = il2cpp.dump_sdk(str(meta), str(ga), str(out))
        outputs = {
            "ok": bool(r.get("ok")),
            "status": r.get("status", "failed"),
            "delivery_complete": bool(r.get("delivery_complete")),
            "types": r.get("types", 0),
            "methods": r.get("methods", 0),
            "fields": r.get("fields", 0),
            "properties": r.get("properties", 0),
            "dump_cs": r.get("dump_cs", ""),
            "script_json": r.get("script_json", ""),
            "stringliteral_json": r.get("stringliteral_json", ""),
            "il2cpp_h": r.get("il2cpp_h", ""),
            "sdk_json": r.get("sdk_json", ""),
            "cpp_dir": r.get("cpp_dir", ""),
            "cpp_headers": r.get("cpp_headers", []),
            "dll": r.get("dll", ""),
            "dummy_dir": r.get("dummy_dir", ""),
            "dummy_dlls": r.get("dummy_dlls", []),
            "official_tool": r.get("official_tool", {}),
            "dll_source": r.get("dll_source", str(ga) if ga.exists() else ""),
            "metadata": r.get("metadata", str(meta)),
            "metadata_source": r.get("metadata_source", str(meta)),
            "metadata_status": r.get("metadata_status", metadata_status),
            "manifest": r.get("manifest", ""),
            "artifacts": r.get("artifacts", []),
            "missing_required": r.get("missing_required", []),
            "out_dir": str(out),
            "warnings": r.get("warnings", []),
        }
        return NodeResult(
            outputs=outputs,
            summary=(f"SDK: {outputs['types']} 类 / {outputs['methods']} 方法 · "
                     f"{'交付完整' if outputs['delivery_complete'] else outputs['status']}"),
        )


@register
class UnityDeliveryGateNode(BaseNode):
    node_type = "unity_delivery_gate"
    label = "Unity 最终交付门禁"
    icon = "✓"
    category = "输出"
    params_schema = []

    async def execute(self, ctx) -> NodeResult:
        pool = ctx.get("pool") or {}
        assembly = _pool_val(pool, "unity_assembly", {})
        validation = _pool_val(pool, "metadata_validation", {}) or _pool_val(
            pool, "unity_metadata_validation", {}
        )
        sdk = _pool_val(pool, "sdk_dump", {})
        report = _pool_val(pool, "report", {})
        build_type = (assembly or {}).get("build_type", "") if isinstance(assembly, dict) else ""
        report_paths = (report or {}).get("report_paths", {}) if isinstance(report, dict) else {}
        root_markdown = (report or {}).get("root_markdown") or report_paths.get("root_markdown", "")
        required = {
            "metadata_verified": bool((validation or {}).get("metadata_verified")),
            "sdk_delivery_complete": bool((sdk or {}).get("delivery_complete")),
            "dump_cs": bool((sdk or {}).get("dump_cs") and Path((sdk or {})["dump_cs"]).is_file()),
            "script_json": bool((sdk or {}).get("script_json") and Path((sdk or {})["script_json"]).is_file()),
            "sdk_json": bool((sdk or {}).get("sdk_json") and Path((sdk or {})["sdk_json"]).is_file()),
            "stringliteral_json": bool((sdk or {}).get("stringliteral_json") and Path((sdk or {})["stringliteral_json"]).is_file()),
            "dummy_dlls": bool((sdk or {}).get("dummy_dlls") and all(
                Path(path).is_file() for path in (sdk or {}).get("dummy_dlls", [])
            )),
            "root_markdown": bool(root_markdown and Path(root_markdown).is_file()),
        }
        if build_type != "IL2CPP":
            required = {"root_markdown": required["root_markdown"]}
        missing = [name for name, ready in required.items() if not ready]
        outputs = {
            "delivery_complete": not missing,
            "build_type": build_type,
            "checks": required,
            "missing": missing,
            "root_markdown": root_markdown,
        }
        if missing:
            return NodeResult(status="failed", outputs=outputs,
                              error="Unity 交付未通过: " + ", ".join(missing))
        return NodeResult(outputs=outputs, summary="Unity 最终交付门禁通过")
