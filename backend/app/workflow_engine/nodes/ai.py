"""AI 辅助分析节点:通用 AI 分析节点 + UE 专项 AI 辅助分析节点。

三层决策链:
  1. 变量池中是否有外部 AI 已提交的结论(_ai_decision_{node_id}) → 直接使用
  2. 内部 AI 是否已配置(base_url/api_key/model) → 调用内部模型
  3. 都没有 → 构建证据并返回 AI_WAITING,引擎标记失败;
     外部 AI 通过 MCP wf_resolve_ai 提交结论后 wf_retry_node 重跑即可

这样工作流无需配置内部 LLM,外部 AI 通过 MCP 即可完全驱动分析。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ...services import pe_parser
from ..variables import resolve
from .base import BaseNode, NodeResult, register


_AI_WAITING_PREFIX = "AI_WAITING: "


def _load_ai_cfg() -> dict:
    from ...services import ai as ai_svc
    return ai_svc.load_config()


def _ai_configured(cfg: dict) -> bool:
    return bool(cfg.get("enabled") and cfg.get("base_url") and cfg.get("model") and cfg.get("api_key"))


def _external_ai_decision(pool: dict, node_id: str) -> dict | None:
    """检查变量池中是否有外部 AI 已提交的结论。"""
    key = f"_ai_decision_{node_id}"
    val = (pool or {}).get(key)
    if isinstance(val, dict) and val.get("ai_output"):
        return val
    return None


def _ai_result_metadata(outputs: dict, source: str) -> dict:
    """Annotate model decisions without promoting them to confirmed facts."""
    result = dict(outputs or {})
    result.setdefault("source", source)
    result.setdefault("evidence_level", "ai_inferred")
    result.setdefault("validation_state", "ai_inferred")
    return result


def _chat_json(cfg: dict, messages: list, max_tokens: int = 2000) -> dict:
    from ...services import ai as ai_svc
    reply = ai_svc.chat(cfg, messages)
    text = (reply or "").strip()
    parsed = _extract_json_object(text)
    if parsed is None:
        return {"ok": True, "text": text, "json": None, "warning": "模型未返回 JSON,已保留原文"}
    return {"ok": True, "text": text, "json": parsed}


def _extract_json_object(content: str) -> dict | None:
    source = content.strip().lstrip("\ufeff")
    fence = re.search(r"```(?:json)?\s*(.*?)```", source, re.IGNORECASE | re.DOTALL)
    candidates = ([fence.group(1).strip()] if fence else []) + [source]
    decoder = json.JSONDecoder()
    for candidate in candidates:
        for match in re.finditer(r"\{", candidate):
            try:
                parsed, _ = decoder.raw_decode(candidate[match.start():])
                if isinstance(parsed, dict):
                    return parsed
            except (TypeError, ValueError):
                continue
    return None


def _prompt_params(ctx: dict) -> dict:
    return dict(ctx.get("params") or {})


def _bounded(value, *, depth: int = 0, max_depth: int = 4,
             max_items: int = 40, max_string: int = 1800):
    """Keep AI prompts sample-specific without embedding entire stage blobs."""
    from ...services import ai as ai_svc
    return ai_svc._limit_value(value, depth=depth, max_depth=max_depth,
                               max_items=max_items, max_string=max_string)


def _pe_ai_evidence(pool: dict) -> dict:
    """Build a bounded PE evidence map while retaining differentiating fields."""
    identified = pool.get("pe_identify", {}) or {}
    pe = identified.get("pe") if isinstance(identified, dict) else {}
    pe = pe if isinstance(pe, dict) else identified if isinstance(identified, dict) else {}

    sections = []
    for item in pe.get("sections", identified.get("sections", []) if isinstance(identified, dict) else []) or []:
        if not isinstance(item, dict):
            continue
        sections.append({key: item.get(key) for key in (
            "name", "virtual_address", "virtual_size", "raw_ptr", "raw_size",
            "characteristics", "entropy", "suspicious") if key in item})

    imports = []
    for item in (pe.get("imports", identified.get("imports", []) if isinstance(identified, dict) else []) or [])[:80]:
        if not isinstance(item, dict):
            continue
        funcs = item.get("functions") or item.get("imports") or []
        names = []
        for fn in funcs[:48]:
            name = fn.get("name") if isinstance(fn, dict) else fn
            if name:
                names.append(str(name))
        imports.append({"dll": item.get("dll") or item.get("name") or "", "functions": names})

    strings = pool.get("strings", {}) or {}
    if isinstance(strings, list):
        strings = {"count": len(strings), "strings": strings}
    decompile = pool.get("decompile", {}) or {}
    functions = []
    if isinstance(decompile, dict):
        for fn in (decompile.get("functions") or [])[:40]:
            if not isinstance(fn, dict):
                continue
            functions.append({key: fn.get(key) for key in ("address", "name", "signature", "c") if key in fn})
    dynamic = pool.get("dynamic", {}) or {}
    # DynamicAnalyzeNode nests local observations under result; expose both
    # the execution decision and the bounded observation payload.
    dynamic_result = dynamic.get("result") if isinstance(dynamic, dict) else {}
    dynamic_status = dynamic.get("execution_status") if isinstance(dynamic, dict) else None
    if not dynamic_status and isinstance(dynamic_result, dict):
        dynamic_status = dynamic_result.get("execution_status") or dynamic_result.get("status")
    if not dynamic_status and isinstance(dynamic, dict) and dynamic.get("executed") is True:
        dynamic_status = "completed" if dynamic.get("ok", True) else "failed"
    if not dynamic:
        dynamic = {"execution_status": "not_collected", "executed": False,
                   "reason": "工作流未包含动态阶段或该阶段尚未运行"}

    packer = (pool.get("packer_detect", {}) or pe.get("packer", {}) or
              (identified.get("packer", {}) if isinstance(identified, dict) else {}))
    sources = {
        "pe_identify": {
            key: pe.get(key) for key in (
                "is_pe", "machine", "is_64bit", "subsystem", "entry_point", "image_base",
                "image_size", "timestamp", "checksum", "security", "debug", "signature",
                "rich_header", "data_directories", "tls_callbacks") if key in pe
        },
        "sections_static": sections,
        "imports_static": imports,
        "exports_static": (pe.get("exports", identified.get("exports", []) if isinstance(identified, dict) else []) or [])[:48],
        "packer_static": packer,
        "protection_matrix": pool.get("pe_protection_matrix", {}) or {},
        "unpack_strategy": pool.get("pe_unpack_strategy", {}) or {},
        "strings_static": {"count": strings.get("count", len(strings.get("strings", [])) if isinstance(strings, dict) else 0),
                            "items": (strings.get("strings") or strings.get("interesting") or [])[:120]
                            if isinstance(strings, dict) else []},
        "disassembly_static": pool.get("disassemble", {}) or {},
        "decompile_static": {"ok": decompile.get("ok"), "available": decompile.get("available"),
                             "function_count": decompile.get("function_count"), "functions": functions},
        "dynamic_observation": dynamic,
    }
    from ...services import ai as ai_svc
    bundle = ai_svc.build_evidence_bundle(
        "PE", sources,
        extra={"dynamic_status": dynamic_status or "not_collected",
               "sample_path": identified.get("sample_path", "") if isinstance(identified, dict) else ""},
    )
    # Keep stage names at the top level for external MCP clients and old
    # workflows, while `sources` remains the canonical traceable envelope.
    bundle.update({"pe": _bounded(sources["pe_identify"]),
                   "sections": _bounded(sections), "imports": _bounded(imports),
                   "exports": _bounded(sources["exports_static"]),
                   "packer": _bounded(packer), "strings": _bounded(sources["strings_static"]),
                   "disassembly": _bounded(sources["disassembly_static"]),
                   "decompile": _bounded(sources["decompile_static"]),
                   "dynamic": _bounded(dynamic)})
    bundle["redaction_notes"] = [
        "节区、导入和函数列表已限量；完整产物仍在工作流输出目录。",
        "dynamic_observation 的 blocked/not_collected 状态表示没有运行时事实。",
    ]
    return bundle


def _unity_ai_evidence(pool: dict) -> dict:
    """Build a bounded Unity evidence map for Mono and IL2CPP alike."""
    source_names = (
        "unity_scan", "unity_assembly", "unity_metadata_candidates", "unity_loader_analysis",
        "unity_metadata", "metadata_validation", "sdk_dump", "unity_analyze",
    )
    raw = {name: pool.get(name, {}) or {} for name in source_names}
    compact = {}
    for name, value in raw.items():
        if isinstance(value, dict):
            # Preserve status/paths/counts and bounded nested evidence.  The
            # complete SDK or scan manifest remains available as an artifact.
            compact[name] = _bounded(value, max_depth=5, max_items=48, max_string=1600)
        else:
            compact[name] = _bounded(value)
    build = raw.get("unity_scan") or raw.get("unity_analyze") or {}
    metadata = raw.get("unity_metadata") or raw.get("unity_assembly") or {}
    dynamic = raw.get("dynamic") or {
        "execution_status": "not_collected", "executed": False,
        "reason": "Unity 专项流程未包含运行时执行阶段",
    }
    from ...services import ai as ai_svc
    bundle = ai_svc.build_evidence_bundle(
        "Unity", compact,
        extra={
            "build_type": build.get("build_type") if isinstance(build, dict) else None,
            "unity_version": build.get("unity_version") if isinstance(build, dict) else None,
            "metadata_status": metadata.get("metadata_status") if isinstance(metadata, dict) else None,
            "dynamic_status": dynamic.get("execution_status", "not_collected") if isinstance(dynamic, dict) else "not_collected",
        },
    )
    bundle.update({"build": compact.get("unity_scan", {}),
                   "assembly": compact.get("unity_assembly", {}),
                   "metadata_candidates": compact.get("unity_metadata_candidates", {}),
                   "loader": compact.get("unity_loader_analysis", {}),
                   "metadata": compact.get("unity_metadata", {}),
                   "validation": compact.get("metadata_validation", {}),
                   "sdk": compact.get("sdk_dump", {})})
    bundle["redaction_notes"] = [
        "目录扫描、程序集、Metadata 表和 SDK 清单均为有界摘要；完整文件通过产物路径取得。",
        "Metadata 候选或高熵文件不能单独证明已解密，需结构验证或构建匹配的运行时证据。",
    ]
    return bundle


def _ai_waiting_node_result(node_id: str, evidence: dict, extra: dict | None = None) -> NodeResult:
    """构建 AI_WAITING 失败结果:evidence 写入 outputs,外部 AI 可通过 MCP 读取。"""
    outputs = {
        "ai_output": True,
        "configured": False,
        "ai_waiting": True,
        "evidence": evidence,
        "error": f"{_AI_WAITING_PREFIX}内部 AI 未配置。外部 AI 可通过 MCP wf_resolve_ai 提交结论后 wf_retry_node 重试。",
        **(extra or {}),
    }
    return NodeResult(
        status="failed",
        outputs=outputs,
        summary=f"等待外部 AI 分析({node_id})",
        error=f"{_AI_WAITING_PREFIX}内部 AI 未配置,等待外部 AI 通过 MCP 提交分析结论",
    )


@register
class AIAnalyzeNode(BaseNode):
    """通用 AI 分析节点:可拖入任意工作流,{{变量}} 引用前序结果。
    支持内部 AI 直接调用或外部 AI 通过 MCP wf_resolve_ai 提交结论。"""

    node_type = "ai_analyze"
    label = "AI 分析节点"
    icon = "🤖"
    category = "AI 辅助分析"
    params_schema = [
        {"key": "prompt", "label": "分析指令(支持 {{变量}})", "type": "textarea", "default": "",
         "required": True,
         "desc": "示例: 分析以下壳检测结果并给出脱壳建议:\\n{{packer_detect.verdict}}"},
        {"key": "system_prompt", "label": "系统提示(可选)", "type": "textarea", "default": "",
         "desc": "给模型的角色设定,如:你是资深逆向工程师"},
        {"key": "output_mode", "label": "输出模式", "type": "select", "default": "text",
         "options": ["text", "json"],
         "desc": "json 模式下会尝试解析模型返回的 JSON 写入变量池"},
        {"key": "model", "label": "模型(留空用全局配置)", "type": "text", "default": ""},
        {"key": "reasoning", "label": "思考强度", "type": "select", "default": "balanced",
         "options": ["fast", "balanced", "deep"]},
        {"key": "max_tool_rounds", "label": "AI 工具轮数上限", "type": "number", "default": 6},
        {"key": "on_fail", "label": "AI 不可用策略", "type": "select", "default": "external_wait",
         "options": ["external_wait", "skip", "abort"],
         "desc": "external_wait:构建证据等待外部 AI; skip:跳过; abort:中止"},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...services.ai_workflow import apply_session_settings, normalize_reasoning
        from ...services import ai as ai_svc
        pool = ctx.get("pool") or {}
        node_id = (ctx.get("node") or {}).get("id", "ai_analyze")
        params = _prompt_params(ctx)
        prompt = resolve(str(params.get("prompt", "")), pool)
        if not prompt.strip():
            return NodeResult(status="failed", error="分析指令不能为空")
        # A generic node should still receive the current workflow evidence
        # when the user asks an open-ended question.  The pool is bounded so a
        # large decompiler result cannot silently exhaust the model context.
        evidence = ai_svc.build_evidence_bundle("workflow", pool)
        # 1) 外部 AI 已提交结论
        ext = _external_ai_decision(pool, node_id)
        if ext:
            return NodeResult(
                outputs=_ai_result_metadata(ext, "external_ai"),
                summary=ext.get("response", "")[:120].replace("\n", " ") or "外部 AI 结论已应用",
            )

        # 2) 内部 AI
        cfg = _load_ai_cfg()
        if _ai_configured(cfg):
            from ...services.ai_agent import run_analysis_agent
            runtime = apply_session_settings(cfg, str(params.get("model") or ""),
                                             normalize_reasoning(params.get("reasoning", "balanced")))
            target = str(pool.get("sample_path") or pool.get("target_path") or "")
            try:
                agent = run_analysis_agent("workflow", target, runtime, evidence=evidence,
                                           instruction=prompt,
                                           system_prompt=str(params.get("system_prompt") or ""),
                                           max_rounds=int(params.get("max_tool_rounds", 6) or 6))
                if not agent.get("ok"):
                    raise RuntimeError(agent.get("error", "AI 工具循环失败"))
                response = agent.get("response", "")
            except Exception as exc:
                return NodeResult(
                    status="failed",
                    outputs={"ai_output": True, "configured": True, "error": str(exc), "response": ""},
                    summary=f"AI 请求失败: {str(exc)[:80]}",
                    error=f"AI 请求失败: {exc}",
                )
            outputs = {
                "ai_output": True, "configured": True,
                "source": "tool_agent", "evidence_level": "ai_inferred", "validation_state": "ai_inferred",
                "response": response[:30000],
                "model": agent.get("model", runtime.get("model", "")),
                "evidence": evidence,
                "tool_trace": agent.get("tool_trace", []),
                "tool_rounds": agent.get("tool_rounds", 0),
                "tool_mode": agent.get("tool_mode", "native"),
                "warning": agent.get("warning", ""),
            }
            parsed = _extract_json_object(response)
            if parsed is not None:
                outputs["json"] = parsed
                outputs["json_ok"] = True
            return NodeResult(outputs=outputs,
                              summary=response[:120].replace("\n", " ") or "AI 工具分析完成")

        # 3) 都没有 → 等待外部 AI
        if params.get("on_fail") == "skip":
            return NodeResult(
                status="skipped",
                outputs={"ai_output": True, "configured": False, "response": ""},
                summary="AI 未配置,跳过",
            )
        if params.get("on_fail") == "abort":
            return NodeResult(status="failed", error="AI 模型未配置")
        # default: external_wait
        return _ai_waiting_node_result(node_id, evidence, extra={"prompt": prompt})


@register
class UEAIAssistNode(BaseNode):
    """UE 专项 AI 辅助:综合静态证据(候选地址+反汇编)给出三大件精确地址、
    GetName/FName 算法与解密算法。支持外部 AI 通过 MCP 驱动。"""

    node_type = "ue_ai_assist"
    label = "UE AI 辅助分析(三大件/算法/解密)"
    icon = "🤖"
    category = "AI 辅助分析"
    params_schema = [
        {"key": "sample_path", "label": "Dump 后的 EXE 路径", "type": "text", "default": ""},
        {"key": "version", "label": "UE 版本(留空自动识别)", "type": "text", "default": ""},
        {"key": "max_tool_rounds", "label": "AI 工具轮数上限", "type": "number", "default": 6,
         "desc": "AI 每轮可调用一个或多个受控分析工具，达到上限后停止"},
        {"key": "on_fail", "label": "AI 不可用策略", "type": "select", "default": "external_wait",
         "options": ["external_wait", "skip", "abort"],
         "desc": "external_wait:构建证据等待外部 AI; skip:跳过; abort:中止"},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...services.ue import ai_assist as ue_ai
        pool = ctx.get("pool") or {}
        node_id = (ctx.get("node") or {}).get("id", "ue_ai_assist")
        params = _prompt_params(ctx)

        # 1) 外部 AI 已提交结论 → 直接使用
        ext = _external_ai_decision(pool, node_id)
        if ext:
            result, path, error = _ue_analysis_reuse(ctx)
            return NodeResult(
                outputs=_ai_result_metadata({**ext, "sample_path": path or params.get("sample_path", ""),
                         "_analysis": result, "source": "external_ai"},
                         "external_ai"),
                summary="外部 AI 结论已应用",
            )

        # 2) 构建证据
        result, path, error = _ue_analysis_reuse(ctx)
        if error:
            return NodeResult(status="failed", error=error)
        path = path or params.get("sample_path", "")
        if not path or not Path(path).exists():
            return NodeResult(status="failed", error="无样本路径")
        data = Path(path).read_bytes()
        pe = pe_parser.parse_pe(data, path)
        if not pe.get("is_pe"):
            return NodeResult(status="failed", error="非 PE 文件,无法执行 UE AI 分析")
        evidence = ue_ai.build_ue_evidence(result, data, pe)

        # 3) 内部 AI
        cfg = _load_ai_cfg()
        if _ai_configured(cfg):
            from ...services.ai_agent import run_analysis_agent
            try:
                agent = run_analysis_agent("UE", path, cfg, evidence=evidence,
                                           max_rounds=int(params.get("max_tool_rounds", 6) or 6))
                if not agent.get("ok"):
                    raise RuntimeError(agent.get("error", "AI 工具循环失败"))
                parsed = _extract_json_object(agent.get("response", "")) or {}
                assisted = ue_ai.normalize_ue_assist(
                    parsed, image_base=ue_ai._parse_int_address(evidence.get("image_base")))
                assisted.update({"raw_response": agent.get("response", "")[:8000],
                                 "tool_trace": agent.get("tool_trace", []),
                                 "tool_rounds": agent.get("tool_rounds", 0),
                                 "tool_mode": agent.get("tool_mode", "native"),
                                 "warning": agent.get("warning", ""),
                                 "model": agent.get("model", cfg.get("model", "")),
                                 "configured": True, "ai_output": True,
                                 "evidence_level": "ai_inferred", "validation_state": "ai_inferred"})
            except Exception as exc:
                return NodeResult(
                    status="failed",
                    outputs={"ai_output": True, "configured": True, "error": str(exc),
                             "three_majors": {}, "getname_algorithm": {}, "decryption_algorithm": {},
                             "evidence": evidence, "_analysis": result, "sample_path": path,
                             "source": "internal_model", "evidence_level": "ai_inferred",
                             "validation_state": "ai_inferred"},
                    summary=f"UE AI 辅助失败: {str(exc)[:80]}",
                    error=f"UE AI 辅助失败: {exc}",
                )
            return _ue_assist_success(assisted, evidence, result, path)

        # 4) 都没有 → 等待外部 AI
        if params.get("on_fail") == "skip":
            return NodeResult(
                status="skipped",
                outputs={"ai_output": True, "configured": False,
                         "three_majors": {}, "getname_algorithm": {}, "decryption_algorithm": {},
                         "evidence": evidence, "_analysis": result, "sample_path": path},
                summary="AI 未配置,UE AI 辅助跳过",
            )
        if params.get("on_fail") == "abort":
            return NodeResult(status="failed", error="AI 模型未配置")
        # default: external_wait
        return _ai_waiting_node_result(
            node_id, evidence,
            extra={"three_majors": {}, "getname_algorithm": {}, "decryption_algorithm": {},
                   "_analysis": result, "sample_path": path},
        )


def _ue_assist_success(assisted: dict, evidence: dict, result: dict, path: str) -> NodeResult:
    three = assisted.get("three_majors") or {}
    gna = assisted.get("getname_algorithm") or {}
    da = assisted.get("decryption_algorithm") or {}
    summary_parts = []
    for key, label in (("gobjects", "GObjects"), ("gnames", "GNames"), ("gworld", "GWorld")):
        item = three.get(key) or {}
        if item.get("rva_hex"):
            summary_parts.append(f"{label}:{item['rva_hex']}")
    getname_summary = "GetName 算法:未给出"
    if gna.get("description") or gna.get("model"):
        getname_summary = f"GetName 算法: {str(gna.get('model') or '')[:20]}"
        if gna.get("key_hex"):
            getname_summary += f" key={gna['key_hex']}"
    dec_summary = "无需解密" if not da.get("detected") else f"解密: {str(da.get('algorithm') or '')[:60]}"
    summary = " · ".join(summary_parts + [getname_summary, dec_summary]) or "UE AI 辅助分析完成"
    return NodeResult(
            outputs={
            "ai_output": True, "configured": True,
            "source": "internal_model", "evidence_level": "ai_inferred",
            "validation_state": "ai_inferred",
            # `three_majors` is the report/MCP contract; retain the old
            # `three_majors_ai` alias for clients that used the early preview.
            "three_majors": three, "three_majors_ai": three,
            "getname_algorithm": gna,
            "decryption_algorithm": da, "notes": assisted.get("notes", []),
            "raw_response": assisted.get("raw_response", "")[:30000],
            "tool_trace": assisted.get("tool_trace", []),
            "tool_rounds": assisted.get("tool_rounds", 0),
            "tool_mode": assisted.get("tool_mode", "native"),
            "warning": assisted.get("warning", ""),
            "model": assisted.get("model", ""), "evidence": evidence,
            "_analysis": result, "sample_path": path,
        },
        summary=summary,
    )


def _ue_analysis_reuse(ctx) -> tuple[dict | None, str, str]:
    from .analysis import _ue_analysis
    return _ue_analysis(ctx)


@register
class PEAIAssistNode(BaseNode):
    """PE 专项 AI 辅助:综合静态分析结果(PE 头/壳检测/字符串/反汇编/反编译)给出
    综合判定(壳/保护/可疑点/逆向建议)。支持外部 AI 通过 MCP 驱动。"""

    node_type = "pe_ai_assist"
    label = "PE AI 辅助分析(壳/可疑点/建议)"
    icon = "🤖"
    category = "AI 辅助分析"
    params_schema = [
        {"key": "sample_path", "label": "样本路径", "type": "text", "default": ""},
        {"key": "max_tool_rounds", "label": "AI 工具轮数上限", "type": "number", "default": 6},
        {"key": "on_fail", "label": "AI 不可用策略", "type": "select", "default": "external_wait",
         "options": ["external_wait", "skip", "abort"],
         "desc": "external_wait:构建证据等待外部 AI; skip:跳过; abort:中止"},
    ]

    async def execute(self, ctx) -> NodeResult:
        pool = ctx.get("pool") or {}
        node_id = (ctx.get("node") or {}).get("id", "pe_ai_assist")
        params = _prompt_params(ctx)

        # 1) 外部 AI 已提交结论
        ext = _external_ai_decision(pool, node_id)
        if ext:
            return NodeResult(outputs=_ai_result_metadata(ext, "external_ai"),
                              summary="外部 AI 结论已应用")

        # 2) 构建证据:按当前样本保留结构差异和动态状态
        evidence = _pe_ai_evidence(pool)

        # 3) 内部 AI
        cfg = _load_ai_cfg()
        if _ai_configured(cfg):
            from ...services.ai_agent import run_analysis_agent
            try:
                target = str(params.get("sample_path") or pool.get("sample_path") or
                             (pool.get("pe_identify", {}) or {}).get("sample_path") or "")
                if target.startswith("{{"):
                    target = str(pool.get("sample_path") or "")
                agent = run_analysis_agent("PE", target, cfg,
                                           evidence=evidence,
                                           max_rounds=int(params.get("max_tool_rounds", 6) or 6))
                if not agent.get("ok"):
                    raise RuntimeError(agent.get("error", "AI 工具循环失败"))
                response = agent.get("response", "")
                return NodeResult(
                    outputs={"ai_output": True, "configured": True, "source": "tool_agent",
                             "evidence_level": "ai_inferred", "validation_state": "ai_inferred",
                             "response": response[:30000], "json": _extract_json_object(response),
                             "model": agent.get("model", cfg.get("model", "")),
                             "tool_trace": agent.get("tool_trace", []),
                             "tool_rounds": agent.get("tool_rounds", 0),
                             "tool_mode": agent.get("tool_mode", "native"),
                             "warning": agent.get("warning", ""), "evidence": evidence},
                    summary=response[:120].replace("\n", " ") or "PE AI 工具分析完成")
            except Exception as exc:
                return NodeResult(status="failed",
                                  outputs={"ai_output": True, "configured": True, "error": str(exc), "evidence": evidence},
                                  summary=f"PE AI 失败: {str(exc)[:80]}", error=f"PE AI 失败: {exc}")

        # 4) 等待外部 AI
        if params.get("on_fail") == "skip":
            return NodeResult(status="skipped",
                              outputs={"ai_output": True, "configured": False, "evidence": evidence},
                              summary="AI 未配置,跳过")
        if params.get("on_fail") == "abort":
            return NodeResult(status="failed", error="AI 模型未配置")
        return _ai_waiting_node_result(node_id, evidence)


@register
class UnityAIAssistNode(BaseNode):
    """Unity 专项 AI 辅助:综合 Unity 分析结果(版本/构建类型/metadata/SDK)给出
    综合判定(构建结论/metadata 可用性/SDK 完整性/风险提示)。支持外部 AI 通过 MCP 驱动。"""

    node_type = "unity_ai_assist"
    label = "Unity AI 辅助分析(构建/SDK/风险)"
    icon = "🤖"
    category = "AI 辅助分析"
    params_schema = [
        {"key": "target_path", "label": "游戏文件夹路径", "type": "text", "default": ""},
        {"key": "max_tool_rounds", "label": "AI 工具轮数上限", "type": "number", "default": 6},
        {"key": "on_fail", "label": "AI 不可用策略", "type": "select", "default": "external_wait",
         "options": ["external_wait", "skip", "abort"],
         "desc": "external_wait:构建证据等待外部 AI; skip:跳过; abort:中止"},
    ]

    async def execute(self, ctx) -> NodeResult:
        pool = ctx.get("pool") or {}
        node_id = (ctx.get("node") or {}).get("id", "unity_ai_assist")
        params = _prompt_params(ctx)

        # 1) 外部 AI 已提交结论
        ext = _external_ai_decision(pool, node_id)
        if ext:
            return NodeResult(outputs=_ai_result_metadata(ext, "external_ai"),
                              summary="外部 AI 结论已应用")

        # 2) 构建证据:同时覆盖 Mono、IL2CPP、Metadata 候选和 SDK 门禁
        evidence = _unity_ai_evidence(pool)

        # 3) 内部 AI
        cfg = _load_ai_cfg()
        if _ai_configured(cfg):
            from ...services.ai_agent import run_analysis_agent
            try:
                target = str(params.get("target_path") or pool.get("target_path") or
                             (pool.get("unity_scan", {}) or {}).get("target_path") or "")
                if target.startswith("{{"):
                    target = str(pool.get("target_path") or "")
                agent = run_analysis_agent("Unity", target, cfg,
                                           evidence=evidence,
                                           max_rounds=int(params.get("max_tool_rounds", 6) or 6))
                if not agent.get("ok"):
                    raise RuntimeError(agent.get("error", "AI 工具循环失败"))
                response = agent.get("response", "")
                return NodeResult(
                    outputs={"ai_output": True, "configured": True, "source": "tool_agent",
                             "evidence_level": "ai_inferred", "validation_state": "ai_inferred",
                             "response": response[:30000], "json": _extract_json_object(response),
                             "model": agent.get("model", cfg.get("model", "")),
                             "tool_trace": agent.get("tool_trace", []),
                             "tool_rounds": agent.get("tool_rounds", 0),
                             "tool_mode": agent.get("tool_mode", "native"),
                             "warning": agent.get("warning", ""), "evidence": evidence},
                    summary=response[:120].replace("\n", " ") or "Unity AI 工具分析完成")
            except Exception as exc:
                return NodeResult(status="failed",
                                  outputs={"ai_output": True, "configured": True, "error": str(exc), "evidence": evidence},
                                  summary=f"Unity AI 失败: {str(exc)[:80]}", error=f"Unity AI 失败: {exc}")

        # 4) 等待外部 AI
        if params.get("on_fail") == "skip":
            return NodeResult(status="skipped",
                              outputs={"ai_output": True, "configured": False, "evidence": evidence},
                              summary="AI 未配置,跳过")
        if params.get("on_fail") == "abort":
            return NodeResult(status="failed", error="AI 模型未配置")
        return _ai_waiting_node_result(node_id, evidence)
