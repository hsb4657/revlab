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
        {"key": "on_fail", "label": "AI 不可用策略", "type": "select", "default": "external_wait",
         "options": ["external_wait", "skip", "abort"],
         "desc": "external_wait:构建证据等待外部 AI; skip:跳过; abort:中止"},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...services.ai_workflow import apply_session_settings, normalize_reasoning
        pool = ctx.get("pool") or {}
        node_id = (ctx.get("node") or {}).get("id", "ai_analyze")
        params = _prompt_params(ctx)
        prompt = resolve(str(params.get("prompt", "")), pool)
        if not prompt.strip():
            return NodeResult(status="failed", error="分析指令不能为空")

        # 1) 外部 AI 已提交结论
        ext = _external_ai_decision(pool, node_id)
        if ext:
            return NodeResult(
                outputs={**ext, "source": "external_ai"},
                summary=ext.get("response", "")[:120].replace("\n", " ") or "外部 AI 结论已应用",
            )

        # 2) 内部 AI
        cfg = _load_ai_cfg()
        if _ai_configured(cfg):
            runtime = apply_session_settings(cfg, str(params.get("model") or ""),
                                             normalize_reasoning(params.get("reasoning", "balanced")))
            system = str(params.get("system_prompt") or "").strip() or (
                "You are REVLab's binary-analysis assistant. Analyze the provided data precisely "
                "and answer in Chinese. If JSON output is requested, return only JSON."
            )
            messages = [{"role": "system", "content": system}, {"role": "user", "content": prompt}]
            try:
                out = _chat_json(runtime, messages)
            except Exception as exc:
                return NodeResult(
                    status="failed",
                    outputs={"ai_output": True, "configured": True, "error": str(exc), "response": ""},
                    summary=f"AI 请求失败: {str(exc)[:80]}",
                    error=f"AI 请求失败: {exc}",
                )
            outputs = {
                "ai_output": True, "configured": True,
                "response": out["text"][:30000],
                "model": runtime.get("model", ""),
            }
            if out.get("json") is not None:
                outputs["json"] = out["json"]
                outputs["json_ok"] = True
            if out.get("warning"):
                outputs["warning"] = out["warning"]
            return NodeResult(outputs=outputs,
                              summary=out["text"][:120].replace("\n", " ") or "AI 分析完成")

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
        return _ai_waiting_node_result(node_id, {"prompt": prompt})


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
                outputs={**ext, "sample_path": path or params.get("sample_path", ""),
                         "_analysis": result, "source": "external_ai"},
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
            try:
                assisted = ue_ai.assist_ue_analysis(evidence, cfg)
            except Exception as exc:
                return NodeResult(
                    status="failed",
                    outputs={"ai_output": True, "configured": True, "error": str(exc),
                             "three_majors": {}, "getname_algorithm": {}, "decryption_algorithm": {},
                             "evidence": evidence, "_analysis": result, "sample_path": path},
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
            "three_majors_ai": three, "getname_algorithm": gna,
            "decryption_algorithm": da, "notes": assisted.get("notes", []),
            "raw_response": assisted.get("raw_response", "")[:30000],
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
            return NodeResult(outputs={**ext, "source": "external_ai"},
                              summary="外部 AI 结论已应用")

        # 2) 构建证据:从变量池收集前序节点输出
        evidence = {
            "pe": pool.get("pe_identify", {}),
            "packer": pool.get("packer_detect", {}),
            "protection": pool.get("pe_protection_matrix", {}),
            "unpack_strategy": pool.get("pe_unpack_strategy", {}),
            "strings": pool.get("strings", {}),
            "disassembly": pool.get("disassemble", {}),
            "decompile": pool.get("decompile", {}),
            "dynamic": pool.get("dynamic", {}),
        }
        # 精简证据(去掉大字段)
        for key in evidence:
            if isinstance(evidence[key], dict):
                evidence[key] = {k: v for k, v in evidence[key].items()
                                 if k not in ("imports", "exports", "sections", "data_directories",
                                              "resources", "functions") and not str(k).startswith("_")}

        # 3) 内部 AI
        cfg = _load_ai_cfg()
        if _ai_configured(cfg):
            from ...services.ai_workflow import apply_session_settings, normalize_reasoning
            runtime = apply_session_settings(cfg, "", "balanced")
            system = ("你是资深 Windows PE 逆向工程师。基于给出的静态分析数据,输出中文结论:\n"
                      "1. 壳/保护判定(真实壳 vs 误报)\n2. 可疑点与恶意行为线索\n"
                      "3. 逆向分析建议(下一步)\n\n"
                      "重要:你可以搜索互联网获取信息,如:\n"
                      "- 搜索样本中出现的 DLL/函数名了解其功能\n"
                      "- 搜索壳特征确认壳类型\n"
                      "- 搜索可疑行为模式\n"
                      "用 JSON 格式输出。")
            user = f"PE 分析数据:\n{json.dumps(evidence, ensure_ascii=False)[:15000]}"
            try:
                out = _chat_json(runtime, [{"role": "system", "content": system},
                                           {"role": "user", "content": user}])
                return NodeResult(
                    outputs={"ai_output": True, "configured": True, "response": out["text"][:30000],
                             "json": out.get("json"), "model": runtime.get("model", ""), "evidence": evidence},
                    summary=out["text"][:120].replace("\n", " ") or "PE AI 分析完成")
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
            return NodeResult(outputs={**ext, "source": "external_ai"},
                              summary="外部 AI 结论已应用")

        # 2) 构建证据:从变量池收集前序节点输出
        evidence = {
            "scan": pool.get("unity_scan", {}),
            "assembly": pool.get("unity_assembly", {}),
            "metadata_candidates": pool.get("unity_metadata_candidates", {}),
            "loader_analysis": pool.get("unity_loader_analysis", {}),
            "metadata": pool.get("unity_metadata", {}),
            "metadata_validation": pool.get("metadata_validation", {}),
            "sdk": pool.get("sdk_dump", {}),
        }
        # 精简证据
        for key in evidence:
            if isinstance(evidence[key], dict):
                evidence[key] = {k: v for k, v in evidence[key].items()
                                 if not str(k).startswith("_") and k not in ("result",)}

        # 3) 内部 AI
        cfg = _load_ai_cfg()
        if _ai_configured(cfg):
            from ...services.ai_workflow import apply_session_settings, normalize_reasoning
            runtime = apply_session_settings(cfg, "", "balanced")
            system = ("你是资深 Unity/IL2CPP 逆向工程师。基于给出的分析数据,输出中文结论:\n"
                      "1. 构建类型与版本结论\n2. Metadata 状态与可用性\n"
                      "3. SDK 完整性评估\n4. 剩余风险与下一步建议\n\n"
                      "重要:你可以搜索互联网获取信息,如:\n"
                      "- 搜索检测到的 Unity 版本的 IL2CPP metadata 格式\n"
                      "- 搜索 global-metadata.dat 结构定义和版本差异\n"
                      "- 搜索 Unity 游戏的已知保护方案\n"
                      "- 搜索 Il2CppDumper 等工具的实现参考\n"
                      "用 JSON 格式输出。")
            user = f"Unity 分析数据:\n{json.dumps(evidence, ensure_ascii=False)[:15000]}"
            try:
                out = _chat_json(runtime, [{"role": "system", "content": system},
                                           {"role": "user", "content": user}])
                return NodeResult(
                    outputs={"ai_output": True, "configured": True, "response": out["text"][:30000],
                             "json": out.get("json"), "model": runtime.get("model", ""), "evidence": evidence},
                    summary=out["text"][:120].replace("\n", " ") or "Unity AI 分析完成")
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
