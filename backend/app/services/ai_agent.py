"""Tool-using AI operator for PE, Unreal and Unity workflow nodes.

The operator is deliberately small and auditable.  The model may request one
of the read-only analysis tools below; REVLab executes it against the current
sample, returns a bounded observation, and lets the model decide whether more
evidence is needed.  Paths are pinned to the workflow target and dynamic
execution is still governed by the normal local-confirmation policy.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import ai
from . import disassembler, hash as hash_svc, packer, pe_parser, strings


def _tool(name: str, description: str, properties: dict, required: list[str] | None = None) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties,
                            "required": required or [], "additionalProperties": False},
        },
    }


TOOL_DEFINITIONS = [
    _tool("pe_get_info", "读取当前 PE 头、架构、安全目录和哈希。", {}, []),
    _tool("pe_list_sections", "读取当前 PE 节区、权限和熵。", {}, []),
    _tool("pe_get_imports", "读取当前 PE 导入/延迟导入/导出/TLS 线索。", {}, []),
    _tool("pe_detect_packer", "基于当前 PE 结构重新检测壳和保护特征。", {}, []),
    _tool("pe_extract_strings", "从当前 PE 提取有界兴趣字符串。", {
        "min_len": {"type": "integer", "minimum": 4, "maximum": 16},
    }),
    _tool("pe_disassemble_entry", "从当前 PE 入口点反汇编一小段指令。", {
        "max_insns": {"type": "integer", "minimum": 16, "maximum": 400},
    }),
    _tool("ue_analyze", "对当前 dump PE 重新执行 UE 版本、三大件和 FName 静态分析。", {
        "version": {"type": "string", "maxLength": 32},
    }),
    _tool("unity_scan", "扫描当前 Unity 游戏目录、版本和 Mono/IL2CPP 构建证据。", {}, []),
    _tool("unity_analyze", "对当前 Unity 目录读取程序集、Metadata 和关键字符串证据。", {}, []),
    _tool("unity_metadata", "重新检查当前 Unity Metadata 状态和结构校验。", {}, []),
    _tool("dynamic_run", "请求本机动态执行当前 PE；AI 不能代替用户确认，因此未确认时只返回阻止状态。", {
        "timeout": {"type": "integer", "minimum": 1, "maximum": 120},
        "mode": {"type": "string", "enum": ["local"]},
    }),
]

_PE_TOOLS = {"pe_get_info", "pe_list_sections", "pe_get_imports", "pe_detect_packer",
             "pe_extract_strings", "pe_disassemble_entry", "dynamic_run"}
_UE_TOOLS = _PE_TOOLS | {"ue_analyze"}
_UNITY_TOOLS = {"unity_scan", "unity_analyze", "unity_metadata"}


def _allowed_tool_names(kind: str) -> set[str]:
    return {"PE": _PE_TOOLS, "UE": _UE_TOOLS, "Unity": _UNITY_TOOLS}.get(
        kind, _UE_TOOLS | _UNITY_TOOLS)


def _bounded(value: Any) -> Any:
    return ai._limit_value(value, max_depth=5, max_items=60, max_string=1800)


def _target_matches(kind: str, target: str, args: dict) -> bool:
    requested = args.get("path") or args.get("sample_path") or args.get("target_path")
    if not requested:
        return True
    try:
        current = Path(target).resolve()
        supplied = Path(str(requested)).resolve()
    except (OSError, ValueError):
        return False
    return supplied == current


def _pe_data(target: str) -> tuple[bytes, dict]:
    data = Path(target).read_bytes()
    return data, pe_parser.parse_pe(data, target)


def _execute_tool(name: str, args: dict, *, kind: str, target: str) -> dict:
    if not target:
        return {"ok": False, "status": "missing_target", "error": "workflow target is not set"}
    if not _target_matches(kind, target, args):
        return {"ok": False, "status": "target_mismatch", "error": "tool path must match the active workflow target"}
    if name not in _allowed_tool_names(kind):
        return {"ok": False, "status": "tool_not_allowed_for_sample_type", "error": name}
    try:
        if name == "pe_get_info":
            data, pe = _pe_data(target)
            return {"ok": True, "tool": name, "hashes": hash_svc.compute_hashes(data), "pe": pe}
        if name == "pe_list_sections":
            _, pe = _pe_data(target)
            return {"ok": True, "tool": name, "sections": pe.get("sections", [])}
        if name == "pe_get_imports":
            _, pe = _pe_data(target)
            return {"ok": True, "tool": name, "imports": pe.get("imports", []),
                    "delayed_imports": pe.get("delayed_imports", []),
                    "exports": pe.get("exports", []), "tls_callbacks": pe.get("tls_callbacks", [])}
        if name == "pe_detect_packer":
            data, pe = _pe_data(target)
            return {"ok": True, "tool": name, "result": packer.detect_packer(pe, None, data)}
        if name == "pe_extract_strings":
            data, _ = _pe_data(target)
            values = strings.extract_strings(data, min_len=int(args.get("min_len", 6) or 6))
            return {"ok": True, "tool": name, "count": len(values),
                    "strings": strings.interesting_strings(values)[:160]}
        if name == "pe_disassemble_entry":
            data, pe = _pe_data(target)
            base = int(pe.get("image_base") or 0)
            ep = int(pe.get("entry_point") or 0)
            arch = "x64" if pe.get("machine") == "x64" else "x86"
            out = disassembler.disassemble_at(data, ep, base, arch,
                                               max_insns=int(args.get("max_insns", 120) or 120),
                                               sections=pe.get("sections", []))
            return {"ok": True, "tool": name, "result": out}
        if name == "ue_analyze":
            from .ue.analyzer import UEAnalyzer
            data = Path(target).read_bytes()
            return {"ok": True, "tool": name,
                    "result": UEAnalyzer(target, version=str(args.get("version") or ""), data=data).run()}
        if name in {"unity_scan", "unity_analyze", "unity_metadata"}:
            from . import unity
            from .unity.analyzer import UnityAnalyzer
            analyzer = UnityAnalyzer(target, version=str(args.get("version") or ""))
            if name == "unity_scan":
                return {"ok": True, "tool": name, "detect": analyzer.run_detect(), "scan": analyzer.run_scan()}
            if name == "unity_analyze":
                analyzer.run_detect()
                analyzer.run_scan()
                return {"ok": True, "tool": name, "summary": analyzer.summary(),
                        "assembly": analyzer.analyze_assemblies(),
                        "strings": analyzer.extract_strings()}
            ctx = {"params": {"version": str(args.get("version") or "")},
                   "target_path": target, "workdir": Path(target), "output_dir": None}
            prior = {}
            for stage in ("scan", "version", "buildtype", "assembly", "decrypt"):
                prior[stage] = unity.execute_stage(stage, ctx, prior)
            return {"ok": True, "tool": name, "decrypt": prior.get("decrypt"),
                    "assembly": prior.get("assembly"), "buildtype": prior.get("buildtype")}
        if name == "dynamic_run":
            return {"ok": True, "tool": name, "executed": False,
                    "execution_status": "blocked_by_policy",
                    "reason": "AI 不能代替用户确认本机执行，请在动态节点中明确勾选确认"}
        return {"ok": False, "status": "unknown_tool", "error": name}
    except Exception as exc:
        return {"ok": False, "tool": name, "status": "tool_error", "error": str(exc)[:800]}


def _tool_result_message(tool_call: dict, result: dict) -> dict:
    return {"role": "tool", "tool_call_id": str(tool_call.get("id") or ""),
            "name": str((tool_call.get("function") or {}).get("name") or ""),
            "content": json.dumps(_bounded(result), ensure_ascii=False, separators=(",", ":"))[:12000]}


def run_analysis_agent(kind: str, target: str, cfg: dict, *, evidence: dict | None = None,
                       instruction: str = "", system_prompt: str = "",
                       max_rounds: int = 6) -> dict:
    """Run a bounded tool-calling loop and return the model conclusion plus trace."""
    allowed = _allowed_tool_names(kind)
    tool_set = [item for item in TOOL_DEFINITIONS
                if (item.get("function") or {}).get("name") in allowed]
    system = (system_prompt.strip() + "\n\n" if system_prompt.strip() else "") + (
        "你是 REVLab 的分析操作员。你可以调用工具读取当前样本证据，再给出结论。"
        "先调用最能减少不确定性的工具，不要凭经验猜地址或行为；每个结论必须引用工具名称。"
        "静态工具结果是 static，dynamic_run 返回的 completed 才是 runtime；blocked_by_policy/not_collected 只能写成缺失证据。"
        "PE、UE、Unity 类型不同就切换对应工具；不要把 Unity Mono 当 IL2CPP，也不要把 UE 候选 RVA 当运行时确认。"
        "最多进行有限轮次，最后只输出 JSON：summary、claims、evidence_refs、uncertainties、next_steps、runtime_hypotheses。"
    )
    initial = {
        "sample_type": kind,
        "target": Path(target).name if target else "",
        "instruction": instruction,
        "initial_evidence": _bounded(evidence or {}),
        "tool_policy": "工具路径已锁定到当前工作流目标；动态执行受策略控制",
    }
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": json.dumps(initial, ensure_ascii=False)}]
    trace = []
    rounds = 0
    try:
        while rounds < max(1, min(int(max_rounds or 6), 8)):
            rounds += 1
            raw = ai.chat_completion(cfg, messages, tools=tool_set, tool_choice="auto")
            message = (raw.get("choices") or [{}])[0].get("message") or {}
            calls = message.get("tool_calls") or []
            # Some providers use the legacy single function_call field.
            if not calls and message.get("function_call"):
                calls = [{"id": f"legacy-{rounds}", "function": message["function_call"]}]
            if not calls:
                content = message.get("content") or ""
                if isinstance(content, list):
                    content = "".join(str(part.get("text", "")) if isinstance(part, dict) else str(part)
                                      for part in content)
                return {"ok": True, "response": str(content)[:30000], "tool_trace": trace,
                        "tool_rounds": rounds, "model": cfg.get("model", ""),
                        "evidence_level": "ai_inferred", "validation_state": "ai_inferred"}
            assistant_message = {"role": "assistant", "content": message.get("content") or "",
                                 "tool_calls": calls}
            messages.append(assistant_message)
            for call in calls[:4]:
                function = call.get("function") or {}
                name = str(function.get("name") or "")
                try:
                    args = json.loads(function.get("arguments") or "{}")
                except (TypeError, ValueError):
                    args = {}
                if not isinstance(args, dict):
                    args = {}
                result = _execute_tool(name, args, kind=kind, target=target)
                trace.append({"tool": name, "arguments": _bounded(args), "result": _bounded(result)})
                messages.append(_tool_result_message(call, result))
        return {"ok": False, "error": "AI tool loop reached max_rounds", "tool_trace": trace,
                "tool_rounds": rounds, "evidence_level": "ai_inferred", "validation_state": "ai_inferred"}
    except Exception as exc:
        # A number of OpenAI-compatible gateways reject the optional tools
        # field.  Fall back to a single evidence-only completion, but expose
        # the limitation so the UI does not imply that tools were called.
        try:
            fallback_messages = list(messages[:2])
            fallback_messages.append({
                "role": "user",
                "content": "工具调用不可用，请仅根据已有证据输出最终 JSON，并明确列出需要补采的证据。",
            })
            content = ai.chat(cfg, fallback_messages)
            return {"ok": True, "response": content[:30000], "tool_trace": trace,
                    "tool_rounds": rounds, "tool_mode": "unsupported_fallback",
                    "warning": str(exc)[:500], "model": cfg.get("model", ""),
                    "evidence_level": "ai_inferred", "validation_state": "ai_inferred"}
        except Exception as fallback_exc:
            return {"ok": False, "error": str(fallback_exc)[:1000], "tool_trace": trace,
                    "tool_rounds": rounds, "tool_mode": "error",
                    "evidence_level": "ai_inferred", "validation_state": "ai_inferred"}
