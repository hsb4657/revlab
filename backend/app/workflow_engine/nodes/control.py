"""控制/脚本/审批/报告节点"""
from __future__ import annotations
import subprocess
import sys
import tempfile
from pathlib import Path

from ...core.config import WORKSPACE_DIR, config
from .base import BaseNode, NodeResult, register


@register
class StartNode(BaseNode):
    node_type = "start"
    label = "工作流开始"
    icon = "▶"
    category = "控制"
    params_schema = []

    async def execute(self, ctx) -> NodeResult:
        return NodeResult(outputs={"started": True}, summary="工作流开始")


@register
class EndNode(BaseNode):
    node_type = "end"
    label = "工作流结束"
    icon = "■"
    category = "控制"
    params_schema = []

    async def execute(self, ctx) -> NodeResult:
        return NodeResult(outputs={"ended": True}, summary="工作流结束")


@register
class ConditionNode(BaseNode):
    node_type = "condition"
    label = "条件分支"
    icon = "🔀"
    category = "控制"
    params_schema = [
        {"key": "expression", "label": "条件表达式", "type": "text", "default": "", "required": True,
         "desc": "示例: {{packer_detect.packed}} == true  支持 == != > < >= <= AND OR NOT 括号"},
    ]

    async def execute(self, ctx) -> NodeResult:
        expr = ctx["params"].get("expression", "")
        from ..conditions import evaluate
        ok = evaluate(expr, ctx["pool"])
        return NodeResult(outputs={"result": ok, "expression": expr},
                          summary=f"{expr} → {ok}")


@register
class ScriptNode(BaseNode):
    node_type = "script"
    label = "脚本节点(Python/Bat)"
    icon = "🧩"
    category = "控制"
    risk_level = "dangerous"
    params_schema = [
        {"key": "lang", "label": "语言", "type": "select", "default": "python", "options": ["python", "bat"]},
        {"key": "script", "label": "脚本内容", "type": "textarea", "default": "", "required": True,
         "desc": "stdout 输出 <WF_VAR>key:value</WF_VAR> 可写入变量池"},
    ]

    async def execute(self, ctx) -> NodeResult:
        if not config.ENABLE_UNSAFE_NODES:
            return NodeResult(
                status="failed",
                error="脚本节点默认禁用；仅在隔离实验环境设置 REVLAB_ENABLE_UNSAFE_NODES=1 后可用",
            )
        lang = ctx["params"].get("lang", "python")
        script = ctx["params"].get("script", "")
        # 先解析占位符(把变量注入脚本文本)
        from ..variables import resolve
        rendered = resolve(script, ctx["pool"])
        workdir = str(WORKSPACE_DIR)
        Path(workdir).mkdir(parents=True, exist_ok=True)
        sp = ""
        try:
            if lang == "python":
                with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, dir=workdir, encoding="utf-8") as f:
                    f.write(rendered)
                    sp = f.name
                p = subprocess.run([sys.executable, sp], capture_output=True, text=True, timeout=120, cwd=workdir)
            else:
                with tempfile.NamedTemporaryFile("w", suffix=".bat", delete=False, dir=workdir, encoding="utf-8") as f:
                    f.write(rendered)
                    sp = f.name
                p = subprocess.run(["cmd", "/c", sp], capture_output=True, text=True, timeout=120, cwd=workdir)
        except subprocess.TimeoutExpired:
            return NodeResult(status="failed", error="脚本超时(120s)")
        except Exception as e:
            return NodeResult(status="failed", error=f"脚本执行失败: {e}")
        finally:
            if sp:
                Path(sp).unlink(missing_ok=True)
        stdout = (p.stdout or "")[:50000]
        # 解析 <WF_VAR>key:value</WF_VAR>
        outputs = {}
        import re
        for m in re.finditer(r"<WF_VAR>\s*([^:\n]+)\s*:\s*(.*?)</WF_VAR>", stdout, re.S):
            outputs[m.group(1).strip()] = m.group(2).strip()
        summary = ""
        m = re.search(r"<script_out>(.*?)</script_out>", stdout, re.S)
        if m:
            summary = m.group(1).strip()
        return NodeResult(status="success" if p.returncode == 0 else "failed",
                          outputs={**outputs, "stdout": stdout[:20000],
                                   "exit_code": p.returncode},
                          summary=summary or f"脚本退出码 {p.returncode}",
                          error="" if p.returncode == 0 else (p.stderr or "")[:500])


@register
class CommandNode(BaseNode):
    node_type = "command"
    label = "自定义命令"
    icon = "⌘"
    category = "自定义"
    risk_level = "dangerous"
    params_schema = [
        {"key": "command", "label": "命令", "type": "text", "default": "", "required": True,
         "desc": "支持 {{变量}} 占位符; stdout 中的结果会写入变量池"},
        {"key": "cwd", "label": "工作目录", "type": "text", "default": "", "required": False},
        {"key": "timeout", "label": "超时(秒)", "type": "number", "default": 120},
    ]

    async def execute(self, ctx) -> NodeResult:
        if not config.ENABLE_UNSAFE_NODES:
            return NodeResult(
                status="failed",
                error="自定义命令默认禁用；仅在隔离实验环境设置 REVLAB_ENABLE_UNSAFE_NODES=1 后可用",
            )
        from ...core.config import BASE_DIR
        from ..variables import resolve
        command = resolve(str(ctx["params"].get("command", "")), ctx["pool"])
        if not command.strip():
            return NodeResult(status="failed", error="命令不能为空")
        cwd = resolve(str(ctx["params"].get("cwd", "") or ""), ctx["pool"]) or str(BASE_DIR)
        timeout = max(1, int(ctx["params"].get("timeout", 120) or 120))
        try:
            p = subprocess.run(command, shell=True, cwd=cwd, capture_output=True,
                               text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return NodeResult(status="failed", error=f"命令超时({timeout}s)")
        except Exception as exc:
            return NodeResult(status="failed", error=f"命令执行失败: {exc}")
        stdout = (p.stdout or "")[:50000]
        stderr = (p.stderr or "")[:5000]
        return NodeResult(status="success" if p.returncode == 0 else "failed",
                          outputs={"stdout": stdout, "stderr": stderr, "exit_code": p.returncode},
                          summary=f"命令退出码 {p.returncode}",
                          error=stderr if p.returncode else "")


@register
class ApprovalNode(BaseNode):
    node_type = "approval"
    label = "人工审批"
    icon = "🛡️"
    category = "控制"
    params_schema = [
        {"key": "message", "label": "审批提示", "type": "text", "default": "确认继续执行下一步?", "required": False},
    ]

    async def execute(self, ctx) -> NodeResult:
        # 引擎会在执行前将节点置为 waiting_approval 并调用 ctx["approval_callback"]
        message = ctx["params"].get("message", "确认继续执行下一步?")
        decision = ctx.get("approval_decision")
        if decision is None:
            # 不应到达;引擎层会挂起
            return NodeResult(status="failed", error="审批未完成")
        return NodeResult(outputs={"approved": bool(decision.get("approved")),
                                   "reason": decision.get("reason", "")},
                          summary="已批准" if decision.get("approved") else f"已驳回: {decision.get('reason','')}")


@register
class ReportNode(BaseNode):
    node_type = "report"
    label = "聚合报告"
    icon = "📄"
    category = "输出"
    params_schema = [
        {"key": "title", "label": "报告标题", "type": "text", "default": "REVLab 分析报告"},
    ]

    async def execute(self, ctx) -> NodeResult:
        from ...services import report as report_svc
        # 汇总变量池中所有节点的 summary
        pool = ctx["pool"]
        sections = []
        ai_outputs = {}
        for k, v in pool.items():
            if isinstance(v, dict):
                if v.get("__summary"):
                    sections.append({"key": k, "summary": v["__summary"]})
                if v.get("ai_output"):
                    ai_outputs[k] = {kk: vv for kk, vv in v.items() if not str(kk).startswith("__")}
        payload = {"workflow_summary": sections, "variables": {k: v for k, v in pool.items()
                                                               if not str(k).startswith("_") and isinstance(v, (str, int, float, bool))}}
        if ai_outputs:
            payload["ai_outputs"] = ai_outputs
        title = ctx["params"].get("title", "REVLab 分析报告")
        source = str(ctx["params"].get("sample_path") or ctx["params"].get("target_path") or "")
        if not source:
            for value in pool.values():
                if not isinstance(value, dict):
                    continue
                source = str(value.get("sample_path") or value.get("target_path") or value.get("file_name") or "")
                if source:
                    break
        source_name = Path(source).name if source else str(title)
        payload["title"] = title
        # Every graph run owns one portable artifact directory.  Keep direct
        # node callers usable with the configured root fallback.
        output_root = ctx.get("output_dir")
        if output_root:
            out = Path(str(output_root)) / "report"
        else:
            from ...core.config import config
            out = config.OUTPUT_ROOT / "runs" / f"task_{ctx.get('task_id', 'adhoc')}" / "report"
        out.mkdir(parents=True, exist_ok=True)
        report_name = report_svc.analysis_report_name(source_name, "analysis")
        paths = report_svc.save_report({"sample": {"file_name": source_name},
                                        "analysis": {"workflow": payload}},
                                       out, report_name)
        return NodeResult(outputs={"report_paths": paths, "sections": sections,
                                   "report_name": report_name, "source_name": source_name},
                          summary=f"报告已生成: {paths.get('html','')}")
