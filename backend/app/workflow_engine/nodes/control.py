"""控制/脚本/审批/报告节点"""
from __future__ import annotations
import subprocess
import tempfile
from pathlib import Path

from ...core.config import WORKSPACE_DIR
from .base import BaseNode, NodeResult, register


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
    params_schema = [
        {"key": "lang", "label": "语言", "type": "select", "default": "python", "options": ["python", "bat"]},
        {"key": "script", "label": "脚本内容", "type": "textarea", "default": "", "required": True,
         "desc": "stdout 输出 <WF_VAR>key:value</WF_VAR> 可写入变量池"},
    ]

    async def execute(self, ctx) -> NodeResult:
        lang = ctx["params"].get("lang", "python")
        script = ctx["params"].get("script", "")
        # 先解析占位符(把变量注入脚本文本)
        from ..variables import resolve
        rendered = resolve(script, ctx["pool"])
        workdir = str(WORKSPACE_DIR)
        Path(workdir).mkdir(parents=True, exist_ok=True)
        try:
            if lang == "python":
                with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, dir=workdir, encoding="utf-8") as f:
                    f.write(rendered)
                    sp = f.name
                p = subprocess.run(["python", sp], capture_output=True, text=True, timeout=120, cwd=workdir)
            else:
                with tempfile.NamedTemporaryFile("w", suffix=".bat", delete=False, dir=workdir, encoding="utf-8") as f:
                    f.write(rendered)
                    sp = f.name
                p = subprocess.run(["cmd", "/c", sp], capture_output=True, text=True, timeout=120, cwd=workdir)
            Path(sp).unlink(missing_ok=True)
        except subprocess.TimeoutExpired:
            return NodeResult(status="failed", error="脚本超时(120s)")
        except Exception as e:
            return NodeResult(status="failed", error=f"脚本执行失败: {e}")
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
        from ...core.config import REPORTS_DIR
        # 汇总变量池中所有节点的 summary
        pool = ctx["pool"]
        sections = []
        for k, v in pool.items():
            if isinstance(v, dict) and v.get("__summary"):
                sections.append({"key": k, "summary": v["__summary"]})
        payload = {"workflow_summary": sections, "variables": {k: v for k, v in pool.items()
                                                               if not str(k).startswith("_") and isinstance(v, (str, int, float, bool))}}
        name = ctx["params"].get("title", "REVLab 分析报告")
        out = REPORTS_DIR / "wf"
        out.mkdir(parents=True, exist_ok=True)
        paths = report_svc.save_report({"sample": {"file_name": name},
                                        "analysis": {"workflow": payload}},
                                       out, f"wf_{ctx['task_id']}")
        return NodeResult(outputs={"report_paths": paths, "sections": sections},
                          summary=f"报告已生成: {paths.get('html','')}")
