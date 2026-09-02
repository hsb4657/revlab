"""图工作流管理与预置模板"""
from __future__ import annotations
import copy
import hashlib
import json

from ..core.database import SessionLocal
from ..models.sample import GraphWorkflow, GraphTask, Sample
from . import definition as dfn
from .engine import start_engine


# ---------------------------------------------------------------- CRUD
def create_workflow(name: str, description: str = "", nodes=None, edges=None,
                    variables=None) -> dict:
    db = SessionLocal()
    try:
        if db.query(GraphWorkflow).filter(GraphWorkflow.name == name).first():
            raise ValueError(f"工作流 '{name}' 已存在")
        valid, errs = dfn.validate_graph(nodes or [], edges or [], variables or [])
        if not valid:
            raise ValueError("; ".join(errs))
        wf = GraphWorkflow(name=name, description=description, nodes=nodes or [],
                           edges=edges or [], variables=variables or [])
        db.add(wf)
        db.commit()
        return {"ok": True, "id": wf.id}
    finally:
        db.close()


def update_workflow(wf_id: int, **kw) -> dict:
    db = SessionLocal()
    try:
        wf = db.query(GraphWorkflow).filter(GraphWorkflow.id == wf_id).first()
        if not wf:
            raise ValueError("工作流不存在")
        if "nodes" in kw or "edges" in kw or "variables" in kw:
            nodes = kw.get("nodes", wf.nodes or [])
            edges = kw.get("edges", wf.edges or [])
            valid, errs = dfn.validate_graph(nodes, edges, kw.get("variables", wf.variables or []))
            if not valid:
                raise ValueError("; ".join(errs))
        for k in ("name", "description", "nodes", "edges", "variables", "enabled"):
            if k in kw:
                setattr(wf, k, kw[k])
        db.commit()
        return {"ok": True, "id": wf_id}
    finally:
        db.close()


def delete_workflow(wf_id: int) -> bool:
    db = SessionLocal()
    try:
        wf = db.query(GraphWorkflow).filter(GraphWorkflow.id == wf_id).first()
        if not wf:
            return False
        db.delete(wf)
        db.commit()
        return True
    finally:
        db.close()


def list_workflows() -> list:
    db = SessionLocal()
    try:
        rows = db.query(GraphWorkflow).order_by(GraphWorkflow.id).all()
        return [{"id": w.id, "name": w.name, "description": w.description,
                 "node_count": len(w.nodes or []), "edge_count": len(w.edges or []),
                 "is_builtin": w.is_builtin, "enabled": w.enabled,
                 "variables": w.variables or [],
                 "created_at": w.created_at.isoformat() + "Z" if w.created_at else None}
                for w in rows]
    finally:
        db.close()


def get_workflow(wf_id: int) -> dict | None:
    db = SessionLocal()
    try:
        w = db.query(GraphWorkflow).filter(GraphWorkflow.id == wf_id).first()
        if not w:
            return None
        return {"id": w.id, "name": w.name, "description": w.description,
                "nodes": w.nodes or [], "edges": w.edges or [], "variables": w.variables or [],
                "is_builtin": w.is_builtin, "enabled": w.enabled}
    finally:
        db.close()


# ---------------------------------------------------------------- tasks
def _workflow_snapshot(workflow: GraphWorkflow) -> tuple[dict, str]:
    """Freeze the executable graph so task history stays reproducible."""
    snapshot = {
        "schema": "revlab.graph-workflow/v1",
        "name": workflow.name,
        "description": workflow.description,
        "nodes": copy.deepcopy(workflow.nodes or []),
        "edges": copy.deepcopy(workflow.edges or []),
        "variables": copy.deepcopy(workflow.variables or []),
    }
    encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return snapshot, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def create_task(wf_id: int, name: str = "", variables: dict = None,
                sample_id: int = 0) -> dict:
    db = SessionLocal()
    try:
        wf = db.query(GraphWorkflow).filter(GraphWorkflow.id == wf_id).first()
        if not wf:
            raise ValueError("工作流不存在")
        if not wf.enabled:
            raise ValueError("工作流已禁用")
        runtime_variables = dict(variables or {})
        if sample_id:
            sample = db.query(Sample).filter(Sample.id == int(sample_id)).first()
            if not sample:
                raise ValueError("样本不存在")
            runtime_variables.setdefault("sample_id", sample.id)
            runtime_variables.setdefault("sample_path", sample.stored_path)
        for spec in (wf.variables or []):
            key = spec.get("key")
            if not key:
                continue
            if key not in runtime_variables:
                runtime_variables[key] = spec.get("default")
            value = runtime_variables.get(key)
            if spec.get("required") and (value is None or value == ""):
                raise ValueError(f"运行变量缺少必填值: {key}")
            vtype = spec.get("type", "text")
            if vtype == "bool" and isinstance(value, str):
                runtime_variables[key] = value.strip().lower() in {"1", "true", "yes", "on"}
            elif vtype == "number" and value not in (None, ""):
                runtime_variables[key] = float(value) if "." in str(value) else int(value)
        snapshot, workflow_version = _workflow_snapshot(wf)
        t = GraphTask(workflow_id=wf_id, sample_id=int(sample_id or 0),
                      workflow_version=workflow_version, definition_snapshot=snapshot,
                      name=name or wf.name, status="pending", status_version=0,
                      cancel_requested=0, variables=runtime_variables, node_states={})
        db.add(t)
        db.commit()
        return {"ok": True, "id": t.id}
    finally:
        db.close()


def run_task(task_id: int) -> dict:
    db = SessionLocal()
    try:
        task = db.query(GraphTask).filter(GraphTask.id == task_id).first()
        if not task:
            raise ValueError("任务不存在")
        if task.status not in ("pending", "stopped", "failed"):
            raise ValueError(f"任务当前状态不允许启动: {task.status}")
        task.cancel_requested = 0
        task.status = "pending"
        task.status_version = (task.status_version or 0) + 1
        db.commit()
    finally:
        db.close()
    if not start_engine(task_id):
        db = SessionLocal()
        try:
            task = db.query(GraphTask).filter(GraphTask.id == task_id).first()
            if task and task.status == "pending" and not task.cancel_requested:
                task.status = "running"
                db.commit()
        finally:
            db.close()
        raise ValueError("任务已经在运行")
    return {"ok": True, "status": "started"}


def list_tasks(wf_id: int = None, limit: int = 100) -> list:
    db = SessionLocal()
    try:
        q = db.query(GraphTask)
        if wf_id:
            q = q.filter(GraphTask.workflow_id == wf_id)
        rows = q.order_by(GraphTask.id.desc()).limit(limit).all()
        return [{"id": t.id, "workflow_id": t.workflow_id, "name": t.name,
                 "status": t.status, "error": t.error,
                 "node_states": t.node_states or {},
                 "variables": t.variables or {},
                 "sample_id": t.sample_id or 0, "workflow_version": t.workflow_version,
                 "created_at": t.created_at.isoformat() + "Z" if t.created_at else None}
                for t in rows]
    finally:
        db.close()


def list_sample_tasks(sample_id: int, limit: int = 100) -> list:
    db = SessionLocal()
    try:
        rows = db.query(GraphTask).filter(GraphTask.sample_id == sample_id) \
            .order_by(GraphTask.id.desc()).limit(limit).all()
        return [{"id": t.id, "workflow_id": t.workflow_id, "sample_id": t.sample_id or 0,
                 "name": t.name, "status": t.status, "error": t.error,
                 "node_states": t.node_states or {}, "variables": t.variables or {},
                 "workflow_version": t.workflow_version,
                 "heartbeat_at": t.heartbeat_at.isoformat() + "Z" if t.heartbeat_at else None,
                 "created_at": t.created_at.isoformat() + "Z" if t.created_at else None}
                for t in rows]
    finally:
        db.close()


def get_task(task_id: int) -> dict | None:
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == task_id).first()
        if not t:
            return None
        return {"id": t.id, "workflow_id": t.workflow_id, "name": t.name,
                "status": t.status, "error": t.error,
                "node_states": t.node_states or {}, "variables": t.variables or {},
                "sample_id": t.sample_id or 0, "workflow_version": t.workflow_version,
                "heartbeat_at": t.heartbeat_at.isoformat() + "Z" if t.heartbeat_at else None,
                "created_at": t.created_at.isoformat() + "Z" if t.created_at else None}
    finally:
        db.close()


# ---------------------------------------------------------------- builtin templates
def _node(nid, label, ntype, params=None, x=0, y=0):
    return {"id": nid, "label": label, "type": ntype, "params": params or {}, "x": x, "y": y}


def _edge(eid, frm, to, condition=None, is_default=None):
    e = {"id": eid, "from": frm, "to": to}
    if condition:
        e["condition"] = condition
    if is_default:
        e["is_default"] = True
    return e


def init_builtin_templates():
    """Create or upgrade the three built-in executable workflow templates."""
    db = SessionLocal()
    try:
        def upsert(name, desc, nodes, edges, variables):
            valid, errors = dfn.validate_graph(nodes, edges, variables)
            if not valid:
                raise ValueError(f"invalid built-in workflow {name}: {'; '.join(errors)}")
            workflow = db.query(GraphWorkflow).filter(GraphWorkflow.name == name).first()
            if workflow is None:
                workflow = GraphWorkflow(name=name, is_builtin=1)
                db.add(workflow)
            workflow.description = desc
            workflow.nodes = copy.deepcopy(nodes)
            workflow.edges = copy.deepcopy(edges)
            workflow.variables = copy.deepcopy(variables)
            workflow.is_builtin = 1
            workflow.enabled = 1

        upsert(
            "pe-auto",
            "PE 分层分析:静态识别→多壳/保护证据矩阵→策略分派(专用解包/内存转储/人工复核)→反汇编→Ghidra→报告",
            [
                _node("pe_identify", "PE 静态识别", "pe_identify", {"sample_path": "{{sample_path}}"}, 0, 120),
                _node("packer_detect", "壳与保护检测", "packer_detect", {}, 260, 40),
                _node("strings", "字符串与 PDB", "strings", {"min_len": 6, "interesting_only": False}, 260, 220),
                _node("pe_protection_matrix", "多壳/保护证据矩阵", "pe_protection_matrix", {"sample_path": "{{sample_path}}"}, 540, 40),
                _node("pe_unpack_strategy", "脱壳策略分派", "pe_unpack_strategy", {"sample_path": "{{sample_path}}"}, 800, 40),
                _node("cond_unpack_strategy", "是否使用专用解包", "condition", {}, 1060, 40),
                _node("unpack", "专用解包并验证产物", "unpack", {}, 1320, 0),
                _node("cond_dynamic", "是否需要内存转储", "condition", {}, 1320, 150),
                _node("approval", "内存转储/动态分析确认", "approval", {"message": "确认开始内存转储或动态行为分析"}, 1580, 150),
                _node("dynamic", "内存转储/动态行为分析", "dynamic_analyze", {
                    "timeout": 60, "capture_network": True,
                    "capture_memory_dump": True, "dump_delay_seconds": 2,
                }, 1840, 150),
                _node("disassemble", "反汇编与入口分析", "disassemble", {"max_insns": 3000}, 1580, 20),
                _node("decompile", "Ghidra 反编译", "decompile", {"max_functions": 200}, 1840, 20),
                _node("pe_ai_assist", "PE AI 辅助(壳/可疑点/建议)", "pe_ai_assist", {"sample_path": "{{sample_path}}"}, 2100, -120),
                _node("report", "证据聚合报告", "report", {"title": "PE 分层分析报告", "sample_path": "{{sample_path}}"}, 2360, 20),
            ],
            [
                _edge("pe_e1", "pe_identify", "packer_detect"),
                _edge("pe_e2", "pe_identify", "strings"),
                _edge("pe_e3", "packer_detect", "pe_protection_matrix"),
                _edge("pe_e4", "pe_protection_matrix", "pe_unpack_strategy"),
                _edge("pe_e5", "pe_unpack_strategy", "cond_unpack_strategy"),
                _edge("pe_e6", "cond_unpack_strategy", "unpack", condition="{{pe_unpack_strategy.selected_strategy}} == \"known_unpacker\""),
                _edge("pe_e7", "cond_unpack_strategy", "cond_dynamic", is_default=True),
                _edge("pe_e8", "unpack", "disassemble"),
                _edge("pe_e9", "cond_dynamic", "approval", condition="{{pe_unpack_strategy.selected_strategy}} == \"memory_dump\""),
                _edge("pe_e10", "cond_dynamic", "disassemble", is_default=True),
                _edge("pe_e11", "approval", "dynamic"),
                _edge("pe_e12", "dynamic", "disassemble"),
                _edge("pe_e13", "disassemble", "decompile"),
                _edge("pe_e14", "decompile", "pe_ai_assist"),
                _edge("pe_e14b", "pe_ai_assist", "report"),
                _edge("pe_e15", "strings", "report"),
            ],
            [
                {"key": "sample_path", "name": "样本路径", "type": "text", "default": "", "required": True, "source_type": "input"},
                {"key": "run_dynamic", "name": "执行动态分析", "type": "bool", "default": False, "required": False, "source_type": "input"},
            ],
        )

        upsert(
            "ue-special",
            "UE 专项:PE/Dump 基线→UE4/UE5 版本→字符串/RIP 全局候选→三大件→FName/GetName XOR→反射结构/偏移→保护/加密分支→运行时验证计划→报告",
            [
                _node("pe_identify", "PE 与 Dump 基线", "pe_identify", {"sample_path": "{{sample_path}}"}, 0, 100),
                _node("strings", "UE 字符串与符号线索", "strings", {"min_len": 5, "interesting_only": False}, 280, 220),
                _node("ue_version", "UE 版本与引擎家族", "ue_version", {"sample_path": "{{sample_path}}", "version": "{{ue_version}}"}, 560, 40),
                _node("ue_static_evidence", "字符串引用与 RIP 全局候选", "ue_static_evidence", {"sample_path": "{{sample_path}}"}, 820, 220),
                _node("ue_globals", "GObjects / GNames / GWorld / GEngine", "ue_globals", {"sample_path": "{{sample_path}}"}, 1100, 40),
                _node("ue_fname", "FName / GNames 算法候选(UE4/UE5)", "ue_fname", {"sample_path": "{{sample_path}}"}, 1380, 40),
                _node("ue_getname_xor", "GetName XOR / 明文候选", "ue_getname_xor", {"sample_path": "{{sample_path}}"}, 1660, 220),
                _node("ue_reflection", "反射结构与字段偏移候选", "ue_reflection", {"sample_path": "{{sample_path}}"}, 1940, 40),
                _node("ue_protection", "壳与保护信号矩阵", "ue_protection", {"sample_path": "{{sample_path}}"}, 2220, 40),
                _node("cond_encryption", "是否需要解密证据", "condition", {}, 2500, 40),
                _node("ue_encryption", "加密/解密状态与校验计划", "ue_encryption", {"sample_path": "{{sample_path}}"}, 2780, 0),
                _node("ue_runtime_validation", "静态边界与运行时验证清单", "ue_runtime_validation", {"sample_path": "{{sample_path}}"}, 3060, 0),
                _node("ue_ai_assist", "UE AI 辅助(三大件精确地址/GetName/解密算法)", "ue_ai_assist", {"sample_path": "{{sample_path}}"}, 3340, 260),
                _node("report", "UE 结构化证据报告", "ue_report", {"title": "UE 专项分析报告", "sample_path": "{{sample_path}}"}, 3620, 120),
                _node("delivery_gate", "UE 报告文件最终交付门禁", "ue_delivery_gate", {}, 3900, 120),
                _node("delivery_complete", "UE 报告交付完成", "end", {}, 4180, 120),
            ],
            [
                _edge("ue_e1", "pe_identify", "strings"),
                _edge("ue_e2", "pe_identify", "ue_version"),
                _edge("ue_e3", "strings", "report"),
                _edge("ue_e4", "ue_version", "ue_static_evidence"),
                _edge("ue_e4b", "ue_static_evidence", "ue_globals"),
                _edge("ue_e5", "ue_globals", "ue_fname"),
                _edge("ue_e6", "ue_fname", "ue_getname_xor"),
                _edge("ue_e6b", "ue_getname_xor", "ue_reflection"),
                _edge("ue_e7", "ue_reflection", "ue_protection"),
                _edge("ue_e8", "ue_protection", "cond_encryption"),
                _edge("ue_e9", "cond_encryption", "ue_encryption", condition="{{ue_protection.needs_decryption}} == true"),
                _edge("ue_e10", "cond_encryption", "ue_runtime_validation", is_default=True),
                _edge("ue_e11", "ue_encryption", "ue_runtime_validation"),
                _edge("ue_e12", "ue_runtime_validation", "ue_ai_assist"),
                _edge("ue_e12b", "ue_ai_assist", "report"),
                _edge("ue_e13", "report", "delivery_gate"),
                _edge("ue_e14", "delivery_gate", "delivery_complete"),
            ],
            [
                {"key": "sample_path", "name": "Dump 后的 EXE 路径", "type": "text", "default": "", "required": True, "source_type": "input"},
                {"key": "ue_version", "name": "UE 版本(留空自动识别)", "type": "text", "default": "", "required": False, "source_type": "input"},
            ],
        )

        upsert(
            "unity-special",
            "Unity 专项:识别→候选/分片→Loader→恢复→结构验证→SDK→报告→严格交付门禁",
            [
                _node("unity_scan", "Unity 目录、版本与构建识别", "unity_scan", {"target_path": "{{target_path}}", "version": "{{unity_version}}"}, 0, 100),
                _node("unity_assembly", "程序集与关键文件定位", "unity_assembly", {"target_path": "{{unity_scan.target_path}}", "version": "{{unity_version}}"}, 300, 100),
                _node("cond_il2cpp", "是否为 IL2CPP", "condition", {}, 620, 100),
                _node("metadata_candidates", "Metadata 候选、分片与保护形态", "unity_metadata_candidates", {"target_path": "{{unity_assembly.target_path}}"}, 900, 0),
                _node("loader_analysis", "Loader、解密模块与恢复策略", "unity_loader_analysis", {"target_path": "{{unity_assembly.target_path}}"}, 1200, 0),
                _node("unity_metadata", "Metadata 静态恢复/必要时运行时采集", "unity_metadata", {"target_path": "{{unity_assembly.target_path}}", "version": "{{unity_version}}"}, 1500, 0),
                _node("metadata_validation", "Header、表边界与重复哈希验证", "unity_metadata_validation", {"target_path": "{{unity_metadata.target_path}}"}, 1800, 0),
                _node("cond_metadata_ready", "Metadata 是否已验证", "condition", {}, 2100, 0),
                _node("sdk_dump", "IL2CPP SDK 交付(Dump.cs / DLL / JSON / C++)", "sdk_dump", {"target_path": "{{unity_metadata.target_path}}"}, 2400, -80),
                _node("unity_ai_assist", "Unity AI 辅助(构建/SDK/风险)", "unity_ai_assist", {"target_path": "{{target_path}}"}, 2700, -220),
                _node("report", "Unity 结构化证据报告与根目录 Markdown", "unity_report", {"title": "Unity 专项分析报告", "target_path": "{{target_path}}"}, 3000, 80),
                _node("delivery_gate", "Metadata + SDK + DLL + Markdown 最终门禁", "unity_delivery_gate", {}, 3300, 80),
                _node("delivery_complete", "Unity 交付完成", "end", {}, 3600, 80),
            ],
            [
                _edge("unity_e1", "unity_scan", "unity_assembly"),
                _edge("unity_e2", "unity_assembly", "cond_il2cpp"),
                _edge("unity_e3", "cond_il2cpp", "metadata_candidates", condition="{{unity_assembly.build_type}} == \"IL2CPP\""),
                _edge("unity_e4", "cond_il2cpp", "report", is_default=True),
                _edge("unity_e5", "metadata_candidates", "loader_analysis"),
                _edge("unity_e5b", "loader_analysis", "unity_metadata"),
                _edge("unity_e5c", "unity_metadata", "metadata_validation"),
                _edge("unity_e5d", "metadata_validation", "cond_metadata_ready"),
                _edge("unity_e6", "cond_metadata_ready", "sdk_dump", condition="{{metadata_validation.metadata_verified}} == true"),
                _edge("unity_e7", "cond_metadata_ready", "unity_ai_assist", is_default=True),
                _edge("unity_e8", "sdk_dump", "unity_ai_assist"),
                _edge("unity_e8b", "unity_ai_assist", "report"),
                _edge("unity_e9", "report", "delivery_gate"),
                _edge("unity_e10", "delivery_gate", "delivery_complete"),
            ],
            [
                {"key": "target_path", "name": "游戏文件夹路径", "type": "text", "default": "", "required": True, "source_type": "input"},
                {"key": "unity_version", "name": "Unity 版本(留空自动识别)", "type": "text", "default": "", "required": False, "source_type": "input"},
            ],
        )
        db.commit()
    finally:
        db.close()
