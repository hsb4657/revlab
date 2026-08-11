"""图工作流管理与预置模板"""
from __future__ import annotations
import copy

from ..core.database import SessionLocal
from ..models.sample import GraphWorkflow, GraphTask
from . import definition as dfn
from .engine import start_engine


# ---------------------------------------------------------------- CRUD
def create_workflow(name: str, description: str = "", nodes=None, edges=None,
                    variables=None) -> dict:
    db = SessionLocal()
    try:
        if db.query(GraphWorkflow).filter(GraphWorkflow.name == name).first():
            raise ValueError(f"工作流 '{name}' 已存在")
        valid, errs = dfn.validate_graph(nodes or [], edges or [])
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
        if "nodes" in kw or "edges" in kw:
            nodes = kw.get("nodes", wf.nodes or [])
            edges = kw.get("edges", wf.edges or [])
            valid, errs = dfn.validate_graph(nodes, edges)
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
def create_task(wf_id: int, name: str = "", variables: dict = None) -> dict:
    db = SessionLocal()
    try:
        wf = db.query(GraphWorkflow).filter(GraphWorkflow.id == wf_id).first()
        if not wf:
            raise ValueError("工作流不存在")
        if not wf.enabled:
            raise ValueError("工作流已禁用")
        t = GraphTask(workflow_id=wf_id, name=name or wf.name,
                      status="pending", variables=dict(variables or {}),
                      node_states={})
        db.add(t)
        db.commit()
        return {"ok": True, "id": t.id}
    finally:
        db.close()


def run_task(task_id: int) -> dict:
    start_engine(task_id)
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
    """初始化预置图工作流模板(PE 全自动 / 引擎专项)。"""
    db = SessionLocal()
    try:
        def add(name, desc, nodes, edges, variables=None):
            if db.query(GraphWorkflow).filter(GraphWorkflow.name == name).first():
                return
            wf = GraphWorkflow(name=name, description=desc, nodes=nodes, edges=edges,
                               variables=variables or [], is_builtin=1)
            db.add(wf)

        # --- PE 全自动 ---
        add("pe-auto", "PE 全自动:识别→壳检测→(条件)脱壳→反汇编→报告",
            [
                _node("pe_identify", "PE 识别", "pe_identify", {"sample_path": "{{sample_path}}"}, 0, 0),
                _node("packer_detect", "壳检测", "packer_detect", {}, 260, 0),
                _node("cond_unpack", "是否加壳?", "condition", {"expression": "{{packer_detect.packed}} == true"}, 520, 0),
                _node("unpack", "自动脱壳", "unpack", {}, 780, 0),
                _node("disassemble", "反汇编入口", "disassemble", {"max_insns": 3000}, 1040, 0),
                _node("report", "聚合报告", "report", {}, 1300, 0),
            ],
            [
                _edge("e1", "pe_identify", "packer_detect"),
                _edge("e2", "packer_detect", "cond_unpack"),
                _edge("e3", "cond_unpack", "unpack", condition="{{packer_detect.packed}} == true"),
                _edge("e4", "cond_unpack", "disassemble", is_default=True),
                _edge("e5", "unpack", "disassemble"),
                _edge("e6", "disassemble", "report"),
            ],
            [{"key": "sample_path", "name": "样本路径", "type": "text", "default": "", "required": True,
              "source_type": "input"}],
        )

        # --- UE 引擎专项 ---
        add("ue-special", "UE 虚幻引擎专项:识别→(可选源码)→三大件→反射→加密解密→报告",
            [
                _node("pe_identify", "PE 识别", "pe_identify", {"sample_path": "{{sample_path}}"}, 0, 0),
                _node("ue_analyze", "UE 引擎分析", "ue_analyze", {"version": ""}, 300, 0),
                _node("report", "UE 专项报告", "report", {"title": "UE 分析报告"}, 600, 0),
            ],
            [
                _edge("e1", "pe_identify", "ue_analyze"),
                _edge("e2", "ue_analyze", "report"),
            ],
            [{"key": "sample_path", "name": "dump 后的 exe 路径", "type": "text", "default": "", "required": True,
              "source_type": "input"}],
        )

        # --- Unity 引擎专项 ---
        add("unity-special", "Unity 引擎专项:目录扫描→版本/构建类型→程序集→解密→SDK dump→报告",
            [
                _node("unity_analyze", "Unity 引擎分析", "unity_analyze", {"target_path": "{{target_path}}"}, 0, 0),
                _node("sdk_dump", "SDK Dump", "sdk_dump", {"target_path": ""}, 320, 0),
                _node("report", "Unity 专项报告", "report", {"title": "Unity 分析报告"}, 640, 0),
            ],
            [
                _edge("e1", "unity_analyze", "sdk_dump"),
                _edge("e2", "sdk_dump", "report"),
            ],
            [{"key": "target_path", "name": "游戏文件夹路径", "type": "text", "default": "", "required": True,
              "source_type": "input"}],
        )
        db.commit()
    finally:
        db.close()
