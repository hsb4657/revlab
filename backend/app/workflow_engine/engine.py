"""图工作流执行引擎:状态机调度、条件分支、失败策略、审批挂起、单节点重跑/跳过"""
from __future__ import annotations
import copy
import logging
import threading
import time
from datetime import datetime

from ..core.database import SessionLocal
from ..models.sample import GraphTask, GraphWorkflow
from . import definition as dfn
from .conditions import evaluate
from .nodes.base import get_node_class
from .variables import resolve, collect_outputs, unresolved_keys

log = logging.getLogger("revlab.wfengine")

# 审批等待注册: {(task_id, node_id): threading.Event}
_pending_approvals = {}
_lock = threading.Lock()


def _now():
    return datetime.utcnow().isoformat() + "Z"


class Engine:
    def __init__(self, task_id: int):
        self.task_id = task_id
        self._stop = threading.Event()

    # ------------------------------------------------------------- helpers
    def _task(self):
        db = SessionLocal()
        try:
            return db.query(GraphTask).filter(GraphTask.id == self.task_id).first()
        finally:
            db.close()

    def _workflow(self, wf_id: int):
        db = SessionLocal()
        try:
            return db.query(GraphWorkflow).filter(GraphWorkflow.id == wf_id).first()
        finally:
            db.close()

    def _load_state(self) -> tuple:
        db = SessionLocal()
        try:
            t = db.query(GraphTask).filter(GraphTask.id == self.task_id).first()
            wf = db.query(GraphWorkflow).filter(GraphWorkflow.id == t.workflow_id).first()
            return (copy.deepcopy(t.node_states or {}), copy.deepcopy(t.variables or {}),
                    copy.deepcopy(wf.nodes or []), copy.deepcopy(wf.edges or []))
        finally:
            db.close()

    def _save(self, node_states: dict, variables: dict, status: str = None, error: str = ""):
        db = SessionLocal()
        try:
            t = db.query(GraphTask).filter(GraphTask.id == self.task_id).first()
            t.node_states = node_states
            t.variables = variables
            if status:
                t.status = status
            if error:
                t.error = error
            db.commit()
        finally:
            db.close()

    def _set_node(self, node_states: dict, nid: str, status: str, outputs=None, error=""):
        st = node_states.setdefault(nid, {"status": dfn.NODE_PENDING, "attempts": 0, "outputs": {}, "error": ""})
        st["status"] = status
        if outputs is not None:
            st["outputs"] = outputs
        if error:
            st["error"] = error
        if status in (dfn.NODE_COMPLETED, dfn.NODE_SKIPPED):
            st["error"] = ""
        if status == dfn.NODE_RUNNING and not st.get("started_at"):
            st["started_at"] = _now()
        if status in (dfn.NODE_COMPLETED, dfn.NODE_FAILED, dfn.NODE_SKIPPED):
            st["finished_at"] = _now()

    # ------------------------------------------------------------- run
    def run(self):
        node_states, variables, nodes, edges = self._load_state()
        node_map = {n["id"]: n for n in nodes}
        plan = dfn.build_execution_plan(nodes, edges)
        self._save(node_states, variables, status="running")

        # 先标记所有节点 pending
        for n in nodes:
            if n["id"] not in node_states:
                self._set_node(node_states, n["id"], dfn.NODE_PENDING)

        skipped = set()      # 条件分支未选中的节点
        visited = set()
        try:
            for nid in plan:
                if self._stop.is_set():
                    self._save(node_states, variables, status="stopped")
                    return {"ok": True, "status": "stopped"}
                if nid in visited or nid in skipped:
                    continue
                node = node_map.get(nid)
                if node is None:
                    continue
                ntype = node.get("type")

                # 条件节点:选分支
                if ntype == "condition":
                    self._set_node(node_states, nid, dfn.NODE_RUNNING)
                    self._save(node_states, variables)
                    expr = node.get("params", {}).get("expression", "")
                    chosen = self._choose_branch(node, expr, edges, variables)
                    self._set_node(node_states, nid, dfn.NODE_COMPLETED,
                                   outputs={"chosen": chosen})
                    visited.add(nid)
                    # 其它出边目标标记 skipped(含下游唯一可达)
                    outs = [e.get("to") for e in edges if e.get("from") == nid]
                    for to in outs:
                        if to != chosen:
                            skips = self._mark_subtree_skipped(node_states, to, edges, node_map, plan)
                            skipped.update(skips)
                    continue

                # 解析参数占位符
                params = dict(node.get("params") or {})
                unresolved = []
                for k, v in params.items():
                    if isinstance(v, str) and "{{" in v:
                        rv = resolve(v, variables)
                        if "{{" in rv:
                            unresolved.append(k)
                        params[k] = rv
                if unresolved:
                    raise RuntimeError(f"节点 {nid} 参数未解析的变量: {unresolved}")

                # 审批节点:挂起等待
                if ntype == "approval":
                    self._set_node(node_states, nid, dfn.NODE_WAITING_APPROVAL)
                    self._save(node_states, variables)
                    decision = self._wait_approval(nid)
                    if decision is None:
                        raise RuntimeError("审批未完成(任务停止)")
                    node_states, variables, _, _ = self._load_state()
                    self._set_node(node_states, nid, dfn.NODE_COMPLETED,
                                   outputs={"approved": bool(decision.get("approved")),
                                            "reason": decision.get("reason", "")})
                    if not decision.get("approved"):
                        # 驳回:回滚到上一个已完成节点重跑(简化:标记失败提示)
                        raise RuntimeError(f"审批驳回: {decision.get('reason','')}")
                    visited.add(nid)
                    continue

                # 普通节点执行
                self._set_node(node_states, nid, dfn.NODE_RUNNING)
                self._save(node_states, variables)
                result = self._execute_node(node, params, variables)
                if result is None:
                    # 重试/跳过策略由 _execute_node 处理
                    if node_states.get(nid, {}).get("status") == dfn.NODE_SKIPPED:
                        visited.add(nid)
                        continue
                    self._save(node_states, variables, status="failed")
                    return {"ok": False, "error": f"节点 {nid} 失败"}
                outputs = result.get("outputs") or {}
                outputs["__summary"] = result.get("summary", "")
                variables = collect_outputs(nid, outputs, variables)
                self._set_node(node_states, nid, dfn.NODE_COMPLETED, outputs=outputs)
                visited.add(nid)
                self._save(node_states, variables)

            self._save(node_states, variables, status="completed")
            return {"ok": True, "status": "completed"}
        except Exception as e:
            log.exception("wf task %s failed", self.task_id)
            self._save(node_states, variables, status="failed", error=str(e))
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------- execute node
    def _execute_node(self, node: dict, params: dict, variables: dict) -> dict | None:
        ntype = node.get("type")
        cls = get_node_class(ntype)
        if cls is None:
            raise RuntimeError(f"未知节点类型: {ntype}")
        import asyncio
        ctx = {"node": node, "params": params, "pool": variables,
               "task_id": self.task_id, "approval_callback": self._approval_cb}
        try:
            res = asyncio.run(cls().execute(ctx))
        except Exception as e:
            res = None
            log.exception("node %s execute error", node.get("id"))
            # 失败策略
            on_fail = node.get("params", {}).get("on_fail", "abort")
            retry_count = int(node.get("params", {}).get("retry_count", 0) or 0)
            node_states, variables2, _, _ = self._load_state()
            st = node_states.setdefault(node.get("id"), {})
            st["attempts"] = st.get("attempts", 0) + 1
            if on_fail == "retry" and st["attempts"] <= retry_count:
                st["status"] = dfn.NODE_RETRY_WAITING
                self._save(node_states, variables2)
                time.sleep(1)
                return self._execute_node(node, params, variables)  # 重试
            if on_fail == "skip":
                st["status"] = dfn.NODE_SKIPPED
                st["error"] = str(e)
                self._save(node_states, variables2)
                return None
            st["status"] = dfn.NODE_FAILED
            st["error"] = str(e)
            self._save(node_states, variables2)
            raise RuntimeError(f"节点 {node.get('id')} 执行失败: {e}")
        if res is None or getattr(res, "status", "failed") == "failed":
            err = getattr(res, "error", "unknown") if res else "unknown"
            node_states, variables2, _, _ = self._load_state()
            st = node_states.setdefault(node.get("id"), {})
            st["attempts"] = st.get("attempts", 0) + 1
            st["status"] = dfn.NODE_FAILED
            st["error"] = err
            self._save(node_states, variables2)
            raise RuntimeError(f"节点 {node.get('id')} 返回失败: {err}")
        return {"outputs": getattr(res, "outputs", {}), "summary": getattr(res, "summary", "")}

    # ------------------------------------------------------------- condition branch
    def _choose_branch(self, node: dict, expr: str, edges: list, variables: dict) -> str:
        """求值条件节点出边,返回选中 target。"""
        outs = [e for e in edges if e.get("from") == node["id"]]
        default = dfn.default_edges_after_condition(edges, node["id"])
        # 先按顺序求值非默认
        for e in outs:
            if e.get("is_default"):
                continue
            cond = e.get("condition")
            if cond and evaluate(cond, variables):
                return e["to"]
        # 无默认则取第一条
        return default or (outs[0]["to"] if outs else None)

    def _mark_subtree_skipped(self, node_states: dict, start: str, edges: list,
                              node_map: dict, plan: list) -> list:
        """将仅经条件未选分支可达的下游节点标记 skipped。返回被标记的节点 id 列表。
        若目标节点有多条入边(共享节点,可从其它分支到达),则不跳过。"""
        if start is None:
            return []
        ins = [e for e in edges if e.get("to") == start]
        if len(ins) > 1:
            return []  # 共享节点,保留
        self._set_node(node_states, start, dfn.NODE_SKIPPED, error="条件分支未选中")
        marked = [start]
        for e in edges:
            if e.get("from") == start:
                marked += self._mark_subtree_skipped(node_states, e["to"], edges, node_map, plan)
        return marked

    # ------------------------------------------------------------- approval
    def _approval_cb(self, task_id, node_id):
        pass

    def _wait_approval(self, node_id: str) -> dict | None:
        evt = threading.Event()
        with _lock:
            _pending_approvals[(self.task_id, node_id)] = evt
        evt.wait(timeout=86400)  # 24h
        with _lock:
            _pending_approvals.pop((self.task_id, node_id), None)
        return self._approval_decision(node_id)

    def _approval_decision(self, node_id: str) -> dict | None:
        db = SessionLocal()
        try:
            t = db.query(GraphTask).filter(GraphTask.id == self.task_id).first()
            st = (t.node_states or {}).get(node_id, {})
            return st.get("_decision") or None
        finally:
            db.close()


def resolve_approval(task_id: int, node_id: str, approved: bool, reason: str = "") -> bool:
    """审批决策:写入节点状态并唤醒引擎线程。"""
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == task_id).first()
        if not t:
            return False
        states = dict(t.node_states or {})
        st = dict(states.get(node_id, {}))
        st["_decision"] = {"approved": approved, "reason": reason}
        states[node_id] = st
        t.node_states = states
        db.commit()
    finally:
        db.close()
    with _lock:
        evt = _pending_approvals.get((task_id, node_id))
        if evt:
            evt.set()
    return True


def stop_task(task_id: int) -> bool:
    """停止任务。"""
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == task_id).first()
        if not t:
            return False
        t.status = "stopped"
        db.commit()
    finally:
        db.close()
    with _lock:
        for (tid, nid), evt in list(_pending_approvals.items()):
            if tid == task_id:
                evt.set()
    return True


def retry_node(task_id: int, node_id: str) -> bool:
    """重跑单节点:重置其状态与下游,任务回到 running 重新执行。"""
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == task_id).first()
        if not t:
            return False
        states = dict(t.node_states or {})
        for k in list(states.keys()):
            states[k]["status"] = "pending"
            states[k].pop("outputs", None)
            states[k].pop("_decision", None)
            states[k]["error"] = ""
        t.node_states = states
        t.status = "running"
        db.commit()
    finally:
        db.close()
    threading.Thread(target=_run_engine_async, args=(task_id,), daemon=True).start()
    return True


def skip_node(task_id: int, node_id: str) -> bool:
    """跳过节点(标记 skipped)。"""
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == task_id).first()
        if not t:
            return False
        states = dict(t.node_states or {})
        st = dict(states.get(node_id, {}))
        st["status"] = "skipped"
        st["error"] = "用户手动跳过"
        states[node_id] = st
        t.node_states = states
        db.commit()
    finally:
        db.close()
    return True


def _run_engine_async(task_id: int):
    Engine(task_id).run()


def start_engine(task_id: int):
    threading.Thread(target=_run_engine_async, args=(task_id,), daemon=True).start()
