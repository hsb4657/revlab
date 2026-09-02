"""图工作流执行引擎 v3.1(一期):状态机调度、条件分支、失败策略(重试/跳过/终止/定时重试)、
审批挂起、单节点重跑/跳过、重试输入冻结、检查点崩溃恢复、乐观并发控制。"""
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
from .variables import resolve, collect_outputs

log = logging.getLogger("revlab.wfengine")

_pending_approvals = {}
_active_engines = {}
_lock = threading.Lock()


def _now():
    return datetime.utcnow().isoformat() + "Z"


def _load_task(task_id: int):
    db = SessionLocal()
    try:
        return db.query(GraphTask).filter(GraphTask.id == task_id).first()
    finally:
        db.close()


def _load_workflow(wf_id: int):
    db = SessionLocal()
    try:
        return db.query(GraphWorkflow).filter(GraphWorkflow.id == wf_id).first()
    finally:
        db.close()


class Engine:
    def __init__(self, task_id: int):
        self.task_id = task_id
        self._stop = threading.Event()

    def request_stop(self):
        self._stop.set()

    # ------------------------------------------------------------- state IO
    def _load_state(self) -> tuple:
        db = SessionLocal()
        try:
            t = db.query(GraphTask).filter(GraphTask.id == self.task_id).first()
            if not t:
                raise RuntimeError(f"task {self.task_id} not found")
            snapshot = copy.deepcopy(t.definition_snapshot or {})
            if "nodes" in snapshot and "edges" in snapshot:
                nodes, edges = snapshot.get("nodes") or [], snapshot.get("edges") or []
            else:
                # Tasks created before snapshot support retain their legacy
                # behavior, while every new task is immutable by definition.
                wf = db.query(GraphWorkflow).filter(GraphWorkflow.id == t.workflow_id).first()
                if not wf:
                    raise RuntimeError(f"workflow {t.workflow_id} not found")
                nodes, edges = wf.nodes or [], wf.edges or []
            return (copy.deepcopy(t.node_states or {}), copy.deepcopy(t.variables or {}),
                    copy.deepcopy(nodes), copy.deepcopy(edges))
        finally:
            db.close()

    def _save(self, node_states: dict, variables: dict, status: str = None, error: str = ""):
        db = SessionLocal()
        try:
            t = db.query(GraphTask).filter(GraphTask.id == self.task_id).first()
            t.node_states = node_states
            t.variables = variables
            if status and not (t.cancel_requested and status not in (dfn.TASK_STOPPED, dfn.TASK_FAILED)):
                t.status = status
            if error:
                t.error = error
            t.heartbeat_at = datetime.utcnow()
            t.status_version = (t.status_version or 0) + 1
            db.commit()
        finally:
            db.close()

    def _set_node(self, node_states: dict, nid: str, status: str, outputs=None, error=""):
        st = node_states.setdefault(nid, {"status": dfn.NODE_PENDING, "attempts": 0,
                                          "outputs": {}, "error": ""})
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
        return st

    # ------------------------------------------------------------- run
    def run(self):
        node_states, variables, nodes, edges = self._load_state()
        node_map = {n["id"]: n for n in nodes}
        plan = dfn.build_execution_plan(nodes, edges)
        # Allocate the same directory the manifest will expose before any
        # node starts.  All built-in nodes can now emit directly into this
        # run's report/sdk/unpacked/etc. folders.
        from ..services.artifacts import task_output_directory
        output_dir = task_output_directory(self.task_id)
        self._save(node_states, variables, status="running")

        skipped = set()
        visited = set()
        # 初始化节点状态
        for n in nodes:
            if n["id"] not in node_states:
                self._set_node(node_states, n["id"], dfn.NODE_PENDING)

        try:
            for nid in plan:
                if self._stop.is_set() or self._cancel_requested():
                    self._save(node_states, variables, status="stopped")
                    return {"ok": True, "status": "stopped"}
                if nid in visited or nid in skipped:
                    continue
                node = node_map.get(nid)
                if node is None:
                    continue
                ntype = node.get("type")

                # 条件节点
                if ntype == "condition":
                    self._set_node(node_states, nid, dfn.NODE_RUNNING)
                    self._save(node_states, variables)
                    expr = node.get("params", {}).get("expression", "")
                    chosen = self._choose_branch(node, expr, edges, variables)
                    condition_outputs = {"chosen": chosen}
                    variables = collect_outputs(nid, condition_outputs, variables)
                    self._set_node(node_states, nid, dfn.NODE_COMPLETED, outputs=condition_outputs)
                    visited.add(nid)
                    for e in edges:
                        if e.get("from") == nid and e.get("to") != chosen:
                            skips = self._mark_subtree_skipped(node_states, e["to"], edges, node_map, plan)
                            skipped.update(skips)
                    continue

                # 已完成的节点(断点恢复/重跑时跳过)
                cur_st = node_states.get(nid, {}).get("status")
                if cur_st in (dfn.NODE_COMPLETED, dfn.NODE_SKIPPED):
                    visited.add(nid)
                    continue

                # 参数解析
                params = self._resolve_params(node, variables, nid, node_states)

                # 审批节点
                if ntype == "approval":
                    self._set_node(node_states, nid, dfn.NODE_WAITING_APPROVAL)
                    self._save(node_states, variables)
                    decision = self._wait_approval(nid)
                    if decision is None:
                        raise RuntimeError("审批未完成(任务停止)")
                    node_states, variables, _, _ = self._load_state()
                    approval_outputs = {"approved": bool(decision.get("approved")),
                                        "reason": decision.get("reason", "")}
                    variables = collect_outputs(nid, approval_outputs, variables)
                    self._set_node(node_states, nid, dfn.NODE_COMPLETED, outputs=approval_outputs)
                    if not decision.get("approved"):
                        raise RuntimeError(f"审批驳回: {decision.get('reason','')}")
                    visited.add(nid)
                    continue

                # 普通节点:执行 + 失败策略(重试/跳过/终止/定时重试)
                result = self._execute_with_policy(
                    node, params, node_states, variables, output_dir
                )
                if result is None:
                    if node_states.get(nid, {}).get("status") == dfn.NODE_SKIPPED:
                        visited.add(nid)
                        continue
                    self._save(node_states, variables, status="failed")
                    return {"ok": False, "error": f"节点 {nid} 失败"}
                outputs = result.get("outputs") or {}
                outputs["__summary"] = result.get("summary", "")
                variables = collect_outputs(nid, outputs, variables)
                if node.get("type") == "unpack" and outputs.get("ok") and outputs.get("path"):
                    # Downstream analysis must consume the verified unpacked artifact.
                    variables["active_sample_path"] = outputs["path"]
                    variables["sample_path"] = outputs["path"]
                self._set_node(node_states, nid, dfn.NODE_COMPLETED, outputs=outputs)
                visited.add(nid)
                self._save(node_states, variables)

            if self._stop.is_set() or self._cancel_requested():
                self._save(node_states, variables, status="stopped")
                return {"ok": True, "status": "stopped"}
            self._save(node_states, variables, status="completed")
            return {"ok": True, "status": "completed"}
        except Exception as e:
            if self._stop.is_set() or self._cancel_requested():
                self._save(node_states, variables, status="stopped", error="")
                return {"ok": True, "status": "stopped"}
            log.exception("wf task %s failed", self.task_id)
            self._save(node_states, variables, status="failed", error=str(e))
            return {"ok": False, "error": str(e)}
        finally:
            # The task manifest is rebuilt for completed, failed, and stopped
            # runs.  A manifest failure must not overwrite the task result.
            try:
                from ..services.artifacts import finalize_task_artifacts
                finalize_task_artifacts(self.task_id)
            except Exception:
                log.exception("could not finalize artifact manifest for task %s", self.task_id)

    # ------------------------------------------------------------- params
    def _resolve_params(self, node: dict, variables: dict, nid: str, node_states: dict) -> dict:
        """解析节点参数;首次执行冻结 input_snapshot,重试/恢复复用冻结值(输入冻结)。"""
        st = node_states.get(nid, {})
        snap = st.get("input_snapshot")
        if snap is not None:
            return copy.deepcopy(snap.get("params", {}))
        params = dict(node.get("params") or {})
        for k, v in params.items():
            if isinstance(v, str) and "{{" in v:
                rv = resolve(v, variables)
                if "{{" in rv:
                    raise RuntimeError(f"节点 {nid} 参数未解析的变量: {k} = {rv}")
                params[k] = rv
        # 冻结输入快照(深拷贝,防止重试时变量/时间漂移)
        st["input_snapshot"] = {"params": copy.deepcopy(params)}
        node_states[nid] = st
        return params

    # ------------------------------------------------------------- execute + policy
    def _execute_with_policy(self, node: dict, params: dict, node_states: dict, variables: dict,
                             output_dir=None):
        """执行节点,含失败策略(abort/skip/retry/定时重试)。返回 {outputs, summary} 或 None(跳过)。"""
        nid = node.get("id")
        node_params = node.get("params") or {}
        on_fail = node_params.get("on_fail", "abort")
        retry_count = int(node_params.get("retry_count", 0) or 0)
        retry_interval = int(node_params.get("retry_interval", 0) or 0)
        st = self._set_node(node_states, nid, dfn.NODE_RUNNING)
        self._save(node_states, variables)

        while True:
            st = node_states.get(nid, {})
            st["attempts"] = st.get("attempts", 0) + 1
            st["started_at"] = _now()
            self._save(node_states, variables)
            res = self._run_plugin(node, params, variables, nid, node_states, output_dir)
            if res is not None:
                return res
            # 失败
            err = st.get("error") or "执行失败"
            if on_fail == "retry" and st["attempts"] <= retry_count:
                if retry_interval > 0:
                    st["status"] = dfn.NODE_RETRY_WAITING
                    st["next_retry_at"] = time.time() + retry_interval
                    st["error"] = err
                    self._save(node_states, variables)
                    self._wait_retry(nid, st)
                    if self._stop.is_set():
                        return None
                    st["status"] = dfn.NODE_RUNNING
                    self._save(node_states, variables)
                    continue  # 到点重试
                self._set_node(node_states, nid, dfn.NODE_RUNNING, error=err)
                self._save(node_states, variables)
                continue  # 立即重试
            if on_fail == "skip":
                self._set_node(node_states, nid, dfn.NODE_SKIPPED, error="失败后跳过: " + err)
                self._save(node_states, variables)
                return None
            self._set_node(node_states, nid, dfn.NODE_FAILED, error=err)
            self._save(node_states, variables)
            raise RuntimeError(f"节点 {nid} 执行失败: {err}")

    def _run_plugin(self, node: dict, params: dict, variables: dict, nid: str,
                    node_states: dict, output_dir=None):
        cls = get_node_class(node.get("type"))
        if cls is None:
            raise RuntimeError(f"未知节点类型: {node.get('type')}")
        import asyncio
        ctx = {
            "node": node,
            "params": params,
            "pool": variables,
            "task_id": self.task_id,
            "output_dir": output_dir,
        }
        try:
            res = asyncio.run(cls().execute(ctx))
        except Exception as e:
            st = node_states.setdefault(nid, {})
            st["error"] = str(e)
            return None
        if res is None or getattr(res, "status", "failed") == "failed":
            err = getattr(res, "error", "unknown") if res else "unknown"
            st = node_states.setdefault(nid, {})
            st["error"] = err
            return None
        return {"outputs": getattr(res, "outputs", {}), "summary": getattr(res, "summary", "")}

    def _wait_retry(self, nid: str, st: dict):
        wait = max(0, (st.get("next_retry_at") or 0) - time.time())
        # 分片等待,支持停止
        while wait > 0 and not self._stop.is_set():
            time.sleep(min(1, wait))
            wait = max(0, (st.get("next_retry_at") or 0) - time.time())

    # ------------------------------------------------------------- condition
    def _choose_branch(self, node: dict, expr: str, edges: list, variables: dict) -> str:
        outs = [e for e in edges if e.get("from") == node["id"]]
        default = dfn.default_edges_after_condition(edges, node["id"])
        for e in outs:
            if e.get("is_default"):
                continue
            cond = e.get("condition")
            if cond and evaluate(cond, variables):
                return e["to"]
        return default or (outs[0]["to"] if outs else None)

    def _mark_subtree_skipped(self, node_states: dict, start: str, edges: list,
                              node_map: dict, plan: list) -> list:
        if start is None:
            return []
        ins = [e for e in edges if e.get("to") == start]
        if len(ins) > 1:
            return []
        self._set_node(node_states, start, dfn.NODE_SKIPPED, error="条件分支未选中")
        marked = [start]
        for e in edges:
            if e.get("from") == start:
                marked += self._mark_subtree_skipped(node_states, e["to"], edges, node_map, plan)
        return marked

    # ------------------------------------------------------------- approval
    def _wait_approval(self, node_id: str) -> dict | None:
        evt = threading.Event()
        with _lock:
            _pending_approvals[(self.task_id, node_id)] = evt
        deadline = time.time() + 86400
        while time.time() < deadline and not self._stop.is_set() and not self._cancel_requested():
            decision = self._approval_decision(node_id)
            if decision is not None:
                break
            evt.wait(timeout=1)
        with _lock:
            _pending_approvals.pop((self.task_id, node_id), None)
        return self._approval_decision(node_id)

    def _cancel_requested(self) -> bool:
        db = SessionLocal()
        try:
            task = db.query(GraphTask).filter(GraphTask.id == self.task_id).first()
            return bool(task and task.cancel_requested)
        finally:
            db.close()

    def _approval_decision(self, node_id: str) -> dict | None:
        db = SessionLocal()
        try:
            t = db.query(GraphTask).filter(GraphTask.id == self.task_id).first()
            return (t.node_states or {}).get(node_id, {}).get("_decision") or None
        finally:
            db.close()


# ================================================================ 控制 API
def resolve_approval(task_id: int, node_id: str, approved: bool, reason: str = "") -> bool:
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == task_id).first()
        if not t:
            return False
        if (states := dict(t.node_states or {})).get(node_id, {}).get("status") != dfn.NODE_WAITING_APPROVAL:
            return False
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
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == task_id).first()
        if not t:
            return False
        if t.status in (dfn.TASK_COMPLETED, dfn.TASK_FAILED, dfn.TASK_STOPPED):
            return False
        t.cancel_requested = 1
        t.status = dfn.TASK_STOPPED
        t.status_version = (t.status_version or 0) + 1
        db.commit()
    finally:
        db.close()
    with _lock:
        for (tid, nid), evt in list(_pending_approvals.items()):
            if tid == task_id:
                evt.set()
        active = _active_engines.get(task_id)
        if active:
            active.request_stop()
    return True


def _expected_ok(task_id: int, node_id: str, expected: int) -> bool:
    """乐观并发校验:节点当前 attempts 必须等于 expected。"""
    if expected is None or expected < 0:
        return True
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == task_id).first()
        return (t.node_states or {}).get(node_id, {}).get("attempts", 0) == expected
    finally:
        db.close()


def retry_node(task_id: int, node_id: str, expected_attempt_count: int = -1) -> dict:
    """重跑单节点(及其后未完成节点)。expected_attempt_count 乐观并发控制。"""
    if not _expected_ok(task_id, node_id, expected_attempt_count):
        return {"ok": False, "error": "conflict", "code": 409}
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == task_id).first()
        if not t:
            return {"ok": False, "error": "not found"}
        states = dict(t.node_states or {})
        # 从该节点起重置为 pending(保留 input_snapshot 以冻结输入)
        target = node_id
        for k in list(states.keys()):
            if k == target:
                st = states[k]
                st["status"] = "pending"
                st["outputs"] = {}
                st.pop("_decision", None)
                st["error"] = ""
        t.node_states = states
        if t.status in (dfn.TASK_COMPLETED, dfn.TASK_STOPPED):
            return {"ok": False, "error": "task is not retryable"}
        t.cancel_requested = 0
        t.status = "running"
        t.status_version = (t.status_version or 0) + 1
        db.commit()
    finally:
        db.close()
    if not _start_thread(task_id):
        return {"ok": False, "error": "task is already running"}
    return {"ok": True}


def skip_node(task_id: int, node_id: str, expected_attempt_count: int = -1) -> dict:
    if not _expected_ok(task_id, node_id, expected_attempt_count):
        return {"ok": False, "error": "conflict", "code": 409}
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == task_id).first()
        if not t:
            return {"ok": False, "error": "not found"}
        if t.status in (dfn.TASK_COMPLETED, dfn.TASK_STOPPED):
            return {"ok": False, "error": "task is not active"}
        states = dict(t.node_states or {})
        st = dict(states.get(node_id, {}))
        st["status"] = "skipped"
        st["error"] = "用户手动跳过"
        states[node_id] = st
        t.node_states = states
        t.status_version = (t.status_version or 0) + 1
        db.commit()
    finally:
        db.close()
    return {"ok": True}


def _start_thread(task_id: int):
    with _lock:
        if task_id in _active_engines:
            return False
        runner = Engine(task_id)
        _active_engines[task_id] = runner
    threading.Thread(target=_run_engine, args=(task_id, runner), daemon=True).start()
    return True


def _run_engine(task_id: int, runner: Engine):
    try:
        runner.run()
    finally:
        with _lock:
            _active_engines.pop(task_id, None)


def start_engine(task_id: int):
    return _start_thread(task_id)


# ================================================================ 崩溃恢复
def recover_engine_tasks():
    """启动时扫描 running/retry_waiting 任务并恢复。
    遗留 running 节点按失败策略处理:可重试→重试;否则标记失败后重跑引擎,让失败策略生效。
    """
    db = SessionLocal()
    try:
        rows = db.query(GraphTask).filter(GraphTask.status.in_(["running", "retry_waiting"])).all()
        recover_ids = []
        for t in rows:
            wf = db.query(GraphWorkflow).filter(GraphWorkflow.id == t.workflow_id).first()
            states = dict(t.node_states or {})
            node_map = {n["id"]: n for n in (wf.nodes or [])} if wf else {}
            for nid, st in states.items():
                if st.get("status") == "running":
                    node = node_map.get(nid) or {}
                    node_params = node.get("params") or {}
                    on_fail = node_params.get("on_fail", "abort")
                    retry_count = int(node_params.get("retry_count", 0) or 0)
                    st["status"] = "retry_waiting"
                    st["error"] = "进程中断后恢复"
                    if not (on_fail == "retry" and st.get("attempts", 0) < retry_count):
                        st["status"] = "failed"
            t.node_states = states
            t.status = "running"
            db.commit()
            recover_ids.append(t.id)
    finally:
        db.close()
    for tid in recover_ids:
        log.info("recovering wf task %s after crash", tid)
        _start_thread(tid)
    return recover_ids
