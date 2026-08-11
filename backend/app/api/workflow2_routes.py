"""图化工作流 v3 API"""
from fastapi import APIRouter, HTTPException, Query

from ..models.sample import GraphWorkflow, GraphTask
from ..workflow_engine import manager as wfm
from ..workflow_engine import definition as dfn
from ..workflow_engine.engine import resolve_approval, stop_task, retry_node, skip_node
from ..workflow_engine.nodes.base import list_node_types

router = APIRouter(prefix="/api/wf2")


@router.get("/spec")
def wf2_spec():
    return {"node_types": list_node_types(), "stages": list(dfn.NODE_STATES)}


@router.post("/validate")
def wf2_validate(payload: dict):
    valid, errors = dfn.validate_graph(payload.get("nodes") or [], payload.get("edges") or [])
    return {"valid": valid, "errors": errors}


@router.get("")
def wf2_list():
    return wfm.list_workflows()


@router.post("")
def wf2_create(payload: dict):
    try:
        return wfm.create_workflow(payload.get("name", ""), payload.get("description", ""),
                                   payload.get("nodes"), payload.get("edges"),
                                   payload.get("variables"))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/{wf_id}")
def wf2_get(wf_id: int):
    w = wfm.get_workflow(wf_id)
    if not w:
        raise HTTPException(404, "workflow not found")
    return w


@router.put("/{wf_id}")
def wf2_update(wf_id: int, payload: dict):
    try:
        return wfm.update_workflow(wf_id, **payload)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/{wf_id}")
def wf2_delete(wf_id: int):
    if not wfm.delete_workflow(wf_id):
        raise HTTPException(404, "not found")
    return {"ok": True}


# ---------------------------------------------------------------- tasks
@router.post("/{wf_id}/tasks")
def wf2_create_task(wf_id: int, payload: dict = None):
    try:
        return wfm.create_task(wf_id, (payload or {}).get("name", ""),
                               (payload or {}).get("variables"))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{wf_id}/tasks/{task_id}/run")
def wf2_run_task(wf_id: int, task_id: int):
    t = wfm.get_task(task_id)
    if not t or t["workflow_id"] != wf_id:
        raise HTTPException(404, "task not found")
    return wfm.run_task(task_id)


@router.post("/{wf_id}/tasks/{task_id}/stop")
def wf2_stop_task(wf_id: int, task_id: int):
    if not stop_task(task_id):
        raise HTTPException(404, "task not found")
    return {"ok": True}


@router.get("/{wf_id}/tasks")
def wf2_list_tasks(wf_id: int, limit: int = Query(100)):
    return wfm.list_tasks(wf_id, limit)


@router.get("/{wf_id}/tasks/{task_id}")
def wf2_get_task(wf_id: int, task_id: int):
    t = wfm.get_task(task_id)
    if not t or t["workflow_id"] != wf_id:
        raise HTTPException(404, "task not found")
    return t


@router.post("/tasks/{task_id}/nodes/{node_id}/retry")
def wf2_retry_node(task_id: int, node_id: str):
    if not retry_node(task_id, node_id):
        raise HTTPException(404, "task/node not found")
    return {"ok": True}


@router.post("/tasks/{task_id}/nodes/{node_id}/skip")
def wf2_skip_node(task_id: int, node_id: str):
    if not skip_node(task_id, node_id):
        raise HTTPException(404, "task/node not found")
    return {"ok": True}


@router.post("/tasks/{task_id}/nodes/{node_id}/resolve-approval")
def wf2_resolve_approval(task_id: int, node_id: str, payload: dict):
    if not resolve_approval(task_id, node_id, bool(payload.get("approved")), payload.get("reason", "")):
        raise HTTPException(404, "task/node not found")
    return {"ok": True, "approved": payload.get("approved")}
