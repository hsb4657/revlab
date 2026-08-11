"""图工作流定义:数据模型校验 + 执行计划构建"""
from __future__ import annotations
import uuid

# 内置/控制节点类型
CONTROL_TYPES = {"condition", "approval", "script", "subflow", "report", "start", "end"}

# 节点状态
NODE_PENDING = "pending"
NODE_RUNNING = "running"
NODE_COMPLETED = "completed"
NODE_FAILED = "failed"
NODE_SKIPPED = "skipped"
NODE_WAITING_APPROVAL = "waiting_approval"
NODE_RETRY_WAITING = "retry_waiting"
NODE_STATES = {NODE_PENDING, NODE_RUNNING, NODE_COMPLETED, NODE_FAILED,
               NODE_SKIPPED, NODE_WAITING_APPROVAL, NODE_RETRY_WAITING}

# 任务状态
TASK_PENDING = "pending"
TASK_RUNNING = "running"
TASK_COMPLETED = "completed"
TASK_FAILED = "failed"
TASK_STOPPED = "stopped"


def gen_id(prefix: str = "n") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def validate_graph(nodes: list, edges: list) -> tuple:
    """校验图结构。返回 (valid, errors[])。"""
    errors = []
    if not nodes:
        return False, ["节点列表为空"]
    ids = [n.get("id") for n in nodes]
    if len(ids) != len(set(ids)):
        errors.append("节点 ID 重复")
    # 边引用的节点必须存在
    edge_ids = {e.get("from") for e in edges} | {e.get("to") for e in edges}
    for rid in edge_ids:
        if rid not in ids:
            errors.append(f"边引用不存在的节点: {rid}")
    # 每个非终止节点至少一条出边
    terminal = {"end", "report"}
    for n in nodes:
        nid = n.get("id")
        if n.get("type") in terminal:
            continue
        if not any(e.get("from") == nid for e in edges):
            errors.append(f"节点 {nid} 没有出边(孤立/无后继)")
    # 条件节点至少 1 条默认出边
    for n in nodes:
        if n.get("type") == "condition":
            outs = [e for e in edges if e.get("from") == n["id"]]
            if not outs:
                errors.append(f"条件节点 {n['id']} 无出边")
            elif not any(e.get("is_default") for e in outs):
                errors.append(f"条件节点 {n['id']} 缺少默认分支(is_default)")
    return (not errors), errors


def build_execution_plan(nodes: list, edges: list) -> list:
    """拓扑排序执行计划(从 start/首节点开始,BFS 依边推进)。
    返回节点 id 列表;condition 节点仅列出,分支由引擎运行时决定。
    """
    node_map = {n["id"]: n for n in nodes}
    in_degree = {n["id"]: 0 for n in nodes}
    adj = {n["id"]: [] for n in nodes}
    for e in edges:
        adj.setdefault(e.get("from"), []).append(e.get("to"))
        in_degree[e["to"]] = in_degree.get(e["to"], 0) + 1
    # 起点:没有入边的节点(或显式 start)
    starts = [n["id"] for n in nodes if in_degree.get(n["id"], 0) == 0]
    if not starts:
        starts = [nodes[0]["id"]]
    # Kahn 拓扑排序
    from collections import deque
    q = deque(starts)
    order = []
    visited = set()
    # 避免 condition 后两条边都算(条件只走一条),这里 plan 给"可达骨架"
    used_edges = set()
    while q:
        nid = q.popleft()
        if nid in visited:
            continue
        visited.add(nid)
        order.append(nid)
        for to in adj.get(nid, []):
            if to in visited:
                continue
            # 条件节点:所有出边目标都作为候选(运行时选一)
            if node_map.get(nid, {}).get("type") == "condition":
                if to not in visited:
                    q.append(to)
            else:
                q.append(to)
    # 补上未被遍历的孤立节点(以防)
    for n in nodes:
        if n["id"] not in order:
            order.append(n["id"])
    return order


def default_edges_after_condition(edges: list, node_id: str) -> str | None:
    """条件节点的默认出边目标。"""
    for e in edges:
        if e.get("from") == node_id and e.get("is_default"):
            return e.get("to")
    return None
