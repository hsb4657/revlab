"""Graph workflow validation and deterministic planning."""
from __future__ import annotations

import uuid
from collections import deque

from .conditions import validate_expression
from .nodes.base import get_node_class

CONTROL_TYPES = {"condition", "approval", "script", "subflow", "report", "start", "end"}

NODE_PENDING = "pending"
NODE_RUNNING = "running"
NODE_COMPLETED = "completed"
NODE_FAILED = "failed"
NODE_SKIPPED = "skipped"
NODE_WAITING_APPROVAL = "waiting_approval"
NODE_RETRY_WAITING = "retry_waiting"
NODE_STATES = {
    NODE_PENDING, NODE_RUNNING, NODE_COMPLETED, NODE_FAILED,
    NODE_SKIPPED, NODE_WAITING_APPROVAL, NODE_RETRY_WAITING,
}

TASK_PENDING = "pending"
TASK_RUNNING = "running"
TASK_COMPLETED = "completed"
TASK_FAILED = "failed"
TASK_STOPPED = "stopped"


def gen_id(prefix: str = "n") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def validate_graph(nodes: list, edges: list, variables: list | None = None) -> tuple[bool, list[str]]:
    """Validate graph structure, node types, expressions, variables and cycles."""
    errors: list[str] = []
    if not nodes:
        return False, ["节点列表为空"]

    ids = [n.get("id") for n in nodes]
    node_ids = set(ids)
    if any(not isinstance(i, str) or not i.strip() for i in ids):
        errors.append("节点 ID 不能为空")
    if len(ids) != len(node_ids):
        errors.append("节点 ID 重复")

    edge_ids = [e.get("id") for e in edges]
    if any(not isinstance(i, str) or not i.strip() for i in edge_ids):
        errors.append("边 ID 不能为空")
    if len(edge_ids) != len(set(edge_ids)):
        errors.append("边 ID 重复")
    edge_pairs = [(e.get("from"), e.get("to")) for e in edges]
    if len(edge_pairs) != len(set(edge_pairs)):
        errors.append("边连接重复；同一对节点只能保留一条边")

    for node in nodes:
        node_id = node.get("id")
        node_type = node.get("type")
        if not node_type:
            errors.append(f"节点 {node_id} 缺少 type")
        elif node_type not in CONTROL_TYPES and get_node_class(node_type) is None:
            errors.append(f"未知节点类型: {node_type}")

    for edge in edges:
        source, target = edge.get("from"), edge.get("to")
        if source not in node_ids:
            errors.append(f"边 {edge.get('id')} 引用了不存在的源节点: {source}")
        if target not in node_ids:
            errors.append(f"边 {edge.get('id')} 引用了不存在的目标节点: {target}")
        if source == target:
            errors.append(f"边 {edge.get('id')} 不能连接自身")

    terminal = {"end", "report", "ue_report", "unity_report"}
    for node in nodes:
        node_id = node.get("id")
        if node.get("type") not in terminal and not any(e.get("from") == node_id for e in edges):
            errors.append(f"节点 {node_id} 没有出边")

    for node in nodes:
        if node.get("type") != "condition":
            continue
        outs = [e for e in edges if e.get("from") == node.get("id")]
        if not outs:
            errors.append(f"条件节点 {node.get('id')} 没有出边")
            continue
        defaults = [e for e in outs if e.get("is_default")]
        if len(defaults) != 1:
            errors.append(f"条件节点 {node.get('id')} 必须有且只有一个默认分支")
        for edge in outs:
            if edge.get("is_default"):
                if edge.get("condition"):
                    errors.append(f"默认分支 {edge.get('id')} 不应配置 condition")
            elif not edge.get("condition"):
                errors.append(f"条件分支 {edge.get('id')} 缺少 condition")
            else:
                syntax_error = validate_expression(edge["condition"])
                if syntax_error:
                    errors.append(f"边 {edge.get('id')} 条件表达式错误: {syntax_error}")

    indegree = {node_id: 0 for node_id in node_ids}
    adjacency = {node_id: [] for node_id in node_ids}
    for edge in edges:
        if edge.get("from") in node_ids and edge.get("to") in node_ids:
            adjacency[edge["from"]].append(edge["to"])
            indegree[edge["to"]] += 1
    queue = deque(node_id for node_id, degree in indegree.items() if degree == 0)
    topo_count = 0
    while queue:
        current = queue.popleft()
        topo_count += 1
        for child in adjacency[current]:
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
    if topo_count != len(node_ids):
        errors.append("工作流包含环；循环必须使用显式 loop 节点")

    roots = [node_id for node_id in node_ids if not any(e.get("to") == node_id for e in edges)]
    if len(roots) != 1:
        errors.append(f"工作流必须有唯一入口，当前发现 {len(roots)} 个入口")

    if variables is not None:
        keys = [v.get("key") for v in variables]
        if any(not isinstance(k, str) or not k.strip() for k in keys):
            errors.append("变量 key 不能为空")
        if len(keys) != len(set(keys)):
            errors.append("变量 key 重复")
        for variable in variables:
            if variable.get("type", "text") not in {"text", "number", "bool", "json"}:
                errors.append(f"变量 {variable.get('key')} 类型无效")

    return not errors, errors


def build_execution_plan(nodes: list, edges: list) -> list[str]:
    """Return a topological plan. Invalid cyclic graphs return reachable order only."""
    node_ids = [node["id"] for node in nodes]
    indegree = {node_id: 0 for node_id in node_ids}
    adjacency = {node_id: [] for node_id in node_ids}
    for edge in edges:
        if edge.get("from") in adjacency and edge.get("to") in indegree:
            adjacency[edge["from"]].append(edge["to"])
            indegree[edge["to"]] += 1
    queue = deque(node_id for node_id in node_ids if indegree[node_id] == 0)
    order: list[str] = []
    while queue:
        node_id = queue.popleft()
        order.append(node_id)
        for child in adjacency[node_id]:
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
    return order


def default_edges_after_condition(edges: list, node_id: str) -> str | None:
    for edge in edges:
        if edge.get("from") == node_id and edge.get("is_default"):
            return edge.get("to")
    return None
