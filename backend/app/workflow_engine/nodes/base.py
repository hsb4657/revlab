"""节点插件体系:BaseNode + 注册中心。参考 DeterminFlow 插件化节点设计。
节点契约:class XNode(BaseNode):
    node_type, label, params_schema, async execute(ctx) -> dict
ctx = {"node": node_def, "params": 已解析参数, "pool": 变量池, "task_id": int, ...}
"""
from __future__ import annotations


class NodeResult:
    def __init__(self, status="success", outputs=None, summary="", error=""):
        self.status = status          # success / failed
        self.outputs = outputs or {}  # dict,写入变量池
        self.summary = summary or ""
        self.error = error or ""


class BaseNode:
    node_type = "base"
    label = "基础节点"
    icon = "⚙️"
    params_schema = []  # [{key,label,type,default,required,options?}]
    category = "通用"
    risk_level = "safe"

    async def execute(self, ctx) -> NodeResult:
        raise NotImplementedError


_NODES = {}


def register(node_cls):
    _NODES[node_cls.node_type] = node_cls
    return node_cls


def get_node_class(node_type: str) -> BaseNode | None:
    return _NODES.get(node_type)


def list_node_types() -> list:
    out = []
    for t, cls in _NODES.items():
        out.append({"type": t, "label": cls.label, "icon": getattr(cls, "icon", "⚙️"),
                    "category": getattr(cls, "category", "通用"),
                    "risk_level": getattr(cls, "risk_level", "safe"),
                    "params_schema": cls.params_schema})
    out.sort(key=lambda x: (x["category"], x["label"]))
    return out
