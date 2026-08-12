"""节点注册:导入即注册"""
from . import analysis  # noqa: F401
from . import control   # noqa: F401
from . import ai        # noqa: F401
from .base import BaseNode, NodeResult, list_node_types, get_node_class, register  # noqa: F401
