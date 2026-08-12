from __future__ import annotations

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.workflow_engine.conditions import ConditionSyntaxError, evaluate, validate_expression
from app.workflow_engine.definition import build_execution_plan, validate_graph


def node(node_id: str, node_type: str = "script") -> dict:
    return {"id": node_id, "label": node_id, "type": node_type, "params": {}}


def edge(edge_id: str, source: str, target: str, **extra) -> dict:
    return {"id": edge_id, "from": source, "to": target, **extra}


class ConditionTests(unittest.TestCase):
    def test_typed_values(self):
        self.assertTrue(evaluate("{{flag}} == true", {"flag": True}))
        self.assertTrue(evaluate("{{flag}} == false", {"flag": False}))
        self.assertTrue(evaluate('{{kind}} == "IL2CPP"', {"kind": "IL2CPP"}))
        self.assertTrue(evaluate("{{count}} >= 3", {"count": 4}))
        self.assertTrue(evaluate("{{missing}} == null", {}))

    def test_boolean_operators_consume_the_full_expression(self):
        self.assertTrue(evaluate("true OR false", {}))
        self.assertFalse(evaluate("false AND true", {}))
        self.assertTrue(evaluate("NOT false AND (true OR false)", {}))

    def test_invalid_expression_is_reported(self):
        self.assertIsNotNone(validate_expression("{{flag}} =="))
        self.assertIsNotNone(validate_expression("true trailing"))
        with self.assertRaises(ConditionSyntaxError):
            evaluate("true trailing", {})


class GraphDefinitionTests(unittest.TestCase):
    def test_valid_condition_graph_and_stable_plan(self):
        nodes = [node("start"), node("branch", "condition"), node("yes"), node("no", "report")]
        edges = [
            edge("e1", "start", "branch"),
            edge("e2", "branch", "yes", condition="{{flag}} == true"),
            edge("e3", "branch", "no", is_default=True),
            edge("e4", "yes", "no"),
        ]
        valid, errors = validate_graph(nodes, edges, [{"key": "flag", "type": "bool"}])
        self.assertTrue(valid, errors)
        self.assertEqual(build_execution_plan(nodes, edges), ["start", "branch", "yes", "no"])

    def test_cycle_duplicate_edge_and_multiple_roots_are_rejected(self):
        cycle_nodes = [node("a"), node("b")]
        valid, errors = validate_graph(
            cycle_nodes,
            [edge("e1", "a", "b"), edge("e2", "b", "a")],
            [],
        )
        self.assertFalse(valid)
        self.assertTrue(any("环" in error for error in errors))

        valid, errors = validate_graph(
            [node("a"), node("b", "report")],
            [edge("e1", "a", "b"), edge("e2", "a", "b")],
            [],
        )
        self.assertFalse(valid)
        self.assertTrue(any("连接重复" in error for error in errors))

        valid, errors = validate_graph([node("a", "report"), node("b", "report")], [], [])
        self.assertFalse(valid)
        self.assertTrue(any("唯一入口" in error for error in errors))

    def test_condition_requires_one_default_branch(self):
        nodes = [node("branch", "condition"), node("out", "report")]
        valid, errors = validate_graph(
            nodes,
            [edge("e1", "branch", "out", condition="true")],
            [],
        )
        self.assertFalse(valid)
        self.assertTrue(any("默认分支" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
