from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.workflow_engine.definition import validate_graph
from app.workflow_engine.manager import get_workflow, init_builtin_templates, list_workflows
from app.workflow_engine.nodes.analysis import UnityDeliveryGateNode


class UnityWorkflowTemplateTests(unittest.TestCase):
    def test_unity_preset_exposes_recovery_and_strict_delivery_nodes(self):
        init_builtin_templates()
        row = next(item for item in list_workflows() if item["name"] == "unity-special")
        workflow = get_workflow(row["id"])
        types = {node["type"] for node in workflow["nodes"]}
        self.assertTrue({
            "unity_scan", "unity_assembly", "unity_metadata_candidates",
            "unity_loader_analysis", "unity_metadata", "unity_metadata_validation",
            "sdk_dump", "unity_report", "unity_delivery_gate", "condition", "end",
        } <= types)
        self.assertGreaterEqual(len(workflow["nodes"]), 12)
        valid, errors = validate_graph(workflow["nodes"], workflow["edges"], workflow["variables"])
        self.assertTrue(valid, errors)


class UnityDeliveryGateTests(unittest.TestCase):
    def test_missing_sdk_artifacts_fails_the_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            md = root / "Build.09052026.md"
            md.write_text("report", encoding="utf-8")
            result = asyncio.run(UnityDeliveryGateNode().execute({
                "params": {},
                "pool": {
                    "unity_assembly": {"build_type": "IL2CPP"},
                    "unity_metadata_validation": {"metadata_verified": False},
                    "sdk_dump": {"delivery_complete": False},
                    "report": {"root_markdown": str(md), "report_paths": {}},
                },
            }))
            self.assertEqual(result.status, "failed")
            self.assertIn("metadata_verified", result.outputs["missing"])
            self.assertIn("dump_cs", result.outputs["missing"])

    def test_all_verified_artifacts_pass_the_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = {}
            for key, name in {
                "dump_cs": "Dump.cs", "script_json": "script.json",
                "stringliteral_json": "stringliteral.json", "sdk_json": "sdk.json",
                "dummy_dll": "Assembly-CSharp.dll",
                "root_markdown": "Build.09052026.md",
            }.items():
                path = root / name
                path.write_bytes(b"ok")
                paths[key] = str(path)
            result = asyncio.run(UnityDeliveryGateNode().execute({
                "params": {},
                "pool": {
                    "unity_assembly": {"build_type": "IL2CPP"},
                    "metadata_validation": {"metadata_verified": True},
                    "sdk_dump": {
                        "delivery_complete": True,
                        **paths,
                        "dummy_dlls": [paths["dummy_dll"]],
                    },
                    "report": {"root_markdown": paths["root_markdown"], "report_paths": {}},
                },
            }))
            self.assertEqual(result.status, "success", result.error)
            self.assertTrue(result.outputs["delivery_complete"])


if __name__ == "__main__":
    unittest.main()
