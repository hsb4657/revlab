from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.ue.analyzer import UEAnalyzer
from app.services.ue.layout_analysis import analyze_get_name_xor
from app.workflow_engine.manager import get_workflow, init_builtin_templates
from app.core.database import SessionLocal
from app.models.sample import GraphWorkflow
from app.workflow_engine.nodes.analysis import UEGetNameXorNode


class UEStaticEvidenceTests(unittest.TestCase):
    def test_getname_xor_is_candidate_until_runtime_observation(self):
        # Symbol marker + ``xor eax, imm32`` in a synthetic function window.
        data = b"GetName\x00" + b"\x90" * 32 + b"\x35\x78\x56\x34\x12" + b"PlayerController\x00"
        result = analyze_get_name_xor(data)
        self.assertEqual(result["validation_state"], "candidate")
        self.assertTrue(result["function_markers"])
        self.assertTrue(result["xor_candidates"])
        self.assertEqual(result["xor_candidates"][0]["validation_state"], "candidate")
        self.assertTrue(result["plaintext_candidates"])
        self.assertTrue(result["runtime_validation_required"])

    def test_runtime_observation_is_the_only_confirmation_path(self):
        data = b"GetName\x00" + b"\x90" * 16 + b"\x34\xaa"
        result = analyze_get_name_xor(
            data,
            runtime_observations={
                "get_name_xor": {
                    "validated": True,
                    "key": 0xAA,
                    "plaintext": "Player",
                }
            },
        )
        self.assertEqual(result["validation_state"], "confirmed")
        self.assertEqual(result["xor_candidates"][0]["validation_state"], "confirmed")
        self.assertEqual(result["plaintext_candidates"][0]["validation_state"], "confirmed")

    def test_analyzer_exposes_plaintext_candidates_and_getname_contract(self):
        sample = Path(__file__).resolve().parents[2] / "samples" / "ue_sample.exe"
        result = UEAnalyzer(str(sample)).run()
        self.assertIn("get_name_xor", result)
        self.assertIn("plaintext_candidates", result)
        self.assertTrue({"gobjects", "gnames", "gworld", "gengine"}.issubset(result["plaintext_candidates"]))
        for item in (result.get("three_majors") or {}).values():
            self.assertIn(item.get("validation_state"), {"candidate", "unconfirmed"})
            self.assertNotEqual(item.get("validation_state"), "confirmed")

    def test_getname_node_is_in_ue_preset(self):
        init_builtin_templates()
        db = SessionLocal()
        try:
            row = db.query(GraphWorkflow).filter(GraphWorkflow.name == "ue-special").first()
            self.assertIsNotNone(row)
            workflow = get_workflow(row.id)
        finally:
            db.close()
        self.assertIn("ue_getname_xor", {node["type"] for node in workflow["nodes"]})
        self.assertTrue(any(edge["to"] == "ue_getname_xor" for edge in workflow["edges"]))
        self.assertTrue(any(edge["from"] == "ue_getname_xor" for edge in workflow["edges"]))
        self.assertEqual(asyncio.run(UEGetNameXorNode().execute({"params": {}, "pool": {}})).status, "failed")


if __name__ == "__main__":
    unittest.main()
