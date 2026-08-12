from __future__ import annotations

import asyncio
import json
import shutil
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.ue.analyzer import UEAnalyzer
from app.services.ue.layout_analysis import analyze_reflection_layouts
from app.core.database import SessionLocal
from app.models.sample import GraphTask, GraphWorkflow
from app.core.config import config
from app.services import report as report_svc
from app.services.ue.signatures import BUILTIN_SIGNATURES, scan_signature
from app.workflow_engine.definition import validate_graph
from app.workflow_engine.manager import get_workflow, init_builtin_templates
from app.workflow_engine.nodes.analysis import (
    UEFNameNode,
    UEGlobalsNode,
    UEReflectionNode,
    UEVersionNode,
    UEReportNode,
    UEDeliveryGateNode,
)


class UEAnalyzerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = Path(__file__).resolve().parents[2] / "samples" / "ue_sample.exe"

    def test_static_result_contains_separate_evidence_contracts(self):
        result = UEAnalyzer(str(self.sample)).run()
        self.assertIn("three_majors", result)
        self.assertIn("major_candidates", result)
        self.assertIn("fname_analysis", result)
        self.assertIn("reflection", result)
        self.assertIn("layout_profiles", result)
        self.assertIn("decryption", result)
        self.assertIn("validation_state", result["three_majors"]["gnames"])
        self.assertIn(result["three_majors"]["gnames"]["validation_state"], {"candidate", "unconfirmed"})
        self.assertIn("algorithm_candidates", result["fname_analysis"])
        self.assertIn("field_offset_candidates", result["reflection"])
        self.assertTrue(result["reflection"]["validation_plan"])
        runtime = result["runtime_validation"]
        self.assertEqual(runtime["analysis_mode"], "static_dump_only")
        self.assertFalse(runtime["execution_available"])
        self.assertEqual(runtime["evidence_status"], "not_collected")
        self.assertTrue(runtime["collection_plan"])
        self.assertTrue(result["runtime_execution_available"] is False)

    def test_ue55_uses_default_version_baseline_not_incidental_game_profile(self):
        result = analyze_reflection_layouts(
            b"Core\x00DeadByDaylight\x00UObject\x00FProperty\x00",
            engine_version="5.5",
            engine_family="UE5",
            fname_model="pool",
        )
        self.assertEqual(result["version_baseline_profile_name"], "Default")
        self.assertEqual(result["selected_profile"]["name"], "Default")
        self.assertEqual(result["profile_selection_state"], "version_baseline_candidate")
        self.assertEqual(result["selected_profile"]["structures"]["UObject"]["Class"]["value"], 0x10)
        self.assertEqual(result["selected_profile"]["structures"]["FProperty"]["Offset"]["value"], 0x4C)

    def test_runtime_validated_profile_can_override_version_baseline(self):
        result = analyze_reflection_layouts(
            b"UObject\x00",
            engine_version="5.5",
            engine_family="UE5",
            runtime_observations={"validated_profile": "Core"},
        )
        self.assertEqual(result["selected_profile"]["name"], "Core")
        self.assertEqual(result["profile_selection_state"], "runtime_confirmed")
        self.assertEqual(result["selected_profile"]["validation_state"], "confirmed")

    def test_granular_nodes_reuse_the_cached_analysis(self):
        path = str(self.sample)
        version = asyncio.run(UEVersionNode().execute({"params": {"sample_path": path}, "pool": {}}))
        self.assertEqual(version.status, "success")
        pool = {"ue_version": version.outputs}
        globals_result = asyncio.run(UEGlobalsNode().execute({"params": {}, "pool": pool}))
        fname_result = asyncio.run(UEFNameNode().execute({"params": {}, "pool": {**pool, "ue_globals": globals_result.outputs}}))
        reflection_result = asyncio.run(UEReflectionNode().execute({"params": {}, "pool": {**pool, "ue_globals": globals_result.outputs, "ue_fname": fname_result.outputs}}))
        self.assertEqual(globals_result.status, "success")
        self.assertEqual(fname_result.status, "success")
        self.assertEqual(reflection_result.status, "success")
        self.assertEqual(fname_result.outputs["_analysis"], version.outputs["_analysis"])
        self.assertTrue(reflection_result.outputs["field_offset_candidates"])

    def test_signature_anchor_scan_preserves_wildcard_and_relative_target(self):
        entry = BUILTIN_SIGNATURES[0]
        pattern = [0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x0C, 0xC8, 0x48, 0x8D, 0x04, 0xD1]
        data = b"\x90" * 9 + bytes(pattern) + b"\x90" * 32
        hits = scan_signature(data, entry)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["match"], 9)
        self.assertEqual(hits[0]["target"], 9 + 3 + 4 + 0x10)

    def test_ue_result_renders_detailed_html_sections(self):
        result = UEAnalyzer(str(self.sample)).run()
        report = report_svc.build_report({"file_name": self.sample.name}, {"ue": result})
        html = report_svc.to_html(report)
        for heading in ("UE 全局对象候选", "FName / GNames 算法候选", "UE 反射结构与字段偏移", "运行时验证清单", "运行时证据边界", "运行时采集计划", "静态分析限制"):
            self.assertIn(heading, html)
        markdown = report_svc.to_markdown(report)
        self.assertIn("运行时证据边界", markdown)
        self.assertIn("Dump 仅静态分析", markdown)


class UEWorkflowTemplateTests(unittest.TestCase):
    def test_ue_preset_is_granular_and_valid(self):
        init_builtin_templates()
        db = SessionLocal()
        try:
            row = db.query(GraphWorkflow).filter(GraphWorkflow.name == "ue-special").first()
            self.assertIsNotNone(row)
            workflow_id = row.id
        finally:
            db.close()
        workflow = get_workflow(workflow_id)
        node_types = {node["type"] for node in workflow["nodes"]}
        required = {"pe_identify", "strings", "ue_version", "ue_globals", "ue_fname", "ue_reflection", "ue_protection", "ue_encryption", "ue_runtime_validation", "ue_report", "ue_delivery_gate", "condition", "end"}
        self.assertTrue(required.issubset(node_types), node_types)
        self.assertGreaterEqual(len(workflow["nodes"]), 10)
        self.assertGreaterEqual(len(workflow["edges"]), 12)
        valid, errors = validate_graph(workflow["nodes"], workflow["edges"], workflow["variables"])
        self.assertTrue(valid, errors)


class UEDeliveryGateTests(unittest.TestCase):
    def test_gate_requires_complete_report_bundle(self):
        root = Path(tempfile.mkdtemp())
        try:
            report_dir = root / "report"
            report_dir.mkdir()
            paths = {
                "root_markdown": str(root / "sample.md"),
                "markdown": str(report_dir / "sample.md"),
                "html": str(report_dir / "sample.html"),
                "json": str(report_dir / "sample.json"),
                "log": str(report_dir / "sample.log"),
            }
            for path in paths.values():
                Path(path).write_text("evidence", encoding="utf-8")
            result = asyncio.run(UEDeliveryGateNode().execute({
                "params": {},
                "pool": {"report": {"report_paths": paths,
                                      "root_markdown": paths["root_markdown"],
                                      "log_path": paths["log"]}},
            }))
            self.assertEqual(result.status, "success", result.error)
            self.assertTrue(result.outputs["delivery_complete"])
            self.assertEqual(result.outputs["missing"], [])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_gate_fails_when_root_markdown_is_missing(self):
        root = Path(tempfile.mkdtemp())
        try:
            report_dir = root / "report"
            report_dir.mkdir()
            paths = {
                "root_markdown": str(root / "sample.md"),
                "markdown": str(report_dir / "sample.md"),
                "html": str(report_dir / "sample.html"),
                "json": str(report_dir / "sample.json"),
                "log": str(report_dir / "sample.log"),
            }
            for key, path in paths.items():
                if key != "root_markdown":
                    Path(path).write_text("evidence", encoding="utf-8")
            result = asyncio.run(UEDeliveryGateNode().execute({
                "params": {}, "pool": {"report": {"report_paths": paths}},
            }))
            self.assertEqual(result.status, "failed")
            self.assertFalse(result.outputs["delivery_complete"])
            self.assertIn("root_markdown", result.outputs["missing"])
        finally:
            shutil.rmtree(root, ignore_errors=True)


class UEReportNodeOutputTests(unittest.TestCase):
    sample = Path(__file__).resolve().parents[2] / "samples" / "ue_sample.exe"

    def test_report_node_writes_task_scoped_sample_named_bundle(self):
        root = Path(tempfile.mkdtemp())
        try:
            result = asyncio.run(UEReportNode().execute({
                "task_id": 990001,
                "params": {"sample_path": str(self.sample), "output_dir": str(root)},
                "pool": {},
            }))
            self.assertEqual(result.status, "success", result.error)
            paths = result.outputs["report_paths"]
            self.assertEqual(Path(paths["json"]).parent, root / "report")
            self.assertEqual(Path(paths["html"]).parent, root / "report")
            self.assertEqual(Path(paths["markdown"]).parent, root / "report")
            self.assertEqual(Path(paths["root_markdown"]).parent, root)
            self.assertTrue(Path(paths["root_markdown"]).is_file())
            self.assertEqual(Path(paths["json"]).stem, "ue_sample")
            self.assertTrue(Path(paths["log"]).is_file())
            log = json.loads(Path(paths["log"]).read_text(encoding="utf-8"))
            self.assertEqual(log["task_id"], 990001)
            self.assertEqual(log["runtime_evidence_status"], "not_collected")
            self.assertTrue(result.outputs["runtime_evidence_required"])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_report_node_uses_report_subdirectory_for_explicit_report_path(self):
        root = Path(tempfile.mkdtemp())
        try:
            report_dir = root / "report"
            result = asyncio.run(UEReportNode().execute({
                "task_id": 990002,
                "params": {"sample_path": str(self.sample), "output_dir": str(report_dir)},
                "pool": {},
            }))
            self.assertEqual(result.status, "success", result.error)
            self.assertTrue(Path(result.outputs["report_paths"]["html"]).is_file())
            self.assertEqual(Path(result.outputs["report_paths"]["html"]).parent, report_dir)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_report_node_uses_ctx_output_dir_without_double_report_child(self):
        root = Path(tempfile.mkdtemp())
        try:
            report_dir = root / "report"
            result = asyncio.run(UEReportNode().execute({
                "task_id": 990003,
                "output_dir": str(root),
                "params": {"sample_path": str(self.sample)},
                "pool": {},
            }))
            self.assertEqual(result.status, "success", result.error)
            self.assertEqual(Path(result.outputs["report_paths"]["html"]).parent, report_dir)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_report_node_derives_default_runs_task_report_directory(self):
        root = Path(tempfile.mkdtemp())
        db = SessionLocal()
        workflow = None
        task = None
        try:
            workflow = GraphWorkflow(
                name=f"ue-report-output-{uuid.uuid4().hex[:12]}",
                description="test", nodes=[], edges=[], variables=[],
            )
            db.add(workflow)
            db.flush()
            task = GraphTask(
                workflow_id=workflow.id, name=workflow.name,
                status="pending", variables={}, node_states={},
            )
            db.add(task)
            db.commit()
            task_id = task.id

            with patch.object(config, "OUTPUT_ROOT", root):
                result = asyncio.run(UEReportNode().execute({
                    "task_id": task_id,
                    "params": {"sample_path": str(self.sample)},
                    "pool": {},
                }))

            self.assertEqual(result.status, "success", result.error)
            report_dir = Path(result.outputs["report_dir"])
            self.assertEqual(report_dir.parent.parent, root / "runs")
            self.assertEqual(report_dir.name, "report")
            self.assertTrue(Path(result.outputs["report_paths"]["json"]).is_file())
        finally:
            if task is not None:
                db.query(GraphTask).filter(GraphTask.id == task.id).delete()
            if workflow is not None:
                db.query(GraphWorkflow).filter(GraphWorkflow.id == workflow.id).delete()
            db.commit()
            db.close()
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
