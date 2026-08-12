from __future__ import annotations

import tempfile
import unittest
import sys
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.api import routes as api_routes
from app.core.config import config
from app.services import artifacts, environment


class EnvironmentContractTests(unittest.TestCase):
    def test_environment_status_has_required_checks(self):
        status = environment.inspect_environment()
        self.assertIn("ready", status)
        self.assertIn("missing", status)
        self.assertIn("checks", status)
        keys = {item["key"] for item in status["checks"]}
        self.assertTrue({"python_venv", "node", "java", "ghidra", "upx", "pe_sieve"}.issubset(keys))

    def test_execution_gate_reports_automatic_setup_progress(self):
        pending = {
            "ready": False,
            "missing": ["ghidra", "pe_sieve"],
            "job": {"status": "running", "logs": [{"message": "Installing tools"}]},
        }
        with patch.object(api_routes, "ensure_environment_async", return_value=pending):
            with self.assertRaises(HTTPException) as raised:
                api_routes._require_execution_environment()
        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.detail["missing"], ["ghidra", "pe_sieve"])
        self.assertEqual(raised.exception.detail["job"]["status"], "running")

    def test_execution_gate_allows_ready_environment(self):
        ready = {"ready": True, "missing": [], "job": {"status": "completed"}}
        with patch.object(api_routes, "ensure_environment_async", return_value=ready):
            self.assertEqual(api_routes._require_execution_environment(), ready)


class ArtifactCollectionTests(unittest.TestCase):
    def test_historical_report_markdown_is_published_at_run_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "output"
            run_dir = root / "runs" / "000036_ue-special"
            nested = run_dir / "report" / "UAGame_dump.md"
            nested.parent.mkdir(parents=True)
            nested.write_text("# UE report", encoding="utf-8")
            rows = [{
                "id": "nested",
                "name": nested.name,
                "relative_path": nested.relative_to(root).as_posix(),
                "kind": "report",
                "source_nodes": ["report"],
                "size": nested.stat().st_size,
                "is_directory": False,
                "materialization": "existing",
            }]
            with patch.object(config, "OUTPUT_ROOT", root):
                upgraded = artifacts._ensure_run_root_markdown(run_dir, rows)
            primary = run_dir / "UAGame_dump.md"
            self.assertTrue(primary.is_file())
            self.assertEqual(primary.read_text(encoding="utf-8"), "# UE report")
            self.assertIn(primary.relative_to(root).as_posix(),
                          {item["relative_path"] for item in upgraded})

    def test_collects_only_manifestable_output_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "output"
            report = root / "reports" / "run.html"
            cpp = root / "sdk" / "sdk_demo" / "sdk_cpp"
            report.parent.mkdir(parents=True)
            cpp.mkdir(parents=True)
            report.write_text("report", encoding="utf-8")
            (cpp / "Game.hpp").write_text("header", encoding="utf-8")
            outside = Path(temp) / "outside.bin"
            outside.write_bytes(b"outside")
            task = SimpleNamespace(
                node_states={
                    "report": {"outputs": {"report_paths": {"html": str(report)}}},
                    "sdk": {"outputs": {"cpp_dir": str(cpp)}},
                    "other": {"outputs": {"path": str(outside)}},
                    "empty": {"outputs": {"decrypted_path": ""}},
                }
            )
            with patch.object(config, "OUTPUT_ROOT", root):
                rows = artifacts._collect_artifacts(task)
            paths = {row["relative_path"] for row in rows}
            self.assertIn("reports/run.html", paths)
            self.assertIn("sdk/sdk_demo/sdk_cpp/Game.hpp", paths)
            self.assertNotIn("../outside.bin", paths)
            self.assertNotIn(".", paths)

    def test_cached_task_manifest_is_read_without_refresh(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest_path = Path(temp) / "manifest.json"
            payload = {"task": {"id": 7}, "artifacts": [{"id": "demo"}]}
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")
            with patch.object(artifacts, "_manifest_path_for_task", return_value=manifest_path):
                self.assertEqual(artifacts._cached_task_manifest(7), payload)

    def test_open_output_root_uses_configured_root(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(config, "OUTPUT_ROOT", Path(temp)), patch.object(artifacts.subprocess, "Popen") as popen:
            result = artifacts.open_output_root()
            self.assertEqual(Path(result["opened"]), Path(temp).resolve())
            popen.assert_called_once()


if __name__ == "__main__":
    unittest.main()
