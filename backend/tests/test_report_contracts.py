from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.services import report


class ReportNamingTests(unittest.TestCase):
    def test_report_stem_uses_current_sample_name_not_internal_task_id(self):
        self.assertEqual(
            report.analysis_report_name(r"F:\games\UAGame_dump.exe", "ue"),
            "UAGame_dump_ue",
        )
        self.assertEqual(
            report.analysis_report_name(r"F:\WeGameApps\rail_apps\soc(2002423)\SKJH.exe", "unity"),
            "SKJH_unity",
        )
        self.assertEqual(
            report.analysis_report_name(r"C:\games\Build.09052026", "unity"),
            "Build.09052026_unity",
        )

    def test_save_report_keeps_output_inside_selected_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            paths = report.save_report(
                report.build_report({"file_name": "sample.exe"}, {}),
                Path(temp),
                r"..\..\sample.exe",
            )
            for path in paths.values():
                self.assertEqual(Path(path).parent, Path(temp))
                self.assertTrue(Path(path).is_file())

    def test_workflow_report_publishes_primary_markdown_at_run_root(self):
        with tempfile.TemporaryDirectory() as temp:
            run_root = Path(temp) / "000001_demo"
            paths = report.save_report(
                report.build_report({"file_name": "UAGame_dump.exe"}, {}),
                run_root / "report",
                "UAGame_dump.exe",
            )
            self.assertTrue(Path(paths["markdown"]).is_file())
            self.assertTrue(Path(paths["root_markdown"]).is_file())
            self.assertEqual(Path(paths["root_markdown"]).parent, run_root)
            self.assertEqual(Path(paths["root_markdown"]).name, "UAGame_dump.md")


class UnityReportRenderingTests(unittest.TestCase):
    def test_dynamic_metadata_validation_is_rendered_in_html_and_markdown(self):
        payload = report.build_report(
            {"file_name": "SKJH.exe", "file_size": 1},
            {
                "unity": {
                    "version": {"version": "2022.3.0f1"},
                    "buildtype": {"build_type": "IL2CPP", "confidence": "high"},
                    "assembly": {"gameassembly_path": "GameAssembly.dll"},
                    "decrypt": {
                        "status": "encrypted_or_obfuscated",
                        "encrypted": True,
                        "decryption_required": True,
                        "decryption_attempted": True,
                        "decryption_status": "failed",
                        "runtime_validation": {
                            "required": True,
                            "status": "pending",
                            "reason": "build-matched decoder trace required",
                            "inputs": {"metadata": "global-metadata.dat", "gameassembly": "GameAssembly.dll", "same_build_required": True},
                            "steps": ["capture decoder"],
                            "evidence": ["before/after hash"],
                            "acceptance": ["metadata parses"],
                        },
                    },
                }
            },
        )
        html = report.to_html(payload)
        markdown = report.to_markdown(payload)
        self.assertIn("IL2CPP Metadata 与解密决策", html)
        self.assertIn("Unity 运行时解密验证要求", html)
        self.assertIn("采集步骤", html)
        self.assertIn("Unity 运行时解密验证要求", markdown)
        self.assertIn("验收标准", markdown)


if __name__ == "__main__":
    unittest.main()
