from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services import report as report_svc
from app.services.ue import ai_assist
from app.services.ue.analyzer import UEAnalyzer
from app.workflow_engine.nodes.base import get_node_class, list_node_types


class AINodeRegistryTests(unittest.TestCase):
    def test_ai_nodes_are_registered(self):
        types = {row["type"] for row in list_node_types()}
        self.assertIn("ai_analyze", types)
        self.assertIn("ue_ai_assist", types)
        self.assertIsNotNone(get_node_class("ai_analyze"))
        self.assertIsNotNone(get_node_class("ue_ai_assist"))

    def test_ai_nodes_expose_schemas(self):
        by_type = {row["type"]: row for row in list_node_types()}
        prompt_keys = {field["key"] for field in by_type["ai_analyze"]["params_schema"]}
        self.assertIn("prompt", prompt_keys)
        self.assertIn("output_mode", prompt_keys)
        ue_keys = {field["key"] for field in by_type["ue_ai_assist"]["params_schema"]}
        self.assertIn("sample_path", ue_keys)


class UEAssistNormalizationTests(unittest.TestCase):
    def test_normalize_parses_addresses_and_applies_image_base(self):
        raw = {
            "three_majors": {"gnames": {"rva": "0x1234", "confidence": 90, "reason": "ok"}},
            "getname_algorithm": {"model": "fnamepool", "key_hex": "0x55"},
            "decryption_algorithm": {"detected": False},
            "notes": ["note"],
        }
        out = ai_assist.normalize_ue_assist(raw, image_base=0x140000000)
        g = out["three_majors"]["gnames"]
        self.assertEqual(g["rva"], 0x1234)
        self.assertEqual(g["absolute_va"], 0x140001234)
        self.assertEqual(g["absolute_va_hex"], "0x140001234")
        self.assertEqual(out["getname_algorithm"]["model"], "fnamepool")
        self.assertFalse(out["decryption_algorithm"]["detected"])

    def test_normalize_tolerates_missing_fields(self):
        out = ai_assist.normalize_ue_assist(None)
        self.assertEqual(out["three_majors"]["gnames"]["rva"], None)
        self.assertEqual(out["notes"], [])

    def test_build_evidence_has_expected_contract(self):
        sample = Path(__file__).resolve().parents[2] / "samples" / "revlab_sample.exe"
        if not sample.exists():
            self.skipTest("demo sample missing")
        data = sample.read_bytes()
        result = UEAnalyzer(str(sample), data=data).run()
        from app.services import pe_parser
        pe = pe_parser.parse_pe(data, str(sample))
        evidence = ai_assist.build_ue_evidence(result, data, pe)
        for key in ("gobjects", "gnames", "gworld", "gengine"):
            self.assertIn(key, evidence["globals"])
            self.assertIn("candidates", evidence["globals"][key])
        self.assertIn("getname_xor", evidence)
        self.assertIn("fname_algorithm_candidates", evidence)
        self.assertIn("image_base", evidence)


class UEAssistReportRenderingTests(unittest.TestCase):
    def _assist(self):
        return {
            "ai_output": True,
            "configured": True,
            "model": "test-model",
            "three_majors": {
                "gnames": {"rva": 0x1234, "rva_hex": "0x1234", "absolute_va_hex": "0x140001234",
                           "confidence": 90, "reason": "exact match"},
            },
            "getname_algorithm": {"model": "fnamepool", "key_hex": "", "block_bits": 16,
                                  "entry_stride": 2, "header_info_offset": 0, "wide_bit": 0,
                                  "length_shift": 6, "description": "block = id >> 16",
                                  "steps": ["step1"]},
            "decryption_algorithm": {"detected": False, "algorithm": "", "key_hex": "",
                                     "description": "no encryption", "steps": []},
            "notes": [],
        }

    def test_ue_report_renders_ai_assist_sections(self):
        ue = {"engine_version": "5.3", "ai_assist": self._assist()}
        rep = report_svc.build_report({"file_name": "t.exe"}, {"ue": ue})
        html = report_svc.to_html(rep)
        md = report_svc.to_markdown(rep)
        self.assertIn("AI 判定的三大件精确地址", html)
        self.assertIn("GetName / FName 算法", html)
        self.assertIn("解密算法", html)
        self.assertIn("AI 判定的三大件精确地址", md)
        self.assertIn("fnamepool", md)

    def test_ue_report_marks_unconfigured_ai(self):
        ue = {"ai_assist": {"ai_output": True, "configured": False,
                            "error": "AI 模型未配置", "three_majors": {},
                            "getname_algorithm": {}, "decryption_algorithm": {}, "notes": []}}
        rep = report_svc.build_report({"file_name": "t.exe"}, {"ue": ue})
        html = report_svc.to_html(rep)
        self.assertIn("UE AI 辅助分析", html)
        self.assertIn("AI 模型未配置", html)

    def test_generic_ai_outputs_rendered(self):
        rep = report_svc.build_report(
            {"file_name": "t.exe"},
            {"workflow": {"ai_outputs": {
                "ai_review": {"ai_output": True, "configured": True, "response": "PE 结论"}}}},
        )
        html = report_svc.to_html(rep)
        md = report_svc.to_markdown(rep)
        self.assertIn("AI 辅助分析输出", html)
        self.assertIn("PE 结论", html)
        self.assertIn("AI 辅助分析输出", md)

    def test_assist_parses_fenced_json_and_normalizes(self):
        cfg = {"enabled": True, "base_url": "http://fake/v1", "api_key": "x",
               "model": "m", "temperature": 0.2, "max_tokens": 2000, "timeout": 10}
        fake = json.dumps({"three_majors": {"gworld": {"rva": "0x3000"}},
                           "getname_algorithm": {"model": "direct"},
                           "decryption_algorithm": {"detected": True, "algorithm": "xor 0x55"}})
        with patch.object(ai_assist.ai_svc, "chat", return_value="```json\n" + fake + "\n```"):
            out = ai_assist.assist_ue_analysis({}, cfg)
        self.assertTrue(out["configured"])
        self.assertEqual(out["three_majors"]["gworld"]["rva"], 0x3000)
        self.assertTrue(out["decryption_algorithm"]["detected"])
        self.assertEqual(out["getname_algorithm"]["model"], "direct")

    def test_assist_safe_returns_error_struct(self):
        with patch.object(ai_assist.ai_svc, "chat",
                          side_effect=RuntimeError("boom")):
            out = ai_assist.assist_ue_analysis_safe({}, {
                "enabled": True, "base_url": "http://fake", "api_key": "x",
                "model": "m", "temperature": 0.2, "max_tokens": 2000, "timeout": 10})
        self.assertFalse(out["configured"])
        self.assertIn("boom", out["error"])
        self.assertTrue(out["ai_output"])


if __name__ == "__main__":
    unittest.main()
