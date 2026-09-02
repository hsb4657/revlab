from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import config
from app.services import environment, pcap, sandbox, ghidra_bridge
from app.workflow_engine import manager
from app.workflow_engine.nodes.analysis import DynamicAnalyzeNode
from app.workflow_engine.nodes.control import CommandNode, ScriptNode


class CaptureSessionTests(unittest.TestCase):
    def _write_pcap(self, _etl: str, pcap_path: str) -> bool:
        Path(pcap_path).write_bytes(b"pcap")
        return True

    def test_session_uses_distinct_etl_and_pcap_paths(self):
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(pcap, "pktmon_start", return_value=True), \
                patch.object(pcap, "pktmon_stop", return_value=True), \
                patch.object(pcap, "pktmon_etl2pcap", side_effect=self._write_pcap), \
                patch.object(pcap, "parse_pcap", return_value={"packet_count": 3}):
            session = pcap.start_capture_session(str(Path(temp) / "capture.pcap"))
            self.assertTrue(session["started"])
            self.assertNotEqual(session["etl_path"], session["pcap_path"])
            self.assertTrue(session["etl_path"].endswith(".etl"))
            result = pcap.finish_capture_session(session)
        self.assertTrue(result["ok"])
        self.assertEqual(result["packet_count"], 3)

    def test_custom_etl_path_is_started_once(self):
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(pcap, "pktmon_start", return_value=True) as start, \
                patch.object(pcap, "pktmon_stop", return_value=True), \
                patch.object(pcap, "pktmon_etl2pcap", side_effect=self._write_pcap), \
                patch.object(pcap, "parse_pcap", return_value={}), \
                patch.object(pcap.time, "sleep"):
            etl = str(Path(temp) / "explicit.etl")
            result = pcap.capture_network(1, str(Path(temp) / "capture.pcap"), etl)
        self.assertTrue(result["ok"])
        start.assert_called_once_with(etl)

    def test_missing_pktmon_is_reported_as_capture_capability_failure(self):
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(pcap.subprocess, "run", side_effect=FileNotFoundError):
            session = pcap.start_capture_session(str(Path(temp) / "capture.pcap"))
            self.assertFalse(session["started"])
            result = pcap.finish_capture_session(session)
        self.assertFalse(result["ok"])
        self.assertIn("pktmon", result["error"])


class ExecutionPolicyTests(unittest.TestCase):
    def test_auto_mode_never_selects_vmware(self):
        with patch.object(config, "DYNAMIC_BACKEND", "auto"), \
                patch.object(sandbox, "sandboxie_available", return_value=False), \
                patch.object(sandbox, "windows_sandbox_available", return_value=False), \
                patch.object(sandbox, "vm_configured", return_value=True):
            capabilities = sandbox.sandbox_capabilities()
        self.assertEqual(capabilities["selected"], "blocked")
        self.assertTrue(capabilities["backends"]["vmware"]["manual_only"])

    def test_sandboxie_runner_can_be_detected_without_starting_it(self):
        fake_start = Path(tempfile.gettempdir()) / "Start.exe"
        with patch.object(sandbox, "_sandboxie_start_path", return_value=fake_start), \
                patch.object(sandbox.os, "name", "nt"):
            runner = sandbox.SandboxieRunner(timeout=2)
        self.assertEqual(runner.backend, "sandboxie")
        self.assertEqual(runner.box_name, "REVLab")

    def test_host_sandbox_requires_explicit_opt_in(self):
        with patch.object(config, "USE_SANDBOX_VM", False), \
                patch.object(config, "ALLOW_HOST_EXECUTION", False):
            with self.assertRaises(sandbox.SandboxError):
                sandbox.create_sandbox()

    def test_host_sandbox_accepts_one_shot_user_confirmation(self):
        with patch.object(config, "USE_SANDBOX_VM", False), \
                patch.object(config, "ALLOW_HOST_EXECUTION", False):
            runner = sandbox.create_sandbox(mode="host", confirm_host_execution=True, timeout=1)
        self.assertIsInstance(runner, sandbox.LocalSandbox)
        self.assertEqual(runner.timeout, 1)

    def test_dynamic_node_reports_policy_block_without_running_sample(self):
        ctx = {"params": {"timeout": 1}, "pool": {}, "task_id": 7}
        with patch.object(config, "USE_SANDBOX_VM", False), \
                patch.object(config, "ALLOW_HOST_EXECUTION", False):
            result = asyncio.run(DynamicAnalyzeNode().execute(ctx))
        self.assertEqual(result.status, "success")
        self.assertFalse(result.outputs["executed"])
        self.assertEqual(result.outputs["execution_status"], "blocked_by_policy")

    def test_dangerous_nodes_are_disabled_by_default(self):
        with patch.object(config, "ENABLE_UNSAFE_NODES", False):
            script = asyncio.run(ScriptNode().execute({"params": {"script": "print(1)"}, "pool": {}}))
            command = asyncio.run(CommandNode().execute({"params": {"command": "echo test"}, "pool": {}}))
        self.assertEqual(script.status, "failed")
        self.assertEqual(command.status, "failed")


class WorkflowSnapshotTests(unittest.TestCase):
    def test_snapshot_is_immutable_and_content_addressed(self):
        workflow = SimpleNamespace(
            name="demo",
            description="snapshot test",
            nodes=[{"id": "start", "type": "start", "params": {}}],
            edges=[],
            variables=[],
        )
        snapshot, digest = manager._workflow_snapshot(workflow)
        workflow.nodes[0]["type"] = "command"
        self.assertEqual(snapshot["nodes"][0]["type"], "start")
        self.assertEqual(len(digest), 64)

    def test_optional_analyzers_do_not_block_core_preflight(self):
        checks = {item["key"]: item for item in environment.inspect_environment()["checks"]}
        for key in ("ghidra", "upx", "pe_sieve", "il2cpp_dumper"):
            self.assertFalse(checks[key]["required"])

    def test_ghidra_directory_without_headless_launcher_is_not_ready(self):
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(ghidra_bridge.config, "GHIDRA_HOME", temp), \
                patch("glob.glob", return_value=[]):
            self.assertEqual(ghidra_bridge.find_ghidra_home(), "")



if __name__ == "__main__":
    unittest.main()
