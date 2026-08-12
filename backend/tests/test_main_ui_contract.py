from __future__ import annotations

import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class MainUiContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.html = (REPOSITORY_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        self.script = (REPOSITORY_ROOT / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
        self.css = (REPOSITORY_ROOT / "frontend" / "css" / "style.css").read_text(encoding="utf-8")

    def test_environment_controls_and_api_helpers_are_wired(self):
        for value in (
            'id="environment-summary"',
            'id="environment-checks"',
            'id="btn-environment-prepare"',
            "environment: () => aiRequest('/api/environment')",
            "prepareEnvironment: (force = false)",
            "function renderEnvironment(status)",
            "function prepareEnvironment()",
        ):
            self.assertIn(value, self.html if value.startswith('id=') else self.script)

    def test_artifact_center_exposes_manifest_backed_actions(self):
        for value in (
            'id="artifact-run-list"',
            'id="artifact-detail"',
            'id="btn-artifact-output-root"',
            'id="btn-sample-output"',
        ):
            self.assertIn(value, self.html)
        for value in (
            "artifactRuns: () => aiRequest('/api/artifacts')",
            "graphArtifacts: (taskId)",
            "engineArtifacts: (engine, analysisId)",
            "openGraphArtifact: (taskId, artifactId, folder = false)",
            "openEngineArtifact: (engine, analysisId, artifactId, folder = false)",
            "function renderArtifactManifest(manifest, run)",
            "function loadEngineArtifactSummary(engine, analysisId)",
        ):
            self.assertIn(value, self.script)
        self.assertIn(".artifact-center-grid", self.css)
        self.assertIn(".environment-checks", self.css)


if __name__ == "__main__":
    unittest.main()
