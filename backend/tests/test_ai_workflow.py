from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.api.routes import router
from app.core.database import Base
from app.models.sample import AIChatMessage
from app.services import ai_workflow
from app.workflow_engine.definition import validate_graph


def valid_model_graph() -> dict:
    return {
        "name": "Model draft",
        "description": "A graph returned by a mocked model.",
        "nodes": [
            {"id": "start", "label": "Start", "type": "start", "params": {}},
            {"id": "branch", "label": "Branch", "type": "condition", "params": {}},
            {"id": "strings", "label": "Strings", "type": "strings", "params": {}},
            {"id": "report", "label": "Report", "type": "report", "params": {}},
        ],
        "edges": [
            {"id": "e1", "from": "start", "to": "branch"},
            {"id": "e2", "from": "branch", "to": "strings", "condition": "true"},
            {"id": "e3", "from": "branch", "to": "report", "is_default": True},
            {"id": "e4", "from": "strings", "to": "report"},
        ],
        "variables": [],
    }


class WorkflowDraftTests(unittest.TestCase):
    def test_local_rule_generator_covers_pe_ue_unity_with_branches_and_report(self):
        cases = [
            ("Create a PE packer analysis", "local-rules:pe", "pe_identify", "pe_ai_assist"),
            ("Create an Unreal UE5 GObjects workflow", "local-rules:ue", "ue_analyze", "ue_ai_assist"),
            ("Create a Unity IL2CPP metadata workflow", "local-rules:unity", "unity_analyze", "unity_ai_assist"),
        ]
        for prompt, generator, expected_type, expected_ai in cases:
            with self.subTest(prompt=prompt):
                result = ai_workflow.generate_workflow(prompt, cfg={"enabled": False})
                self.assertEqual(result["generator"], generator)
                self.assertTrue(result["editable"])
                self.assertIn(expected_type, [node["type"] for node in result["nodes"]])
                self.assertIn(expected_ai, [node["type"] for node in result["nodes"]])
                self.assertIn("condition", [node["type"] for node in result["nodes"]])
                self.assertIn("report", [node["type"] for node in result["nodes"]])
                valid, errors = validate_graph(result["nodes"], result["edges"], result["variables"])
                self.assertTrue(valid, errors)

    def test_fenced_model_json_is_extracted_and_validated(self):
        graph = valid_model_graph()
        response = "Model notes before JSON.\n```json\n" + __import__("json").dumps(graph) + "\n```"
        cfg = {"enabled": True, "base_url": "http://model/v1", "model": "test", "api_key": "key"}
        with patch.object(ai_workflow.ai, "chat", return_value=response) as chat:
            result = ai_workflow.generate_workflow("Build a branch workflow", cfg=cfg)
        self.assertEqual(result["generator"], "ai")
        chat.assert_called_once()
        valid, errors = validate_graph(result["nodes"], result["edges"], result["variables"])
        self.assertTrue(valid, errors)

    def test_model_graph_repairs_missing_default_branch_but_rejects_unknown_nodes(self):
        repairable = valid_model_graph()
        repairable["edges"][2].pop("is_default")
        graph, warnings = ai_workflow.prepare_workflow_definition(repairable, repair=True)
        self.assertTrue(warnings)
        valid, errors = validate_graph(graph["nodes"], graph["edges"], graph["variables"])
        self.assertTrue(valid, errors)

        invalid = valid_model_graph()
        invalid["nodes"][1]["type"] = "not_a_registered_node"
        with self.assertRaises(ai_workflow.AIWorkflowError) as ctx:
            ai_workflow.prepare_workflow_definition(invalid, repair=True)
        self.assertEqual(ctx.exception.code, "unknown_workflow_node")


class PersistentSessionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tempdir.name) / 'ai-test.db'}")
        Base.metadata.create_all(self.engine)
        self.factory = sessionmaker(bind=self.engine, autoflush=False, autocommit=False, expire_on_commit=False)
        self.original_session_local = ai_workflow.SessionLocal
        ai_workflow.SessionLocal = self.factory

    def tearDown(self):
        ai_workflow.SessionLocal = self.original_session_local
        self.engine.dispose()
        self.tempdir.cleanup()

    def test_session_settings_are_independent_and_compaction_keeps_history(self):
        first = ai_workflow.create_chat_session(title="First", model="model-a", reasoning="high")
        second = ai_workflow.create_chat_session(title="Second", model="model-b", reasoning="low")
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(first["model"], "model-a")
        self.assertEqual(first["reasoning"], "high")
        self.assertEqual(second["model"], "model-b")
        self.assertEqual(second["reasoning"], "low")

        changed = ai_workflow.update_chat_session(first["id"], title="Renamed", model="model-c", reasoning="balanced")
        self.assertEqual(changed["title"], "Renamed")
        self.assertEqual(changed["model"], "model-c")
        self.assertEqual(changed["reasoning"], "balanced")
        self.assertEqual(ai_workflow.get_chat_session(second["id"], False)["session"]["model"], "model-b")

        db = self.factory()
        try:
            for index in range(30):
                db.add(AIChatMessage(
                    session_id=first["id"], role="user" if index % 2 == 0 else "assistant",
                    content=f"turn {index}: " + ("x" * 900), model="model-c", reasoning="balanced",
                ))
            db.commit()
        finally:
            db.close()
        compact = ai_workflow.compact_chat_session(first["id"], force=True, use_ai=False)
        self.assertTrue(compact["compressed"])
        detail = ai_workflow.get_chat_session(first["id"])
        self.assertTrue(detail["session"]["summary"])
        self.assertGreater(detail["session"]["summary_upto"], 0)
        self.assertEqual(len(detail["messages"]), 30)

        self.assertTrue(ai_workflow.delete_chat_session(first["id"]))
        with self.assertRaises(ai_workflow.AIWorkflowError):
            ai_workflow.get_chat_session(first["id"])

    def test_send_persists_turns_and_uses_the_session_model_and_reasoning(self):
        session = ai_workflow.create_chat_session(title="Per-session", model="session-model", reasoning="high")
        config = {"enabled": True, "base_url": "http://model/v1", "model": "global-model", "api_key": "key"}
        with patch.object(ai_workflow.ai, "load_config", return_value=config), \
             patch.object(ai_workflow.ai, "chat", return_value="persisted reply") as chat:
            result = ai_workflow.send_chat_message(session["id"], "Explain the graph")
        self.assertEqual(result["reply"], "persisted reply")
        self.assertEqual(result["session"]["model"], "session-model")
        self.assertEqual(result["session"]["reasoning"], "high")
        runtime_config = chat.call_args.args[0]
        self.assertEqual(runtime_config["model"], "session-model")
        self.assertEqual(runtime_config["temperature"], 0.08)
        self.assertEqual(runtime_config["max_tokens"], 5000)
        detail = ai_workflow.get_chat_session(session["id"])
        self.assertEqual([message["role"] for message in detail["messages"]], ["user", "assistant"])


class WorkflowRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app = FastAPI()
        app.include_router(router)
        cls.client = TestClient(app)

    def test_generate_and_save_routes_return_editable_valid_graph(self):
        generated = self.client.post("/api/ai/workflows/generate", json={"prompt": "Unity IL2CPP metadata"})
        self.assertEqual(generated.status_code, 200, generated.text)
        draft = generated.json()
        self.assertTrue(draft["editable"])
        self.assertEqual(draft["generator"], "local-rules:unity")
        valid, errors = validate_graph(draft["nodes"], draft["edges"], draft["variables"])
        self.assertTrue(valid, errors)

        with patch("app.workflow_engine.manager.list_workflows", return_value=[]), \
             patch("app.workflow_engine.manager.create_workflow", return_value={"ok": True, "id": 991}) as create:
            saved = self.client.post("/api/ai/workflows/save", json={"workflow": draft["workflow"], "generator": draft["generator"]})
        self.assertEqual(saved.status_code, 200, saved.text)
        body = saved.json()
        self.assertEqual(body["id"], 991)
        self.assertEqual(body["action"], "created")
        self.assertTrue(body["editable"])
        create.assert_called_once()


if __name__ == "__main__":
    unittest.main()
