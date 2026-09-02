"""Persistent AI chat orchestration and editable graph-workflow drafts.

The module deliberately keeps provider access in :mod:`app.services.ai` so
every OpenAI-compatible provider uses one transport.  It adds two layers on
top of that transport:

* durable, per-conversation model and reasoning settings with compacted
  context; and
* JSON-only workflow draft generation that is validated against the live node
  registry before it reaches the visual editor or database.
"""
from __future__ import annotations

import copy
import json
import re
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func

from ..core.database import SessionLocal
from ..models.sample import AIChatMessage, AIChatSession, Sample
from ..workflow_engine import definition as graph_definition
from ..workflow_engine.conditions import validate_expression
from ..workflow_engine.nodes.base import list_node_types
from . import ai


REASONING_PRESETS = {
    "low": {"temperature": 0.35, "max_tokens": 1400},
    "balanced": {"temperature": 0.20, "max_tokens": 2400},
    "high": {"temperature": 0.08, "max_tokens": 5000},
}
REASONING_ALIASES = {
    "fast": "low", "quick": "low", "low": "low", "rapid": "low",
    "balanced": "balanced", "normal": "balanced", "medium": "balanced",
    "high": "high", "deep": "high", "thorough": "high",
    "快速": "low", "平衡": "balanced", "深度": "high",
}
ALLOWED_ROLES = {"user", "assistant", "system"}
DEFAULT_SESSION_TITLE = "New conversation"
DEFAULT_SYSTEM_PROMPT = (
    "You are REVLab's binary-analysis workflow assistant. Give precise, "
    "practical answers grounded in the active sample and conversation. "
    "When planning a workflow, make each branch and expected artifact explicit."
)
MAX_MESSAGE_CHARS = 50000
CONTEXT_CHAR_LIMIT = 18000
CONTEXT_MESSAGE_LIMIT = 24
CONTEXT_RECENT_MESSAGES = 12
SUMMARY_CHAR_LIMIT = 6500


class AIWorkflowError(RuntimeError):
    """An API-safe error with a stable code and HTTP status."""

    def __init__(self, message: str, *, code: str = "ai_workflow_error",
                 status_code: int = 422, warnings: list[str] | None = None):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.warnings = warnings or []


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def normalize_reasoning(value: Any, default: str = "balanced") -> str:
    key = str(value or default).strip().lower()
    return REASONING_ALIASES.get(key, default)


def _clean_text(value: Any, default: str = "", limit: int | None = None) -> str:
    if value is None:
        text = default
    elif isinstance(value, str):
        text = value.strip()
    else:
        text = str(value).strip()
    return text[:limit] if limit else text


def _json_clone(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False))
    except (TypeError, ValueError) as exc:
        raise AIWorkflowError("Workflow definition must contain JSON-compatible values",
                              code="workflow_not_json") from exc


def _model_is_configured(cfg: dict) -> bool:
    # Keep the existing REVLab configuration contract: an enabled provider is
    # usable only after its endpoint, model and credential have all been saved.
    return bool(cfg.get("enabled") and cfg.get("base_url") and cfg.get("model") and cfg.get("api_key"))


def _require_model_config(cfg: dict):
    if not _model_is_configured(cfg):
        raise AIWorkflowError(
            "AI model is not enabled or is missing base_url/model configuration",
            code="ai_not_configured", status_code=400,
        )


def apply_session_settings(cfg: dict, model: str = "", reasoning: str = "balanced") -> dict:
    """Return a provider config with a session's model and reasoning applied."""
    runtime = dict(cfg or {})
    if _clean_text(model):
        runtime["model"] = _clean_text(model, limit=256)
    level = normalize_reasoning(reasoning)
    runtime.update(REASONING_PRESETS[level])
    return runtime


def _session_payload(session: AIChatSession, message_count: int = 0,
                     include_summary: bool = True) -> dict:
    result = {
        "id": session.id,
        "title": session.title or DEFAULT_SESSION_TITLE,
        "model": session.model or "",
        "reasoning": normalize_reasoning(session.reasoning),
        "sample_id": int(session.sample_id or 0),
        "message_count": int(message_count),
        "summary_upto": int(session.summary_upto or 0),
        "created_at": session.created_at.isoformat() + "Z" if session.created_at else None,
        "updated_at": session.updated_at.isoformat() + "Z" if session.updated_at else None,
    }
    if include_summary:
        result["summary"] = session.summary or ""
    return result


def _message_payload(message: AIChatMessage) -> dict:
    return {
        "id": message.id,
        "role": message.role,
        "content": message.content or "",
        "model": message.model or "",
        "reasoning": normalize_reasoning(message.reasoning),
        "created_at": message.created_at.isoformat() + "Z" if message.created_at else None,
    }


def _get_session(db, session_id: str) -> AIChatSession:
    session = db.query(AIChatSession).filter(AIChatSession.id == str(session_id)).first()
    if not session:
        raise AIWorkflowError("AI conversation not found", code="session_not_found", status_code=404)
    return session


def _validate_sample_id(db, sample_id: Any) -> int:
    try:
        sid = int(sample_id or 0)
    except (TypeError, ValueError) as exc:
        raise AIWorkflowError("sample_id must be an integer", code="invalid_sample_id", status_code=400) from exc
    if sid and not db.query(Sample.id).filter(Sample.id == sid).first():
        raise AIWorkflowError("Sample not found", code="sample_not_found", status_code=404)
    return sid


def create_chat_session(*, title: str = "", model: str = "", reasoning: str = "balanced",
                        sample_id: int = 0, system_prompt: str = "") -> dict:
    """Create an independent persistent conversation with its own runtime settings."""
    db = SessionLocal()
    try:
        sid = _validate_sample_id(db, sample_id)
        row = AIChatSession(
            id=str(uuid.uuid4()),
            title=_clean_text(title, DEFAULT_SESSION_TITLE, 256) or DEFAULT_SESSION_TITLE,
            model=_clean_text(model, limit=256),
            reasoning=normalize_reasoning(reasoning),
            sample_id=sid,
            system_prompt=_clean_text(system_prompt, limit=8000),
            summary="",
            summary_upto=0,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return _session_payload(row, 0)
    finally:
        db.close()


def list_chat_sessions(limit: int = 100) -> list[dict]:
    limit = max(1, min(int(limit or 100), 1000))
    db = SessionLocal()
    try:
        rows = db.query(AIChatSession).order_by(AIChatSession.updated_at.desc(), AIChatSession.created_at.desc()) \
            .limit(limit).all()
        if not rows:
            return []
        ids = [row.id for row in rows]
        counts = dict(
            db.query(AIChatMessage.session_id, func.count(AIChatMessage.id))
            .filter(AIChatMessage.session_id.in_(ids))
            .group_by(AIChatMessage.session_id)
            .all()
        )
        return [_session_payload(row, counts.get(row.id, 0), include_summary=False) for row in rows]
    finally:
        db.close()


def get_chat_session(session_id: str, include_messages: bool = True) -> dict:
    db = SessionLocal()
    try:
        row = _get_session(db, session_id)
        messages = []
        if include_messages:
            messages = db.query(AIChatMessage).filter(AIChatMessage.session_id == row.id) \
                .order_by(AIChatMessage.id).all()
        count = len(messages) if include_messages else db.query(AIChatMessage) \
            .filter(AIChatMessage.session_id == row.id).count()
        return {
            "session": _session_payload(row, count),
            "messages": [_message_payload(message) for message in messages],
        }
    finally:
        db.close()


def update_chat_session(session_id: str, **changes) -> dict:
    """Rename a session or change its per-session model, reasoning and sample context."""
    db = SessionLocal()
    try:
        row = _get_session(db, session_id)
        if "title" in changes:
            title = _clean_text(changes.get("title"), limit=256)
            if not title:
                raise AIWorkflowError("Conversation title is required", code="invalid_session_title", status_code=400)
            row.title = title
        if "model" in changes:
            row.model = _clean_text(changes.get("model"), limit=256)
        if "reasoning" in changes:
            row.reasoning = normalize_reasoning(changes.get("reasoning"))
        if "sample_id" in changes:
            row.sample_id = _validate_sample_id(db, changes.get("sample_id"))
        if "system_prompt" in changes:
            row.system_prompt = _clean_text(changes.get("system_prompt"), limit=8000)
        db.commit()
        db.refresh(row)
        count = db.query(AIChatMessage).filter(AIChatMessage.session_id == row.id).count()
        return _session_payload(row, count)
    finally:
        db.close()


def delete_chat_session(session_id: str) -> bool:
    db = SessionLocal()
    try:
        row = _get_session(db, session_id)
        db.query(AIChatMessage).filter(AIChatMessage.session_id == row.id).delete(synchronize_session=False)
        db.delete(row)
        db.commit()
        return True
    finally:
        db.close()


def _short_content(value: str, limit: int = 700) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _deterministic_summary(previous: str, messages: list[AIChatMessage]) -> str:
    lines = []
    if previous:
        lines.append("Prior summary: " + _short_content(previous, 1800))
    for message in messages:
        role = "User" if message.role == "user" else "Assistant" if message.role == "assistant" else "System"
        lines.append(f"{role}: {_short_content(message.content, 700)}")
    result = "\n".join(lines)
    return result if len(result) <= SUMMARY_CHAR_LIMIT else result[:SUMMARY_CHAR_LIMIT - 3] + "..."


def _messages_for_summary(messages: list[AIChatMessage]) -> str:
    return "\n".join(
        f"{message.role}: {_short_content(message.content, 1400)}"
        for message in messages
    )


def _summary_with_ai(cfg: dict, previous: str, messages: list[AIChatMessage]) -> str:
    prompt = (
        "Summarize the prior REVLab conversation for future context. Preserve user goals, "
        "technical decisions, unresolved questions, sample-specific facts, and workflow "
        "requirements. Be concise, factual, and do not invent results.\n\n"
        f"Existing summary:\n{previous or '(none)'}\n\n"
        f"Turns to compact:\n{_messages_for_summary(messages)}"
    )
    compact_cfg = dict(cfg)
    compact_cfg["temperature"] = 0.1
    compact_cfg["max_tokens"] = min(int(compact_cfg.get("max_tokens", 1400) or 1400), 1400)
    result = ai.chat(compact_cfg, [
        {"role": "system", "content": "Return only a compact conversation summary."},
        {"role": "user", "content": prompt},
    ])
    return _short_content(result, SUMMARY_CHAR_LIMIT)


def compact_chat_session(session_id: str, *, force: bool = False, use_ai: bool = True,
                         cfg: dict | None = None) -> dict:
    """Compact older stored turns into a durable summary without deleting history."""
    db = SessionLocal()
    try:
        row = _get_session(db, session_id)
        messages = db.query(AIChatMessage).filter(AIChatMessage.session_id == row.id) \
            .order_by(AIChatMessage.id).all()
        covered = max(0, min(int(row.summary_upto or 0), len(messages)))
        recent = messages[covered:]
        chars = len(row.summary or "") + sum(len(message.content or "") for message in recent)
        if not force and len(recent) <= CONTEXT_MESSAGE_LIMIT and chars <= CONTEXT_CHAR_LIMIT:
            return {
                "ok": True, "compressed": False, "reason": "context_within_limit",
                "summary_upto": covered, "message_count": len(messages), "warnings": [],
            }
        cutoff = len(messages) - CONTEXT_RECENT_MESSAGES
        if cutoff <= covered:
            return {
                "ok": True, "compressed": False, "reason": "not_enough_older_turns",
                "summary_upto": covered, "message_count": len(messages), "warnings": [],
            }
        segment = messages[covered:cutoff]
        warnings: list[str] = []
        runtime_cfg = apply_session_settings(cfg or ai.load_config(), row.model, row.reasoning)
        summary = ""
        if use_ai and _model_is_configured(runtime_cfg):
            try:
                summary = _summary_with_ai(runtime_cfg, row.summary or "", segment)
            except Exception as exc:  # The deterministic summary retains continuity on provider failure.
                warnings.append(f"AI compression failed; used local compaction: {exc}")
        if not summary:
            summary = _deterministic_summary(row.summary or "", segment)
        row.summary = summary
        row.summary_upto = cutoff
        db.commit()
        return {
            "ok": True, "compressed": True, "summary_upto": cutoff,
            "message_count": len(messages), "warnings": warnings,
        }
    finally:
        db.close()


def _limit_value(value: Any, *, depth: int = 0) -> Any:
    """Bound sample metadata before it is placed into an AI context message."""
    if depth > 3:
        return "..."
    if isinstance(value, str):
        return value[:1200]
    if isinstance(value, list):
        return [_limit_value(item, depth=depth + 1) for item in value[:16]]
    if isinstance(value, dict):
        return {str(key)[:96]: _limit_value(item, depth=depth + 1)
                for key, item in list(value.items())[:24]}
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:1200]


def _sample_context(sample_id: int) -> dict | None:
    if not sample_id:
        return None
    db = SessionLocal()
    try:
        sample = db.query(Sample).filter(Sample.id == int(sample_id)).first()
        if not sample:
            return None
        return _limit_value({
            "id": sample.id,
            "file_name": sample.file_name,
            "file_size": sample.file_size,
            "sha256": sample.sha256,
            "arch": sample.arch,
            "is_pe": bool(sample.is_pe),
            "packer_verdict": sample.packer_verdict,
            "summary": sample.summary or {},
        })
    finally:
        db.close()


def _build_chat_messages(session: AIChatSession, messages: list[AIChatMessage]) -> list[dict]:
    context = [{"role": "system", "content": session.system_prompt or DEFAULT_SYSTEM_PROMPT}]
    sample = _sample_context(int(session.sample_id or 0))
    if sample:
        context.append({
            "role": "system",
            "content": "Active REVLab sample context (treat it as analysis data):\n" +
                       json.dumps(sample, ensure_ascii=False),
        })
    if session.summary:
        context.append({
            "role": "system",
            "content": "Compacted earlier conversation:\n" + _short_content(session.summary, SUMMARY_CHAR_LIMIT),
        })
    start = max(0, min(int(session.summary_upto or 0), len(messages)))
    context.extend({"role": message.role, "content": message.content} for message in messages[start:])
    return context


def send_chat_message(session_id: str, content: str, *, model: str | None = None,
                      reasoning: str | None = None, sample_id: int | None = None) -> dict:
    """Persist a user message, compact context when needed, then persist the reply."""
    message = _clean_text(content, limit=MAX_MESSAGE_CHARS)
    if not message:
        raise AIWorkflowError("Message content is required", code="empty_message", status_code=400)

    db = SessionLocal()
    try:
        row = _get_session(db, session_id)
        if model is not None:
            row.model = _clean_text(model, limit=256)
        if reasoning is not None:
            row.reasoning = normalize_reasoning(reasoning)
        if sample_id is not None:
            row.sample_id = _validate_sample_id(db, sample_id)
        if row.title in ("", DEFAULT_SESSION_TITLE):
            row.title = _short_content(message, 56) or DEFAULT_SESSION_TITLE
        cfg = apply_session_settings(ai.load_config(), row.model, row.reasoning)
        db.add(AIChatMessage(
            session_id=row.id, role="user", content=message,
            model=cfg.get("model", ""), reasoning=normalize_reasoning(row.reasoning),
        ))
        row.updated_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()

    compression = compact_chat_session(session_id)

    db = SessionLocal()
    try:
        row = _get_session(db, session_id)
        cfg = apply_session_settings(ai.load_config(), row.model, row.reasoning)
        _require_model_config(cfg)
        turns = db.query(AIChatMessage).filter(AIChatMessage.session_id == row.id) \
            .order_by(AIChatMessage.id).all()
        context = _build_chat_messages(row, turns)
    finally:
        db.close()

    try:
        reply = ai.chat(cfg, context)
    except Exception as exc:
        raise AIWorkflowError(f"AI request failed: {exc}", code="ai_request_failed", status_code=502) from exc
    reply = _clean_text(reply, limit=MAX_MESSAGE_CHARS)
    if not reply:
        raise AIWorkflowError("AI returned an empty reply", code="empty_ai_reply", status_code=502)

    db = SessionLocal()
    try:
        row = _get_session(db, session_id)
        db.add(AIChatMessage(
            session_id=row.id, role="assistant", content=reply,
            model=cfg.get("model", ""), reasoning=normalize_reasoning(row.reasoning),
        ))
        row.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(row)
        count = db.query(AIChatMessage).filter(AIChatMessage.session_id == row.id).count()
        return {
            "ok": True,
            "reply": reply,
            "session": _session_payload(row, count),
            "compression": compression,
        }
    finally:
        db.close()


def chat_with_overrides(messages: list[dict], *, model: str = "", reasoning: str = "balanced") -> str:
    """Compatibility helper for the original stateless ``/api/ai/chat`` endpoint."""
    if not isinstance(messages, list) or not messages:
        raise AIWorkflowError("messages required", code="messages_required", status_code=400)
    cleaned = []
    for item in messages:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role", "user")).strip().lower()
        content = _clean_text(item.get("content"), limit=MAX_MESSAGE_CHARS)
        if role in ALLOWED_ROLES and content:
            cleaned.append({"role": role, "content": content})
    if not cleaned:
        raise AIWorkflowError("No valid chat messages", code="messages_required", status_code=400)
    cfg = apply_session_settings(ai.load_config(), model, reasoning)
    _require_model_config(cfg)
    try:
        return ai.chat(cfg, cleaned)
    except Exception as exc:
        raise AIWorkflowError(f"AI request failed: {exc}", code="ai_request_failed", status_code=502) from exc


# -------------------------------------------------------------------------
# Editable graph workflow draft generation

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)
_ID_RE = re.compile(r"[^A-Za-z0-9_-]+")
_TYPE_ALIASES = {
    "pe": "pe_identify", "pe_analyze": "pe_identify", "pe_analysis": "pe_identify",
    "packer": "packer_detect", "detect_packer": "packer_detect",
    "ghidra": "decompile", "ghidra_decompile": "decompile", "decompilation": "decompile",
    "unreal": "ue_analyze", "ue": "ue_analyze", "unreal_engine": "ue_analyze",
    "ue_ai": "ue_ai_assist", "ue_ai_assist": "ue_ai_assist",
    "unity": "unity_analyze", "il2cpp": "unity_analyze",
    "sdk": "sdk_dump", "sdkdump": "sdk_dump", "unity_sdk_dump": "sdk_dump",
    "branch": "condition", "if": "condition", "decision": "condition",
    "generate_report": "report", "output": "report",
    "ai": "ai_analyze", "ai_analyze": "ai_analyze", "ai_node": "ai_analyze",
    "ai_assist": "ai_analyze", "llm": "ai_analyze",
}


def extract_json_payload(content: Any) -> dict:
    """Extract the first JSON object from raw or fenced model output."""
    if isinstance(content, dict):
        return _json_clone(content)
    if not isinstance(content, str):
        raise AIWorkflowError("AI workflow response is not JSON text", code="workflow_json_missing")
    source = content.strip().lstrip("\ufeff")
    candidates = [match.group(1).strip() for match in _FENCE_RE.finditer(source)] + [source]
    decoder = json.JSONDecoder()
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except (TypeError, ValueError):
            pass
        for start in re.finditer(r"[\{\[]", candidate):
            try:
                parsed, _ = decoder.raw_decode(candidate[start.start():])
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, dict):
                return parsed
    raise AIWorkflowError("AI workflow response did not contain a JSON object", code="workflow_json_missing")


def _unwrap_graph(raw: dict) -> dict:
    for key in ("workflow", "graph", "workflow_definition", "definition", "data"):
        nested = raw.get(key) if isinstance(raw, dict) else None
        if isinstance(nested, dict) and any(name in nested for name in ("nodes", "edges", "variables")):
            return nested
    return raw


def _safe_identifier(value: Any, prefix: str, index: int, used: set[str]) -> str:
    text = _ID_RE.sub("_", _clean_text(value)).strip("_").lower()
    if not text:
        text = f"{prefix}_{index + 1}"
    if text[0].isdigit():
        text = f"{prefix}_{text}"
    base = text[:80]
    text = base
    suffix = 2
    while text in used:
        tail = f"_{suffix}"
        text = base[:80 - len(tail)] + tail
        suffix += 1
    used.add(text)
    return text


def _canonical_node_type(value: Any) -> str:
    raw = _clean_text(value).lower().replace("-", "_").replace(" ", "_")
    return _TYPE_ALIASES.get(raw, raw)


def _known_node_types() -> set[str]:
    return {row["type"] for row in list_node_types()}


def _normalize_nodes(raw_nodes: Any, *, repair: bool, warnings: list[str]) -> tuple[list[dict], dict[str, Any]]:
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise AIWorkflowError("Workflow requires a non-empty nodes array", code="workflow_nodes_missing")
    known = _known_node_types()
    nodes: list[dict] = []
    id_map: dict[str, Any] = {}
    used: set[str] = set()
    for index, source in enumerate(raw_nodes):
        if not isinstance(source, dict):
            raise AIWorkflowError(f"Node {index + 1} must be an object", code="invalid_workflow_node")
        item = _json_clone(source)
        raw_id = item.get("id", item.get("key"))
        if repair:
            node_id = _safe_identifier(raw_id, "node", index, used)
            if _clean_text(raw_id) != node_id:
                warnings.append(f"Normalized node id '{raw_id}' to '{node_id}'.")
        else:
            node_id = raw_id
        if raw_id is not None:
            id_map.setdefault(str(raw_id), node_id)
        if isinstance(node_id, str):
            id_map.setdefault(node_id, node_id)
        node_type = _canonical_node_type(item.get("type", item.get("node_type")))
        if node_type not in known:
            raise AIWorkflowError(
                f"Workflow uses unavailable node type '{item.get('type', item.get('node_type', ''))}'",
                code="unknown_workflow_node",
                warnings=warnings,
            )
        params = item.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            if not repair:
                raise AIWorkflowError(f"Node '{raw_id}' params must be an object", code="invalid_node_params")
            warnings.append(f"Replaced non-object params on node '{node_id}' with an empty object.")
            params = {}
        label = _clean_text(item.get("label"), node_type, 160) or node_type
        node = dict(item)
        node.update({"id": node_id, "label": label, "type": node_type, "params": _json_clone(params)})
        if repair:
            for axis, default in (("x", (index % 5) * 300), ("y", (index // 5) * 180)):
                try:
                    node[axis] = float(node.get(axis, default))
                except (TypeError, ValueError):
                    node[axis] = default
                    warnings.append(f"Replaced invalid {axis} position on node '{node_id}'.")
        nodes.append(node)
    return nodes, id_map


def _normalize_edges(raw_edges: Any, id_map: dict[str, Any], *, repair: bool,
                     warnings: list[str]) -> list[dict]:
    if raw_edges is None:
        raw_edges = []
    if not isinstance(raw_edges, list):
        raise AIWorkflowError("Workflow edges must be an array", code="invalid_workflow_edges")
    edges: list[dict] = []
    used_ids: set[str] = set()
    used_pairs: set[tuple[Any, Any]] = set()
    for index, source in enumerate(raw_edges):
        if not isinstance(source, dict):
            raise AIWorkflowError(f"Edge {index + 1} must be an object", code="invalid_workflow_edge")
        item = _json_clone(source)
        raw_from = item.get("from", item.get("source"))
        raw_to = item.get("to", item.get("target"))
        if repair:
            source_id = id_map.get(str(raw_from))
            target_id = id_map.get(str(raw_to))
            if source_id is None or target_id is None:
                warnings.append(f"Dropped edge with an unknown endpoint: {raw_from!r} -> {raw_to!r}.")
                continue
            if source_id == target_id:
                warnings.append(f"Dropped self-referencing edge on '{source_id}'.")
                continue
            pair = (source_id, target_id)
            if pair in used_pairs:
                warnings.append(f"Dropped duplicate edge {source_id} -> {target_id}.")
                continue
            used_pairs.add(pair)
            edge_id = _safe_identifier(item.get("id"), "edge", index, used_ids)
        else:
            source_id, target_id, edge_id = raw_from, raw_to, item.get("id")
        edge = dict(item)
        edge.update({"id": edge_id, "from": source_id, "to": target_id})
        edge.pop("source", None)
        edge.pop("target", None)
        if edge.get("condition") is not None:
            edge["condition"] = _clean_text(edge.get("condition"))
        if edge.get("is_default"):
            edge["is_default"] = True
        else:
            edge.pop("is_default", None)
        edges.append(edge)
    return edges


def _normalize_variables(raw_variables: Any, *, repair: bool, warnings: list[str]) -> list[dict]:
    if raw_variables is None:
        raw_variables = []
    if isinstance(raw_variables, dict) and repair:
        raw_variables = [
            {"key": key, "name": key, "default": value}
            for key, value in raw_variables.items()
        ]
        warnings.append("Converted variable map to the editor's variable array format.")
    if not isinstance(raw_variables, list):
        raise AIWorkflowError("Workflow variables must be an array", code="invalid_workflow_variables")
    variables = []
    used: set[str] = set()
    allowed = {"text", "number", "bool", "json"}
    for index, source in enumerate(raw_variables):
        if not isinstance(source, dict):
            raise AIWorkflowError(f"Variable {index + 1} must be an object", code="invalid_workflow_variable")
        item = _json_clone(source)
        key = item.get("key", item.get("id"))
        if repair:
            normalized = _safe_identifier(key, "var", index, used)
            if _clean_text(key) != normalized:
                warnings.append(f"Normalized variable key '{key}' to '{normalized}'.")
            key = normalized
        vtype = _clean_text(item.get("type"), "text").lower() or "text"
        if vtype not in allowed:
            if not repair:
                vtype = item.get("type")
            else:
                warnings.append(f"Changed invalid type for variable '{key}' to text.")
                vtype = "text"
        variable = dict(item)
        variable.update({
            "key": key,
            "name": _clean_text(item.get("name"), str(key or "variable"), 120),
            "type": vtype,
        })
        if "required" in variable:
            variable["required"] = bool(variable["required"])
        variables.append(variable)
    return variables


def _new_node_id(nodes: list[dict], prefix: str) -> str:
    used = {str(node.get("id")) for node in nodes}
    index = 1
    candidate = prefix
    while candidate in used:
        index += 1
        candidate = f"{prefix}_{index}"
    return candidate


def _new_edge_id(edges: list[dict], prefix: str = "edge") -> str:
    used = {str(edge.get("id")) for edge in edges}
    index = 1
    candidate = prefix
    while candidate in used:
        index += 1
        candidate = f"{prefix}_{index}"
    return candidate


def _add_edge(edges: list[dict], source: str, target: str, **extra) -> bool:
    if source == target or any(edge.get("from") == source and edge.get("to") == target for edge in edges):
        return False
    edges.append({"id": _new_edge_id(edges), "from": source, "to": target, **extra})
    return True


def _repair_graph_structure(nodes: list[dict], edges: list[dict], warnings: list[str]):
    """Apply only deterministic, non-destructive repairs to model output."""
    reports = [node for node in nodes if node.get("type") == "report"]
    if reports:
        report_id = reports[0]["id"]
    else:
        report_id = _new_node_id(nodes, "report")
        nodes.append({
            "id": report_id, "label": "Analysis report", "type": "report",
            "params": {"title": "AI generated analysis report"},
            "x": max((float(node.get("x", 0)) for node in nodes), default=0) + 300,
            "y": 120,
        })
        warnings.append("Added a final report node because the model omitted one.")

    # Condition nodes need one default and one or more explicitly conditional paths.
    for node in list(nodes):
        if node.get("type") != "condition":
            continue
        node_id = node["id"]
        outgoing = [edge for edge in edges if edge.get("from") == node_id]
        if not outgoing:
            relay_id = _new_node_id(nodes, f"{node_id}_path")
            nodes.append({"id": relay_id, "label": "Condition path", "type": "end", "params": {},
                          "x": float(node.get("x", 0)) + 260, "y": float(node.get("y", 0)) + 100})
            _add_edge(edges, node_id, relay_id, condition="true")
            _add_edge(edges, node_id, report_id, is_default=True)
            _add_edge(edges, relay_id, report_id)
            warnings.append(f"Added missing branches for condition node '{node_id}'.")
            outgoing = [edge for edge in edges if edge.get("from") == node_id]
        elif len(outgoing) == 1:
            only = outgoing[0]
            if only.get("condition"):
                only.pop("is_default", None)
                if not _add_edge(edges, node_id, report_id, is_default=True):
                    relay_id = _new_node_id(nodes, f"{node_id}_default")
                    nodes.append({"id": relay_id, "label": "Default path", "type": "end", "params": {},
                                  "x": float(node.get("x", 0)) + 260, "y": float(node.get("y", 0)) + 100})
                    _add_edge(edges, node_id, relay_id, is_default=True)
                    _add_edge(edges, relay_id, report_id)
            else:
                only.pop("condition", None)
                only["is_default"] = True
                relay_id = _new_node_id(nodes, f"{node_id}_branch")
                nodes.append({"id": relay_id, "label": "Conditional path", "type": "end", "params": {},
                              "x": float(node.get("x", 0)) + 260, "y": float(node.get("y", 0)) + 100})
                _add_edge(edges, node_id, relay_id, condition="true")
                _add_edge(edges, relay_id, report_id)
            warnings.append(f"Added a second branch for condition node '{node_id}'.")

        outgoing = [edge for edge in edges if edge.get("from") == node_id]
        defaults = [edge for edge in outgoing if edge.get("is_default")]
        if not defaults:
            defaults = [outgoing[-1]]
            defaults[0]["is_default"] = True
            warnings.append(f"Marked one path as default for condition node '{node_id}'.")
        for edge in defaults[1:]:
            edge.pop("is_default", None)
        default = defaults[0]
        default.pop("condition", None)
        suggested = _clean_text((node.get("params") or {}).get("expression"))
        for edge in outgoing:
            if edge is default:
                continue
            condition = _clean_text(edge.get("condition"))
            if validate_expression(condition):
                condition = suggested if suggested and not validate_expression(suggested) else "true"
                edge["condition"] = condition
                warnings.append(f"Repaired condition expression on edge '{edge.get('id')}'.")

    # A report gives dangling leaf nodes a concrete, inspectable output.
    for node in list(nodes):
        node_id = node.get("id")
        if node_id == report_id:
            continue
        if not any(edge.get("from") == node_id for edge in edges):
            if _add_edge(edges, node_id, report_id):
                warnings.append(f"Connected dangling node '{node_id}' to the report.")

    ids = {node.get("id") for node in nodes}
    roots = [node_id for node_id in ids if not any(edge.get("to") == node_id for edge in edges)]
    if len(roots) > 1:
        start_id = _new_node_id(nodes, "start")
        nodes.insert(0, {"id": start_id, "label": "Workflow start", "type": "start", "params": {}, "x": -260, "y": 120})
        for root in sorted(roots):
            _add_edge(edges, start_id, root)
        warnings.append("Added a start node to join multiple workflow entry points.")


def prepare_workflow_definition(raw: Any, *, repair: bool = False,
                                default_name: str = "AI workflow") -> tuple[dict, list[str]]:
    """Normalize and validate a graph with the current runtime node registry."""
    if not isinstance(raw, dict):
        raise AIWorkflowError("Workflow definition must be a JSON object", code="invalid_workflow_definition")
    source = _unwrap_graph(_json_clone(raw))
    warnings: list[str] = []
    nodes, id_map = _normalize_nodes(source.get("nodes"), repair=repair, warnings=warnings)
    edges = _normalize_edges(source.get("edges", source.get("connections")), id_map,
                             repair=repair, warnings=warnings)
    variables = _normalize_variables(source.get("variables"), repair=repair, warnings=warnings)
    name = _clean_text(source.get("name", source.get("title")), default_name, 64) or default_name
    description = _clean_text(source.get("description"), "", 512)
    if repair:
        _repair_graph_structure(nodes, edges, warnings)
    valid, errors = graph_definition.validate_graph(nodes, edges, variables)
    if not valid:
        raise AIWorkflowError(
            "Workflow graph validation failed: " + "; ".join(errors),
            code="workflow_validation_failed", warnings=warnings,
        )
    return {
        "name": name,
        "description": description,
        "nodes": nodes,
        "edges": edges,
        "variables": variables,
    }, warnings


def _node(node_id: str, label: str, node_type: str, params: dict | None, x: int, y: int) -> dict:
    return {"id": node_id, "label": label, "type": node_type, "params": params or {}, "x": x, "y": y}


def _edge(edge_id: str, source: str, target: str, **extra) -> dict:
    return {"id": edge_id, "from": source, "to": target, **extra}


def _pe_rule_workflow() -> dict:
    return {
        "name": "AI PE analysis workflow",
        "description": "Static PE triage with packer branching, decompilation and a consolidated report.",
        "nodes": [
            _node("start", "Workflow start", "start", {}, 0, 120),
            _node("pe_identify", "PE baseline", "pe_identify", {"sample_path": "{{sample_path}}"}, 250, 120),
            _node("packer_detect", "Packer and protection detection", "packer_detect", {}, 520, 20),
            _node("strings", "Strings and PDB evidence", "strings", {"min_len": 6, "interesting_only": False}, 520, 240),
            _node("packed_gate", "Known packer detected?", "condition", {}, 790, 20),
            _node("unpack", "Unpack and verify artifact", "unpack", {}, 1050, 0),
            _node("disassemble", "Disassemble entry point", "disassemble", {"max_insns": 3000}, 1320, 120),
            _node("decompile", "Ghidra decompilation", "decompile", {"max_functions": 200}, 1590, 120),
            _node("pe_ai_assist", "PE AI evidence review", "pe_ai_assist", {"sample_path": "{{sample_path}}", "on_fail": "external_wait"}, 1860, 20),
            _node("report", "Evidence report", "report", {"title": "AI PE analysis report"}, 2130, 120),
        ],
        "edges": [
            _edge("e_start_pe", "start", "pe_identify"),
            _edge("e_pe_packer", "pe_identify", "packer_detect"),
            _edge("e_pe_strings", "pe_identify", "strings"),
            _edge("e_packer_gate", "packer_detect", "packed_gate"),
            _edge("e_gate_unpack", "packed_gate", "unpack", condition="{{packer_detect.packed}} == true"),
            _edge("e_gate_disasm", "packed_gate", "disassemble", is_default=True),
            _edge("e_unpack_disasm", "unpack", "disassemble"),
            _edge("e_disasm_decompile", "disassemble", "decompile"),
            _edge("e_decompile_ai", "decompile", "pe_ai_assist"),
            _edge("e_ai_report", "pe_ai_assist", "report"),
            _edge("e_strings_report", "strings", "report"),
        ],
        "variables": [
            {"key": "sample_path", "name": "Sample path", "type": "text", "default": "", "required": True,
             "source_type": "input"},
        ],
    }


def _ue_rule_workflow() -> dict:
    return {
        "name": "AI UE analysis workflow",
        "description": "UE dump triage with three-major/reflection evidence, AI-assisted address/algorithm resolution and an encryption branch.",
        "nodes": [
            _node("start", "Workflow start", "start", {}, 0, 120),
            _node("pe_identify", "Dump baseline", "pe_identify", {"sample_path": "{{sample_path}}"}, 250, 120),
            _node("strings", "UE strings and symbols", "strings", {"min_len": 5, "interesting_only": False}, 520, 240),
            _node("ue_analyze", "UE version, three majors and reflection", "ue_analyze", {"version": "{{ue_version}}"}, 520, 20),
            _node("encryption_gate", "Encryption indicators present?", "condition", {}, 810, 20),
            _node("decryption_trace", "Record runtime decryption requirement", "script", {
                "lang": "python",
                "script": "print('<script_out>Encryption signals recorded. Supply a matching runtime memory dump for decryption validation.</script_out>')",
            }, 1080, 0),
            _node("ue_ai_assist", "UE AI resolution: precise globals / GetName / decryption", "ue_ai_assist", {
                "sample_path": "{{sample_path}}", "on_fail": "external_wait",
            }, 1080, 240),
            _node("decompile", "Ghidra function review", "decompile", {"max_functions": 200}, 1340, 120),
            _node("report", "UE evidence report", "report", {"title": "AI UE analysis report"}, 1610, 120),
        ],
        "edges": [
            _edge("e_start_pe", "start", "pe_identify"),
            _edge("e_pe_strings", "pe_identify", "strings"),
            _edge("e_pe_ue", "pe_identify", "ue_analyze"),
            _edge("e_ue_gate", "ue_analyze", "encryption_gate"),
            _edge("e_gate_trace", "encryption_gate", "decryption_trace", condition="{{ue_analyze.needs_decryption}} == true"),
            _edge("e_gate_ai", "encryption_gate", "ue_ai_assist", is_default=True),
            _edge("e_trace_ai", "decryption_trace", "ue_ai_assist"),
            _edge("e_ai_decompile", "ue_ai_assist", "decompile"),
            _edge("e_gate_decompile", "encryption_gate", "decompile", condition="{{ue_analyze.needs_decryption}} == false"),
            _edge("e_strings_report", "strings", "report"),
            _edge("e_ue_report", "ue_analyze", "report"),
            _edge("e_ai_report", "ue_ai_assist", "report"),
            _edge("e_decompile_report", "decompile", "report"),
        ],
        "variables": [
            {"key": "sample_path", "name": "Dump executable path", "type": "text", "default": "", "required": True,
             "source_type": "input"},
            {"key": "ue_version", "name": "UE version override", "type": "text", "default": "", "required": False,
             "source_type": "input"},
        ],
    }


def _unity_rule_workflow() -> dict:
    return {
        "name": "AI Unity analysis workflow",
        "description": "Unity build classification, metadata encryption/decryption verification and IL2CPP SDK delivery.",
        "nodes": [
            _node("start", "Workflow start", "start", {}, 0, 120),
            _node("unity_analyze", "Unity metadata and build analysis", "unity_analyze", {
                "target_path": "{{target_path}}", "version": "{{unity_version}}", "include_sdk": False,
            }, 260, 120),
            _node("metadata_gate", "Metadata encrypted?", "condition", {}, 590, 120),
            _node("decrypt_trace", "Verify metadata decryption result", "script", {
                "lang": "python",
                "script": "print('<script_out>Metadata encryption state and decryption artifact are recorded for SDK generation.</script_out>')",
            }, 860, 20),
            _node("unity_ai_assist", "Unity AI evidence review", "unity_ai_assist", {
                "target_path": "{{target_path}}", "on_fail": "external_wait",
            }, 1420, 20),
            _node("sdk_dump", "IL2CPP SDK delivery", "sdk_dump", {"target_path": "{{unity_analyze.target_path}}"}, 1140, 120),
            _node("report", "Unity evidence report", "report", {"title": "AI Unity analysis report"}, 1690, 120),
        ],
        "edges": [
            _edge("e_start_unity", "start", "unity_analyze"),
            _edge("e_unity_gate", "unity_analyze", "metadata_gate"),
            _edge("e_gate_trace", "metadata_gate", "decrypt_trace", condition="{{unity_analyze.metadata_encrypted}} == true"),
            _edge("e_gate_sdk", "metadata_gate", "sdk_dump", is_default=True),
            _edge("e_trace_sdk", "decrypt_trace", "sdk_dump"),
            _edge("e_sdk_ai", "sdk_dump", "unity_ai_assist"),
            _edge("e_ai_report", "unity_ai_assist", "report"),
        ],
        "variables": [
            {"key": "target_path", "name": "Unity game directory", "type": "text", "default": "", "required": True,
             "source_type": "input"},
            {"key": "unity_version", "name": "Unity version override", "type": "text", "default": "", "required": False,
             "source_type": "input"},
        ],
    }


def _local_rule_workflow(prompt: str, sample: dict | None = None) -> tuple[dict, str]:
    text = (prompt + " " + str((sample or {}).get("file_name", ""))).lower()
    if any(marker in text for marker in ("unity", "il2cpp", "metadata", "dump.cs", "global-metadata")):
        return _unity_rule_workflow(), "local-rules:unity"
    if any(marker in text for marker in ("unreal", "ue4", "ue5", "ue ", "虚幻", "gobjects", "gworld", "gnames")):
        return _ue_rule_workflow(), "local-rules:ue"
    return _pe_rule_workflow(), "local-rules:pe"


def _node_contract() -> list[dict]:
    return [{"type": row["type"], "params": [field.get("key") for field in row.get("params_schema", [])]}
            for row in list_node_types()]


def _generation_messages(prompt: str, sample: dict | None) -> list[dict]:
    contract = json.dumps(_node_contract(), ensure_ascii=False)
    sample_text = json.dumps(_limit_value(sample or {}), ensure_ascii=False)
    system = (
        "Generate an editable REVLab graph workflow. Return exactly one JSON object and no prose or markdown. "
        "Schema: {name, description, nodes:[{id,label,type,params,x,y}], "
        "edges:[{id,from,to,condition?,is_default?}], variables:[{key,name,type,default,required}]}. "
        "Use only these live node types and their parameter keys: " + contract + ". "
        "The graph must have exactly one entry, no cycles, unique ids, every nonterminal node must have an "
        "outgoing edge, and a final report node. Every condition node must have exactly one default outgoing edge; "
        "all other outgoing edges need a valid expression such as {{packer_detect.packed}} == true. "
        "Use an explicit branch when encryption/protection/metadata state changes the next analysis step. "
        "For PE, Unreal, or Unity reverse-analysis requests, include the matching AI assist node after the "
        "evidence-producing stages and connect it to the final report unless the user explicitly requests "
        "a static-only workflow. Set its on_fail policy to external_wait so AI is never silently omitted. "
        "The user will continue editing the graph, so preserve clear labels, meaningful variables, and expandable layout."
    )
    user = f"User workflow request:\n{prompt}\n\nOptional sample context:\n{sample_text}"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _workflow_response(graph: dict, warnings: list[str], generator: str) -> dict:
    return {
        "ok": True,
        "workflow": graph,
        "nodes": graph["nodes"],
        "edges": graph["edges"],
        "variables": graph["variables"],
        "warnings": warnings,
        "generator": generator,
        "editable": True,
    }


def generate_workflow(prompt: str, *, sample: dict | None = None, cfg: dict | None = None) -> dict:
    """Generate a validated, editable workflow draft from a natural-language request."""
    request = _clean_text(prompt, limit=16000)
    if not request:
        raise AIWorkflowError("prompt is required", code="workflow_prompt_required", status_code=400)
    runtime_cfg = dict(cfg) if cfg is not None else ai.load_config()
    if _model_is_configured(runtime_cfg):
        try:
            response = ai.chat(runtime_cfg, _generation_messages(request, sample))
        except Exception as exc:
            raise AIWorkflowError(f"AI workflow generation failed: {exc}", code="ai_request_failed", status_code=502) from exc
        raw = extract_json_payload(response)
        graph, warnings = prepare_workflow_definition(raw, repair=True)
        return _workflow_response(graph, warnings, "ai")

    raw, generator = _local_rule_workflow(request, sample)
    graph, warnings = prepare_workflow_definition(raw, repair=False)
    warnings.insert(0, "No enabled OpenAI-compatible model is configured; generated a deterministic local draft.")
    return _workflow_response(graph, warnings, generator)
