from pathlib import Path
import os

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..core.config import config, resolve_sample_path
from ..core.database import get_db
from ..models.sample import Sample, AnalysisRecord
from ..orchestrator.pipeline import analyze_in_background
from ..services import report as report_svc
from ..services import workflow as wf_svc
from ..services.disassembler import disassemble_at
from ..services.environment import ensure_environment_async
from ..services.ghidra_bridge import find_ghidra_home

router = APIRouter(prefix="/api")


def _require_execution_environment() -> dict:
    """Start automatic setup when needed and stop work until requirements are ready."""
    environment = ensure_environment_async()
    if not environment.get("ready"):
        raise HTTPException(
            503,
            {
                "message": "Environment setup is in progress",
                "missing": environment.get("missing", []),
                "job": environment.get("job", {}),
            },
        )
    return environment


@router.post("/samples/upload")
async def upload_sample(file: UploadFile = File(...), db: Session = Depends(get_db)):
    data = await file.read()
    if len(data) > config.MAX_UPLOAD_SIZE:
        raise HTTPException(413, "file too large")
    import hashlib
    sha256 = hashlib.sha256(data).hexdigest()
    # 哈希去重
    existing = db.query(Sample).filter(Sample.sha256 == sha256).first()
    if existing:
        return {"id": existing.id, "duplicate": True}

    from ..services import hash as hash_svc
    name = Path(file.filename).name
    dest = config.SAMPLES_DIR / f"{sha256[:16]}_{name}"
    dest.write_bytes(data)
    try:
        pe = __import__("pefile").PE(data=data)
    except Exception:
        pe = None
    hashes = hash_svc.compute_hashes(data, pe)
    sample = Sample(
        file_name=name, stored_path=str(dest), file_size=len(data),
        md5=hashes["md5"], sha1=hashes["sha1"], sha256=hashes["sha256"],
        imphash=hashes["imphash"], ssdeep=hashes["ssdeep"],
        status="uploaded",
    )
    db.add(sample)
    db.commit()
    return {"id": sample.id, "duplicate": False, "sha256": sha256}


@router.get("/samples")
def list_samples(db: Session = Depends(get_db)):
    rows = db.query(Sample).order_by(Sample.id.desc()).limit(200).all()
    return [{
        "id": s.id, "file_name": s.file_name, "file_size": s.file_size,
        "sha256": s.sha256, "md5": s.md5, "imphash": s.imphash,
        "machine": s.machine, "arch": s.arch, "is_pe": s.is_pe,
        "packer_verdict": s.packer_verdict, "status": s.status, "stage": s.stage,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "report_path": s.report_path,
    } for s in rows]


@router.get("/samples/{sample_id}")
def get_sample(sample_id: int, db: Session = Depends(get_db)):
    s = db.query(Sample).filter(Sample.id == sample_id).first()
    if not s:
        raise HTTPException(404, "not found")
    return {
        "id": s.id, "file_name": s.file_name, "file_size": s.file_size,
        "md5": s.md5, "sha1": s.sha1, "sha256": s.sha256, "imphash": s.imphash,
        "machine": s.machine, "arch": s.arch, "is_pe": s.is_pe,
        "subsystem": s.subsystem, "entry_point": s.entry_point, "image_base": s.image_base,
        "packer_hits": s.packer_hits, "packer_verdict": s.packer_verdict,
        "status": s.status, "stage": s.stage, "error": s.error,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "report_path": s.report_path,
        "summary": s.summary or {},
    }


@router.post("/samples/{sample_id}/analyze")
def trigger_analyze(sample_id: int, workflow: str = Query("full-auto", description="工作流名"),
                    sync: bool = Query(False, description="等待完成(动态/反编译较慢)"),
                    confirm_local_execution: bool = Query(
                        False, description="确认本次允许本机动态执行"
                    )):
    from ..core.database import SessionLocal
    db = SessionLocal()
    try:
        s = db.query(Sample).filter(Sample.id == sample_id).first()
    finally:
        db.close()
    if not s:
        raise HTTPException(404, "not found")
    wf = wf_svc.get_workflow(workflow) or wf_svc.default_workflow()
    if not wf.get("enabled", True):
        raise HTTPException(400, f"workflow '{workflow}' is disabled")
    if confirm_local_execution:
        import copy
        wf = copy.deepcopy(wf)
        for stage in wf.get("stages", []):
            if stage.get("name") == "dynamic":
                stage.setdefault("params", {})["confirm_local_execution"] = True
    _require_execution_environment()
    if sync:
        from ..orchestrator.pipeline import Runner
        return Runner(sample_id, workflow=wf).run(resume=True)
    analyze_in_background(sample_id, wf)
    return {"ok": True, "status": "queued", "workflow": workflow,
            "stages": [s_["name"] for s_ in wf["stages"] if s_.get("enabled", True)]}


@router.get("/samples/{sample_id}/graph-runs")
def list_sample_graph_runs(sample_id: int, limit: int = Query(100, ge=1, le=500)):
    """List graph workflow runs associated with a sample."""
    from ..workflow_engine import manager as graph_manager
    return graph_manager.list_sample_tasks(sample_id, limit)


@router.post("/samples/{sample_id}/graph-runs")
def create_sample_graph_run(sample_id: int, payload: dict):
    """Create and optionally start a graph workflow with sample inputs injected."""
    from ..workflow_engine import manager as graph_manager

    workflow_id = int(payload.get("workflow_id") or 0)
    if not workflow_id:
        raise HTTPException(400, "workflow_id is required")
    try:
        workflow_def = graph_manager.get_workflow(workflow_id)
        if not workflow_def:
            raise HTTPException(404, "workflow not found")
        has_dynamic = any(
            (node or {}).get("type") == "dynamic_analyze"
            for node in (workflow_def.get("nodes") or [])
        )
        if payload.get("start", True) and has_dynamic and not payload.get("confirm_local_execution", False):
            raise HTTPException(400, "任务包含本机动态执行，需要本次明确确认")
        if payload.get("start", True):
            _require_execution_environment()
        created = graph_manager.create_task(
            workflow_id,
            payload.get("name", ""),
            payload.get("variables") or {},
            sample_id=sample_id,
        )
        if payload.get("start", True):
            graph_manager.run_task(
                created["id"],
                confirm_local_execution=bool(payload.get("confirm_local_execution", False)),
            )
        return {**created, "sample_id": sample_id, "status": "started" if payload.get("start", True) else "pending"}
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.get("/samples/{sample_id}/disassembly")
def get_disassembly(sample_id: int, addr: str = Query("", description="起始 VA,默认入口"),
                    max_insns: int = Query(3000, le=20000), db: Session = Depends(get_db)):
    s = db.query(Sample).filter(Sample.id == sample_id).first()
    if not s or not s.summary:
        raise HTTPException(404, "no analysis")
    data = resolve_sample_path(s.stored_path).read_bytes()
    arch = s.arch or "x64"
    image_base = int(s.image_base or "0x140000000", 16)
    start = int(addr, 16) if addr else int(s.entry_point or "0", 16)
    r = disassemble_at(data, start, image_base, arch, max_insns=max_insns,
                       sections=(s.summary.get("pe") or {}).get("sections"))
    if "error" in r:
        raise HTTPException(400, r["error"])
    return {"arch": arch, "start": hex(start), "count": r["count"], "insns": r["insns"]}


@router.get("/samples/{sample_id}/strings")
def get_strings(sample_id: int, min_len: int = Query(6), db: Session = Depends(get_db)):
    s = db.query(Sample).filter(Sample.id == sample_id).first()
    if not s:
        raise HTTPException(404, "not found")
    data = resolve_sample_path(s.stored_path).read_bytes()
    from ..services.strings import extract_strings, interesting_strings
    alls = extract_strings(data, min_len=min_len)
    return {"total": len(alls), "interesting": interesting_strings(alls), "all": alls[:1000]}


@router.get("/samples/{sample_id}/report")
def get_report(sample_id: int, fmt: str = Query("html"), db: Session = Depends(get_db)):
    s = db.query(Sample).filter(Sample.id == sample_id).first()
    if not s or not s.summary or "report" not in s.summary:
        raise HTTPException(404, "no report yet")
    paths = s.summary["report"].get("paths") or s.summary["report"].get("report_paths") or {}
    if fmt not in {"html", "json", "markdown"}:
        raise HTTPException(400, "fmt must be html, json, or markdown")
    key = fmt
    path = paths.get(key)
    resolved = resolve_sample_path(path) if path else None
    output_root = Path(config.OUTPUT_ROOT).resolve()
    try:
        if resolved is None or not resolved.resolve().is_relative_to(output_root):
            raise ValueError
    except (ValueError, OSError):
        raise HTTPException(404, f"report format '{fmt}' is not available")
    if not resolved.is_file():
        raise HTTPException(404, f"report format '{fmt}' is not available")
    media_type = {"html": "text/html", "json": "application/json", "markdown": "text/markdown"}[fmt]
    return FileResponse(resolved, media_type=media_type)


@router.get("/samples/{sample_id}/report/text")
def get_report_text(sample_id: int, db: Session = Depends(get_db)):
    s = db.query(Sample).filter(Sample.id == sample_id).first()
    if not s or not s.summary or "report" not in s.summary:
        raise HTTPException(404, "no report yet")
    paths = s.summary["report"].get("paths") or s.summary["report"].get("report_paths") or {}
    p = paths.get("markdown")
    resolved = resolve_sample_path(p) if p else None
    try:
        valid = resolved is not None and resolved.resolve().is_relative_to(Path(config.OUTPUT_ROOT).resolve())
    except (ValueError, OSError):
        valid = False
    if not valid or not resolved.is_file():
        raise HTTPException(404, "markdown report is not available")
    return FileResponse(resolved, media_type="text/plain")


@router.delete("/samples/{sample_id}")
def delete_sample(sample_id: int, db: Session = Depends(get_db)):
    s = db.query(Sample).filter(Sample.id == sample_id).first()
    if not s:
        raise HTTPException(404, "not found")
    db.delete(s)
    db.commit()
    return {"ok": True}


@router.get("/status")
def status():
    from ..services.ghidra_bridge import ghidra_available
    from ..services.environment import inspect_environment
    from ..services import sandbox
    environment = inspect_environment()
    capabilities = sandbox.sandbox_capabilities()
    selected_backend = capabilities["selected"]
    dynamic_execution = {
        "allowed": True,
        "mode": selected_backend,
        "requires_confirmation": bool(capabilities.get("requires_confirmation")),
        "reason": capabilities["message"],
        "capabilities": capabilities,
    }
    return {
        "ok": True,
        "ghidra": bool(ghidra_available()) and find_ghidra_home(),
        "upx": Path(config.UPX_PATH).exists(),
        "pe_sieve": Path(config.PESIEVE_PATH).exists(),
        "vmware": False,
        "pktmon": True,
        "sandbox_mode": selected_backend,
        "host_execution_allowed": False,
        "dynamic_execution": dynamic_execution,
        "stages": wf_svc.DEFAULT_STAGE_ORDER,
        "environment_ready": environment["ready"],
        "environment_missing": environment["missing"],
    }


@router.get("/environment")
def environment_status():
    from ..services.environment import inspect_environment
    return inspect_environment()


@router.post("/environment/prepare")
def environment_prepare(payload: dict = None):
    from ..services.environment import prepare_environment
    return prepare_environment(bool((payload or {}).get("force")))


# ================================================================ 工作流
@router.get("/workflows")
def workflows_list():
    return wf_svc.list_workflows()


@router.get("/workflows/meta")
def workflows_meta():
    return wf_svc.STAGE_META


@router.get("/workflows/{name}")
def workflows_get(name: str):
    w = wf_svc.get_workflow(name)
    if not w:
        raise HTTPException(404, "workflow not found")
    return w


@router.post("/workflows")
def workflows_create(payload: dict):
    try:
        return wf_svc.create_workflow(payload.get("name", ""), payload.get("description", ""),
                                      payload.get("stages"))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/workflows/{name}")
def workflows_update(name: str, payload: dict):
    try:
        return wf_svc.update_workflow(name, payload.get("description"),
                                      payload.get("enabled"), payload.get("stages"))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/workflows/{name}")
def workflows_delete(name: str):
    try:
        return wf_svc.delete_workflow(name)
    except ValueError as e:
        raise HTTPException(400, str(e))


# ================================================================ pipeline 状态
@router.get("/samples/{sample_id}/pipeline")
def pipeline_status(sample_id: int, db: Session = Depends(get_db)):
    s = db.query(Sample).filter(Sample.id == sample_id).first()
    if not s:
        raise HTTPException(404, "not found")
    recs = db.query(AnalysisRecord).filter(AnalysisRecord.sample_id == sample_id) \
        .order_by(AnalysisRecord.id).all()
    nodes = (s.summary or {}).get("_pipeline_status", [])
    return {
        "sample_id": sample_id,
        "status": s.status, "stage": s.stage,
        "workflow": s.workflow_name,
        "nodes": nodes,
        "history": [{
            "id": r.id, "stage": r.stage, "engine": r.engine,
            "success": r.success, "error": r.error,
            "started_at": r.started_at.isoformat() + "Z" if r.started_at else None,
            "finished_at": r.finished_at.isoformat() + "Z" if r.finished_at else None,
        } for r in recs],
    }


# ================================================================ AI 模型接入
@router.get("/ai/config")
def ai_get_config():
    from ..services.ai import load_config
    cfg = load_config()
    return {k: (v if k != "api_key" else ("***" if v else "")) for k, v in cfg.items()}


@router.post("/ai/config")
def ai_save_config(payload: dict):
    from ..services.ai import save_config
    return save_config(payload)


@router.post("/ai/test")
def ai_test(payload: dict):
    from ..services import ai
    cfg = ai.load_config()
    cfg.update({k: v for k, v in payload.items() if k in cfg})
    return ai.test_connection(cfg)


@router.post("/ai/chat")
def ai_chat(payload: dict):
    """Compatibility endpoint for the original stateless chat client.

    Supplying ``session_id`` upgrades the same call into a durable turn while
    preserving the historical ``messages`` payload for existing clients.
    """
    from ..services import ai_workflow
    try:
        session_id = payload.get("session_id")
        if session_id:
            content = payload.get("content") or payload.get("message")
            if not content:
                for item in reversed(payload.get("messages") or []):
                    if isinstance(item, dict) and item.get("role") == "user":
                        content = item.get("content")
                        break
            return ai_workflow.send_chat_message(
                str(session_id), content or "", model=payload.get("model"),
                reasoning=payload.get("reasoning"), sample_id=payload.get("sample_id"),
            )
        reply = ai_workflow.chat_with_overrides(
            payload.get("messages", []), model=payload.get("model", ""),
            reasoning=payload.get("reasoning", "balanced"),
        )
        return {"reply": reply}
    except ai_workflow.AIWorkflowError as exc:
        raise HTTPException(exc.status_code, {
            "code": exc.code, "message": str(exc), "warnings": exc.warnings,
        })


# ================================================================ AI persistent conversations
@router.get("/ai/sessions")
def ai_sessions_list(limit: int = Query(100, ge=1, le=1000)):
    from ..services import ai_workflow
    return {"sessions": ai_workflow.list_chat_sessions(limit)}


@router.post("/ai/sessions")
def ai_sessions_create(payload: dict = None):
    from ..services import ai_workflow
    data = payload or {}
    try:
        session = ai_workflow.create_chat_session(
            title=data.get("title", data.get("name", "")),
            model=data.get("model", ""),
            reasoning=data.get("reasoning", "balanced"),
            sample_id=data.get("sample_id", 0),
            system_prompt=data.get("system_prompt", ""),
        )
        return {"ok": True, "session": session}
    except ai_workflow.AIWorkflowError as exc:
        raise HTTPException(exc.status_code, {
            "code": exc.code, "message": str(exc), "warnings": exc.warnings,
        })


@router.get("/ai/sessions/{session_id}")
def ai_sessions_get(session_id: str, include_messages: bool = Query(True)):
    from ..services import ai_workflow
    try:
        return ai_workflow.get_chat_session(session_id, include_messages)
    except ai_workflow.AIWorkflowError as exc:
        raise HTTPException(exc.status_code, {"code": exc.code, "message": str(exc)})


@router.patch("/ai/sessions/{session_id}")
def ai_sessions_update(session_id: str, payload: dict = None):
    from ..services import ai_workflow
    data = payload or {}
    changes = {key: data[key] for key in ("model", "reasoning", "sample_id", "system_prompt") if key in data}
    if "title" in data or "name" in data:
        changes["title"] = data.get("title", data.get("name"))
    try:
        return {"ok": True, "session": ai_workflow.update_chat_session(session_id, **changes)}
    except ai_workflow.AIWorkflowError as exc:
        raise HTTPException(exc.status_code, {
            "code": exc.code, "message": str(exc), "warnings": exc.warnings,
        })


@router.delete("/ai/sessions/{session_id}")
def ai_sessions_delete(session_id: str):
    from ..services import ai_workflow
    try:
        ai_workflow.delete_chat_session(session_id)
        return {"ok": True}
    except ai_workflow.AIWorkflowError as exc:
        raise HTTPException(exc.status_code, {"code": exc.code, "message": str(exc)})


@router.post("/ai/sessions/{session_id}/messages")
def ai_sessions_send(session_id: str, payload: dict = None):
    from ..services import ai_workflow
    data = payload or {}
    try:
        return ai_workflow.send_chat_message(
            session_id, data.get("content", data.get("message", "")),
            model=data.get("model") if "model" in data else None,
            reasoning=data.get("reasoning") if "reasoning" in data else None,
            sample_id=data.get("sample_id") if "sample_id" in data else None,
        )
    except ai_workflow.AIWorkflowError as exc:
        raise HTTPException(exc.status_code, {
            "code": exc.code, "message": str(exc), "warnings": exc.warnings,
        })


@router.post("/ai/sessions/{session_id}/compress")
def ai_sessions_compress(session_id: str, payload: dict = None):
    from ..services import ai_workflow
    data = payload or {}
    try:
        return ai_workflow.compact_chat_session(
            session_id, force=bool(data.get("force", True)), use_ai=bool(data.get("use_ai", True)),
        )
    except ai_workflow.AIWorkflowError as exc:
        raise HTTPException(exc.status_code, {
            "code": exc.code, "message": str(exc), "warnings": exc.warnings,
        })


# ================================================================ AI workflow drafts
@router.post("/ai/workflows/generate")
def ai_workflows_generate(payload: dict, db: Session = Depends(get_db)):
    from ..services import ai_workflow
    prompt = (payload or {}).get("prompt", "")
    sample_id = (payload or {}).get("sample_id", 0)
    sample_context = None
    if sample_id:
        try:
            sid = int(sample_id)
        except (TypeError, ValueError):
            raise HTTPException(400, "sample_id must be an integer")
        sample = db.query(Sample).filter(Sample.id == sid).first()
        if not sample:
            raise HTTPException(404, "sample not found")
        sample_context = {
            "id": sample.id, "file_name": sample.file_name, "file_size": sample.file_size,
            "sha256": sample.sha256, "arch": sample.arch, "is_pe": bool(sample.is_pe),
            "packer_verdict": sample.packer_verdict, "summary": sample.summary or {},
        }
    try:
        return ai_workflow.generate_workflow(prompt, sample=sample_context)
    except ai_workflow.AIWorkflowError as exc:
        raise HTTPException(exc.status_code, {
            "code": exc.code, "message": str(exc), "warnings": exc.warnings,
        })


@router.post("/ai/workflows/save")
def ai_workflows_save(payload: dict):
    """Persist an AI draft only after the same graph validation used by wf2."""
    from ..services import ai_workflow
    from ..workflow_engine import manager as graph_manager
    data = payload or {}
    raw = data.get("workflow") if isinstance(data.get("workflow"), dict) else data
    if not isinstance(raw, dict):
        raise HTTPException(400, "workflow object required")
    try:
        graph, warnings = ai_workflow.prepare_workflow_definition(raw, repair=False)
        workflow_id = data.get("workflow_id", raw.get("id"))
        if workflow_id:
            try:
                workflow_id = int(workflow_id)
            except (TypeError, ValueError) as exc:
                raise HTTPException(400, "workflow_id must be an integer") from exc
            saved = graph_manager.update_workflow(
                workflow_id, name=graph["name"], description=graph["description"],
                nodes=graph["nodes"], edges=graph["edges"], variables=graph["variables"],
            )
            action = "updated"
        else:
            # Drafts must be saveable repeatedly. Add a readable suffix rather
            # than rejecting a second custom workflow with the same draft name.
            existing = {str(row.get("name", "")).lower() for row in graph_manager.list_workflows()}
            base = graph["name"]
            name = base
            index = 2
            while name.lower() in existing:
                suffix = f" {index}"
                name = base[:64 - len(suffix)] + suffix
                index += 1
            graph["name"] = name
            saved = graph_manager.create_workflow(
                graph["name"], graph["description"], graph["nodes"], graph["edges"], graph["variables"],
            )
            workflow_id = saved["id"]
            action = "created"
        graph["id"] = int(workflow_id)
        return {
            "ok": True, "id": int(workflow_id), "action": action, "workflow": graph,
            "nodes": graph["nodes"], "edges": graph["edges"], "variables": graph["variables"],
            "warnings": warnings, "generator": data.get("generator", "ai-draft"), "editable": True,
        }
    except ai_workflow.AIWorkflowError as exc:
        raise HTTPException(exc.status_code, {
            "code": exc.code, "message": str(exc), "warnings": exc.warnings,
        })
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post("/ai/summarize/{sample_id}")
def ai_summarize(sample_id: int, payload: dict = None, db: Session = Depends(get_db)):
    from ..services import ai
    s = db.query(Sample).filter(Sample.id == sample_id).first()
    if not s:
        raise HTTPException(404, "not found")
    sdict = {
        "file_name": s.file_name, "file_size": s.file_size,
        "sha256": s.sha256, "imphash": s.imphash,
        "summary": s.summary or {},
    }
    try:
        prompt = (payload or {}).get("prompt", "")
        return {"reply": ai.summarize_sample(sdict, prompt)}
    except Exception as e:
        raise HTTPException(502, str(e))


# ================================================================ UE 虚幻引擎分析
@router.get("/ue/versions")
def ue_versions():
    from ..services.ue.versions import all_versions, UE_VERSIONS
    return [{"version": v, **{k: x for k, x in UE_VERSIONS[v].items() if k != "sources"}}
            for v in all_versions()]


@router.get("/ue/version/{ver}")
def ue_version_detail(ver: str):
    from ..services.ue.versions import get_version, FNAME_DETAILS
    v = get_version(ver)
    if not v:
        raise HTTPException(404, "version not in knowledge base")
    return {**v, "fname_detail": FNAME_DETAILS.get(v["fname"])}


@router.get("/ue/signatures")
def ue_signatures(ver: str = Query("", description="按版本过滤")):
    from ..services.ue.signatures import all_signatures, signatures_for_version
    return signatures_for_version(ver) if ver else all_signatures()


@router.post("/ue/signatures")
def ue_save_signature(payload: dict):
    from ..services.ue.signatures import save_custom_signature
    name = payload.get("name", "").strip()
    sig = payload.get("signature", "").strip()
    if not name or not sig:
        raise HTTPException(400, "name and signature required")
    return save_custom_signature({"name": name, "signature": sig, "offset": payload.get("offset", 4),
                                  "rel": payload.get("rel", True), "versions": payload.get("versions", ["custom"]),
                                  "desc": payload.get("desc", "custom signature")})


@router.post("/ue/source/search")
def ue_source_search(payload: dict):
    from ..services.ue.source_fetcher import find_version_branch
    try:
        return {"ok": True, **find_version_branch(payload.get("version", ""))}
    except Exception as e:
        raise HTTPException(404, str(e))


@router.post("/ue/source/fetch")
def ue_source_fetch(payload: dict):
    from ..services.ue.source_fetcher import fetch_version_sources
    try:
        r = fetch_version_sources(payload.get("version", ""), cache=True)
        return {"ok": True, **r}
    except Exception as e:
        raise HTTPException(502, str(e))


@router.get("/ue/source/cache")
def ue_source_cache():
    from ..services.ue.source_fetcher import cached_sources
    return cached_sources()


@router.post("/ue/analyze/{sample_id}")
def ue_analyze(sample_id: int, version: str = Query("", description="指定 UE 版本,留空自动识别"),
               report: bool = Query(True, description="同时生成报告文件")):
    from ..services.ue.analyzer import analyze_sample, ue_report
    try:
        _require_execution_environment()
        if report:
            return ue_report(sample_id, version=version)
        return {"ok": True, "result": analyze_sample(sample_id, version=version)}
    except ValueError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(502, str(e))


# ================================================================ 全局设置
@router.get("/settings")
def settings_get():
    from ..services.settings import load_settings
    return load_settings()


@router.post("/settings")
def settings_save(payload: dict):
    from ..services.settings import save_settings
    return save_settings(payload)


# ================================================================ 引擎专项通用接口(UE/Unity)
@router.get("/engine/{engine}/spec")
def engine_spec_api(engine: str):
    from ..services.engine_runner import engine_spec
    try:
        return engine_spec(engine)
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.post("/engine/{engine}/analyze")
def engine_analyze(engine: str, payload: dict):
    from ..services.engine_runner import start_analysis
    target_path = payload.get("target_path", "").strip()
    sample_id = int(payload.get("sample_id", 0) or 0)
    version = payload.get("version", "") or ""
    params = payload.get("params") or {}
    if not target_path:
        # 支持以 sample_id 作为输入(UE dump exe)
        from ..core.config import resolve_sample_path
        db = SessionLocal()
        try:
            s = db.query(Sample).filter(Sample.id == sample_id).first()
        finally:
            db.close()
        if not s:
            raise HTTPException(400, "target_path 或有效 sample_id 必填")
        target_path = str(resolve_sample_path(s.stored_path))
        target_name = s.file_name
    else:
        from pathlib import Path as P
        p = P(target_path)
        if not p.exists():
            raise HTTPException(404, f"路径不存在: {target_path}")
        target_name = p.name
    try:
        _require_execution_environment()
        return start_analysis(engine, target_name, target_path, sample_id=sample_id,
                              version=version, params=params)
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.get("/engine/{engine}/analyses")
def engine_analyses(engine: str):
    from ..services.engine_runner import list_analyses
    try:
        return list_analyses(engine)
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.get("/engine/{engine}/analyses/{aid}")
def engine_analysis_detail(engine: str, aid: int):
    from ..services.engine_runner import get_analysis
    a = get_analysis(aid)
    if not a or a["engine"] != engine:
        raise HTTPException(404, "not found")
    return a


@router.post("/engine/{engine}/analyses/{aid}/rerun")
def engine_analysis_rerun(engine: str, aid: int):
    from ..services.engine_runner import get_analysis, start_analysis, _load_engine
    a = get_analysis(aid)
    if not a or a["engine"] != engine:
        raise HTTPException(404, "not found")
    _load_engine(engine)
    _require_execution_environment()
    return start_analysis(engine, a["target_name"], a["target_path"],
                          sample_id=a["sample_id"], version=a["version"],
                          params=(a["result"] or {}).get("_params", {}))


@router.delete("/engine/{engine}/analyses/{aid}")
def engine_analysis_delete(engine: str, aid: int):
    from ..services.engine_runner import delete_analysis
    ok = delete_analysis(aid)
    if not ok:
        raise HTTPException(404, "not found")
    return {"ok": True}
