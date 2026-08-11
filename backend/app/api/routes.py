from pathlib import Path

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
from ..services.ghidra_bridge import find_ghidra_home

router = APIRouter(prefix="/api")


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
                    sync: bool = Query(False, description="等待完成(动态/反编译较慢)")):
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
    if sync:
        from ..orchestrator.pipeline import Runner
        return Runner(sample_id, workflow=wf).run(resume=True)
    analyze_in_background(sample_id, wf)
    return {"ok": True, "status": "queued", "workflow": workflow,
            "stages": [s_["name"] for s_ in wf["stages"] if s_.get("enabled", True)]}


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
    paths = s.summary["report"]["paths"]
    key = {"html": "html", "json": "json", "markdown": "markdown"}.get(fmt, "html")
    return FileResponse(paths[key], media_type="text/html" if fmt == "html" else "application/json")


@router.get("/samples/{sample_id}/report/text")
def get_report_text(sample_id: int, db: Session = Depends(get_db)):
    s = db.query(Sample).filter(Sample.id == sample_id).first()
    if not s or not s.summary or "report" not in s.summary:
        raise HTTPException(404, "no report yet")
    p = s.summary["report"]["paths"]["markdown"]
    return FileResponse(p, media_type="text/plain")


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
    return {
        "ok": True,
        "ghidra": bool(ghidra_available()) and find_ghidra_home(),
        "upx": Path(config.UPX_PATH).exists(),
        "pe_sieve": Path(config.PESIEVE_PATH).exists(),
        "vmware": Path(config.VMWARE_RUN).exists(),
        "pktmon": True,
        "sandbox_mode": "vmware" if config.USE_SANDBOX_VM else "local",
        "stages": wf_svc.DEFAULT_STAGE_ORDER,
    }


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
    from ..services import ai
    messages = payload.get("messages", [])
    if not messages:
        raise HTTPException(400, "messages required")
    cfg = ai.load_config()
    if not cfg.get("enabled") or not cfg.get("api_key"):
        raise HTTPException(400, "AI 未配置或未启用")
    try:
        return {"reply": ai.chat(cfg, messages)}
    except Exception as e:
        raise HTTPException(502, str(e))


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
