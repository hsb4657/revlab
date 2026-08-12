"""Local, manifest-backed artifact center APIs."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from ..services import artifacts


router = APIRouter(prefix="/api/artifacts", tags=["artifacts"])


@router.get("")
def list_runs(limit: int = Query(100, ge=1, le=500)):
    return {"runs": artifacts.list_artifact_runs(limit)}


@router.post("/open-output-root")
def open_output_root():
    return artifacts.open_output_root()


@router.get("/engine/{engine}/{analysis_id}")
def get_engine_artifacts(engine: str, analysis_id: int, refresh: bool = Query(True)):
    manifest = artifacts.get_engine_manifest(engine, analysis_id, refresh=refresh)
    if not manifest:
        raise HTTPException(404, "Engine analysis was not found")
    return artifacts.public_manifest(manifest)


@router.post("/engine/{engine}/{analysis_id}/open-run-folder")
def open_engine_run_folder(engine: str, analysis_id: int):
    try:
        return artifacts.open_engine_run_folder(engine, analysis_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.post("/engine/{engine}/{analysis_id}/open")
def open_engine_file(engine: str, analysis_id: int, payload: dict):
    try:
        return artifacts.open_engine_artifact(engine, analysis_id, str((payload or {}).get("artifact_id") or ""), folder=False)
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.post("/engine/{engine}/{analysis_id}/open-folder")
def open_engine_file_folder(engine: str, analysis_id: int, payload: dict):
    try:
        return artifacts.open_engine_artifact(engine, analysis_id, str((payload or {}).get("artifact_id") or ""), folder=True)
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.get("/engine/{engine}/{analysis_id}/download/{artifact_id}")
def download_engine_file(engine: str, analysis_id: int, artifact_id: str):
    found = artifacts.registered_engine_artifact(engine, analysis_id, artifact_id)
    if not found:
        raise HTTPException(404, "Artifact is not registered for this run")
    artifact, path = found
    if path.is_dir():
        raise HTTPException(400, "A folder cannot be downloaded as a single file")
    return FileResponse(path, filename=artifact.get("name") or path.name)


@router.get("/{task_id}")
def get_artifacts(task_id: int, refresh: bool = Query(True)):
    manifest = artifacts.get_task_manifest(task_id, refresh=refresh)
    if not manifest:
        raise HTTPException(404, "Task was not found")
    return artifacts.public_manifest(manifest)


@router.post("/{task_id}/open-run-folder")
def open_run_folder(task_id: int):
    try:
        return artifacts.open_run_folder(task_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.post("/{task_id}/open")
def open_file(task_id: int, payload: dict):
    try:
        return artifacts.open_artifact(task_id, str((payload or {}).get("artifact_id") or ""), folder=False)
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.post("/{task_id}/open-folder")
def open_file_folder(task_id: int, payload: dict):
    try:
        return artifacts.open_artifact(task_id, str((payload or {}).get("artifact_id") or ""), folder=True)
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.get("/{task_id}/download/{artifact_id}")
def download_file(task_id: int, artifact_id: str):
    found = artifacts.registered_artifact(task_id, artifact_id)
    if not found:
        raise HTTPException(404, "Artifact is not registered for this task")
    artifact, path = found
    if path.is_dir():
        raise HTTPException(400, "A folder cannot be downloaded as a single file")
    return FileResponse(path, filename=artifact.get("name") or path.name)
