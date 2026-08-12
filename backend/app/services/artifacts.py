"""Task-scoped artifact manifests and local artifact actions.

The manifest is the authority for the UI: an artifact action never receives an
arbitrary filesystem path.  This keeps the output center useful while making
the task run directory a durable, portable record of what was produced.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from ..core.config import config
from ..core.database import SessionLocal
from ..models.sample import EngineAnalysis, GraphTask, GraphWorkflow


MANIFEST_NAME = "manifest.json"
MANIFEST_VERSION = 2
RUN_SUBDIRECTORIES = (
    "report",
    "sdk",
    "unpacked",
    "decompile",
    "captures",
    "logs",
    "decryption",
    "workspace",
)
_PATH_KEYS = {
    "report_paths", "root_markdown", "dump_cs", "script_json", "sdk_json",
    "cpp_dir", "cpp_headers", "dll", "delivery_path", "decrypted_path", "out_dir",
    "unpacked_path", "pcap_path", "capture_path", "report_path", "report_dir",
    "log_path", "manifest", "sdk_manifest", "metadata", "recovery_manifest",
    "il2cpp_h", "stringliteral_json", "dummy_dir", "dummy_dlls",
}
_GENERIC_FILE_PATH_NODES = {"decompile", "unpack"}


def _output_root() -> Path:
    return Path(config.OUTPUT_ROOT).resolve()


def _slug(value: str, fallback: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "")).strip("_.-")
    return value[:72] or fallback


def _timestamp(value: datetime | None) -> str:
    return (value or datetime.utcnow()).strftime("%Y%m%d_%H%M%S")


def _is_under_output_root(path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(_output_root())
        return True
    except (OSError, ValueError):
        return False


def _relative(path: Path) -> str:
    return path.resolve(strict=False).relative_to(_output_root()).as_posix()


def run_directory(task: GraphTask, workflow: GraphWorkflow | None = None) -> Path:
    """Return the stable output directory assigned to a graph task."""
    workflow_name = workflow.name if workflow else task.name
    variables = task.variables or {}
    target = str(variables.get("target_path") or variables.get("sample_path") or "")
    target_path = Path(target.rstrip("\\/")) if target else None
    if target_path:
        # Directory names may legitimately contain dots (for example a build
        # named Build.09052026). Preserve the complete directory identity;
        # only strip a suffix when the submitted target is a file.
        is_directory = target_path.is_dir() or target.endswith(("\\", "/"))
        target_name = target_path.name if is_directory else target_path.stem
    else:
        target_name = ""
    target_slug = _slug(target_name, "target")
    workflow_slug = _slug(workflow_name, "workflow")
    return _output_root() / "runs" / (
        f"{int(task.id):06d}_{target_slug}_{workflow_slug}_{_timestamp(task.created_at)}"
    )


def _prepare_run_directory(path: Path) -> Path:
    """Create the standard, self-contained layout for one analysis run."""
    path.mkdir(parents=True, exist_ok=True)
    for name in RUN_SUBDIRECTORIES:
        (path / name).mkdir(parents=True, exist_ok=True)
    return path


def task_output_directory(task_id: int) -> Path:
    """Return the stable, writable output directory for a graph task.

    This is deliberately the same path used by the manifest, rather than a
    second task-specific directory.  Nodes can therefore write directly into
    ``report/``, ``sdk/``, ``unpacked/`` and the other standard subfolders and
    the user can open one folder to inspect every deliverable from that run.
    """
    db = SessionLocal()
    try:
        task = db.query(GraphTask).filter(GraphTask.id == int(task_id)).first()
        if not task:
            raise ValueError(f"Task {task_id} was not found")
        workflow = db.query(GraphWorkflow).filter(
            GraphWorkflow.id == task.workflow_id
        ).first()
        path = run_directory(task, workflow)
    finally:
        db.close()
    return _prepare_run_directory(path)


def _artifact_kind(path: Path, key: str) -> str:
    if path.is_dir():
        return "folder"
    key = key.lower()
    if "report" in key or path.suffix.lower() in {".html", ".md"}:
        return "report"
    if path.suffix.lower() == ".json":
        return "json"
    if path.suffix.lower() in {".cs", ".h", ".hpp", ".cpp"}:
        return "source"
    if path.suffix.lower() in {".dll", ".exe"}:
        return "binary"
    return "file"


def _artifact_id(relative_path: str) -> str:
    return hashlib.sha1(relative_path.encode("utf-8")).hexdigest()[:16]


def _walk_output_values(value: Any, key: str = "", depth: int = 0) -> Iterable[tuple[str, str]]:
    """Yield file-like values from node outputs without treating all strings as paths."""
    if depth > 8:
        return
    if isinstance(value, dict):
        path_container = key in _PATH_KEYS
        for child_key, child_value in value.items():
            if path_container or child_key in _PATH_KEYS or isinstance(child_value, (dict, list, tuple)):
                # report_paths is a map such as {html: path, json: path}; its
                # children remain path values even though their own keys are
                # format names rather than canonical path field names.
                next_key = key if path_container else str(child_key)
                yield from _walk_output_values(child_value, next_key, depth + 1)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_output_values(child, key, depth + 1)
    elif isinstance(value, str) and key in _PATH_KEYS:
        yield key, value


def _collect_artifacts_from_states(node_states: dict) -> list[dict]:
    artifacts: dict[str, dict] = {}
    for node_id, state in (node_states or {}).items():
        outputs = state.get("outputs") if isinstance(state, dict) else None
        if not isinstance(outputs, dict):
            continue
        candidates = list(_walk_output_values(outputs))
        # Only node contracts that explicitly expose a single generated file
        # may use the otherwise ambiguous key named "path".  Engine scan
        # records contain many ordinary filesystem paths and must never turn
        # their source tree into an artifact list.
        if node_id in _GENERIC_FILE_PATH_NODES and isinstance(outputs.get("path"), str):
            candidates.append(("generated_path", outputs["path"]))
        for key, raw_path in candidates:
            if not isinstance(raw_path, str) or not raw_path.strip():
                continue
            try:
                path = Path(raw_path).expanduser().resolve(strict=False)
            except (OSError, TypeError, ValueError):
                continue
            if not path.exists() or not _is_under_output_root(path):
                continue
            paths = [path]
            # A directory is useful as an actionable parent and its direct
            # deliverables should appear individually in the output center.
            if path.is_dir():
                paths.extend(item for item in path.rglob("*") if item.is_file())
            for item in paths:
                if not _is_under_output_root(item):
                    continue
                relative_path = _relative(item)
                aid = _artifact_id(relative_path)
                if aid in artifacts:
                    if node_id not in artifacts[aid]["source_nodes"]:
                        artifacts[aid]["source_nodes"].append(node_id)
                    continue
                artifacts[aid] = {
                    "id": aid,
                    "name": item.name,
                    "relative_path": relative_path,
                    "kind": _artifact_kind(item, key),
                    "source_nodes": [node_id],
                    "size": item.stat().st_size if item.is_file() else 0,
                    "is_directory": item.is_dir(),
                    # These two fields are intentionally private.  They let
                    # materialization retain the semantic output category
                    # without leaking an implementation path into a manifest.
                    "_source_path": str(item),
                    "_source_key": key,
                }
    return sorted(artifacts.values(), key=lambda item: (item["kind"], item["relative_path"]))


def _collect_artifacts(task: GraphTask) -> list[dict]:
    return _collect_artifacts_from_states(task.node_states or {})


def _inside(path: Path, parent: Path) -> Path | None:
    try:
        return path.resolve(strict=False).relative_to(parent.resolve(strict=False))
    except (OSError, ValueError):
        return None


def _artifact_bucket(source: Path, source_key: str) -> str:
    """Choose the stable run subdirectory for a generated legacy artifact."""
    key = str(source_key or "").lower()
    names = [part.lower() for part in source.parts]
    if key in {"dump_cs", "script_json", "sdk_json", "cpp_dir", "cpp_headers", "dll",
               "delivery_path", "sdk_manifest", "manifest", "metadata",
               "il2cpp_h", "stringliteral_json", "dummy_dir", "dummy_dlls"}:
        return "sdk"
    if key in {"decrypted_path", "recovery_manifest"} or any("decrypt" in part for part in names):
        return "decryption"
    if key in {"unpacked_path"} or "unpacked" in names:
        return "unpacked"
    if key in {"pcap_path", "capture_path"} or "captures" in names:
        return "captures"
    if key in {"generated_path"} and "decompile" in names:
        return "decompile"
    if key in {"report_paths", "report_path", "report_dir", "log_path"}:
        return "report"
    if "sdk" in key or any(part.startswith("sdk") for part in names):
        return "sdk"
    if "decompil" in key or any("decompil" in part for part in names):
        return "decompile"
    if source.suffix.lower() in {".html", ".md"}:
        return "report"
    if source.suffix.lower() == ".log":
        return "logs"
    return "workspace"


def _legacy_tail(source: Path, bucket: str) -> Path:
    """Derive a concise, collision-resistant child path for legacy outputs."""
    rel = _inside(source, _output_root())
    parts = list(rel.parts) if rel else [source.name]
    lowered = [part.lower() for part in parts]

    if bucket == "sdk":
        # Old SDK paths vary between sdk/<task>/..., reports/unity/sdk_<name>/
        # ..., and a direct sdk_cpp directory.  Preserve the useful delivery
        # structure while discarding global/task-specific parent folders.
        for marker in ("sdk_cpp", "inputs"):
            if marker in lowered:
                index = lowered.index(marker)
                return Path(*parts[index:])
        return Path(source.name)
    if bucket == "decryption":
        return Path(source.name)
    if bucket == "unpacked":
        if "unpacked" in lowered:
            index = lowered.index("unpacked")
            tail = parts[index + 1:]
            if tail:
                return Path(*tail)
        return Path(source.name)
    if bucket == "captures":
        if "captures" in lowered:
            index = lowered.index("captures")
            tail = parts[index + 1:]
            if tail:
                return Path(*tail)
        return Path(source.name)
    return Path(source.name)


def _same_file_content(first: Path, second: Path) -> bool:
    try:
        if first.samefile(second):
            return True
    except OSError:
        pass
    try:
        if first.stat().st_size != second.stat().st_size:
            return False
        first_hash = hashlib.sha256()
        second_hash = hashlib.sha256()
        with first.open("rb") as first_handle, second.open("rb") as second_handle:
            while True:
                first_chunk = first_handle.read(1024 * 1024)
                second_chunk = second_handle.read(1024 * 1024)
                if first_chunk != second_chunk:
                    return False
                if not first_chunk:
                    return first_hash.digest() == second_hash.digest()
                first_hash.update(first_chunk)
                second_hash.update(second_chunk)
    except OSError:
        return False


def _unique_destination(destination: Path, source: Path) -> Path:
    """Avoid silently replacing different legacy artifacts with the same name."""
    if not destination.exists() or _same_file_content(destination, source):
        return destination
    suffix = hashlib.sha1(str(source).encode("utf-8")).hexdigest()[:8]
    return destination.with_name(f"{destination.stem}_{suffix}{destination.suffix}")


def _link_or_copy(source: Path, destination: Path) -> str:
    """Materialize one file, preferring a same-volume hard link to a copy."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if _same_file_content(destination, source):
            return "existing"
        destination.unlink()
    try:
        os.link(source, destination)
        return "hardlink"
    except OSError:
        shutil.copy2(source, destination)
        return "copy"


def materialize_run_artifacts(run_dir: Path, artifacts: Iterable[dict]) -> list[dict]:
    """Place every registered output inside ``run_dir`` and return manifest rows.

    New runners write directly to the task/engine directory.  This function
    also upgrades historical runs whose reports, SDKs, unpacked images or
    captures were written to global folders.  It uses hard links where the
    volume permits and copies across volumes, so opening a run folder always
    shows the actual deliverables rather than only its manifest.
    """
    run_dir = _prepare_run_directory(Path(run_dir))
    materialized: dict[str, dict] = {}
    for item in artifacts or []:
        raw_source = item.get("_source_path") or item.get("absolute_path")
        if not raw_source:
            relative = item.get("relative_path")
            raw_source = str(_output_root() / relative) if relative else ""
        try:
            source = Path(str(raw_source)).expanduser().resolve(strict=False)
        except (OSError, TypeError, ValueError):
            continue
        if not source.is_file():
            continue
        # Do not register the run manifest itself as one of its deliverables.
        if source == (run_dir / MANIFEST_NAME).resolve(strict=False):
            continue
        current_relative = _inside(source, run_dir)
        if current_relative is not None:
            destination = source
            # Manifest paths are always relative to OUTPUT_ROOT, even when a
            # file already sits under this run directory.
            relative_path = _relative(source)
            method = "existing"
        else:
            bucket = _artifact_bucket(source, str(item.get("_source_key") or ""))
            destination = _unique_destination(run_dir / bucket / _legacy_tail(source, bucket), source)
            method = _link_or_copy(source, destination)
            relative_path = destination.relative_to(_output_root()).as_posix()

        artifact_id = _artifact_id(relative_path)
        if artifact_id in materialized:
            for node_id in item.get("source_nodes") or []:
                if node_id not in materialized[artifact_id]["source_nodes"]:
                    materialized[artifact_id]["source_nodes"].append(node_id)
            continue
        materialized[artifact_id] = {
            "id": artifact_id,
            "name": destination.name,
            "relative_path": relative_path,
            "kind": _artifact_kind(destination, str(item.get("_source_key") or "")),
            "source_nodes": list(item.get("source_nodes") or []),
            "size": destination.stat().st_size,
            "is_directory": False,
            "materialization": method,
        }
    return sorted(materialized.values(), key=lambda item: (item["kind"], item["relative_path"]))


def _ensure_run_root_markdown(run_dir: Path, artifacts: list[dict]) -> list[dict]:
    """Publish and register the primary workflow Markdown at the run root.

    Current report nodes already create this file.  Historical runs may only
    contain ``report/<sample>.md`` because they finished before that contract
    existed.  Refreshing their manifest upgrades them without rerunning the
    expensive analysis.
    """
    run_dir = Path(run_dir).resolve(strict=False)
    existing_root = [
        item for item in artifacts
        if Path(str(item.get("relative_path") or "")).suffix.lower() == ".md"
        and (_output_root() / str(item.get("relative_path") or "")).resolve(strict=False).parent == run_dir
    ]
    if existing_root:
        return artifacts

    candidates = []
    for item in artifacts:
        relative_path = str(item.get("relative_path") or "")
        source = (_output_root() / relative_path).resolve(strict=False)
        if source.suffix.lower() != ".md" or source.parent != run_dir / "report":
            continue
        if "report" not in (item.get("source_nodes") or []):
            continue
        candidates.append((source, item))
    if not candidates:
        return artifacts

    # A workflow has one primary report.  Prefer the largest Markdown when a
    # legacy report directory contains additional notes.
    source, source_item = max(candidates, key=lambda pair: pair[0].stat().st_size)
    destination = run_dir / source.name
    method = _link_or_copy(source, destination)
    relative_path = _relative(destination)
    root_item = {
        "id": _artifact_id(relative_path),
        "name": destination.name,
        "relative_path": relative_path,
        "kind": "report",
        "source_nodes": list(source_item.get("source_nodes") or ["report"]),
        "size": destination.stat().st_size,
        "is_directory": False,
        "materialization": method,
    }
    return sorted([*artifacts, root_item], key=lambda item: (item["kind"], item["relative_path"]))


def finalize_task_artifacts(task_id: int) -> dict | None:
    """Create or refresh the manifest after task execution has settled."""
    db = SessionLocal()
    try:
        task = db.query(GraphTask).filter(GraphTask.id == int(task_id)).first()
        if not task:
            return None
        workflow = db.query(GraphWorkflow).filter(GraphWorkflow.id == task.workflow_id).first()
        task_name = task.name
        task_status = task.status
        task_error = task.error or ""
        task_created = task.created_at
        workflow_name = workflow.name if workflow else task_name
        workflow_id = task.workflow_id
        sample_id = task.sample_id or 0
        run_dir = run_directory(task, workflow)
        artifacts = _collect_artifacts(task)
    finally:
        db.close()

    run_dir = _prepare_run_directory(run_dir)
    artifacts = materialize_run_artifacts(run_dir, artifacts)
    artifacts = _ensure_run_root_markdown(run_dir, artifacts)
    manifest = {
        "schema_version": MANIFEST_VERSION,
        "task": {
            "id": int(task_id),
            "name": task_name,
            "status": task_status,
            "error": task_error,
            "workflow_id": workflow_id,
            "workflow": workflow_name,
            "sample_id": sample_id,
            "created_at": task_created.isoformat() + "Z" if task_created else None,
        },
        "run_directory": _relative(run_dir),
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "artifacts": artifacts,
    }
    (run_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return manifest


def _manifest_path_for_task(task_id: int) -> Path | None:
    db = SessionLocal()
    try:
        task = db.query(GraphTask).filter(GraphTask.id == int(task_id)).first()
        if not task:
            return None
        workflow = db.query(GraphWorkflow).filter(GraphWorkflow.id == task.workflow_id).first()
        return run_directory(task, workflow) / MANIFEST_NAME
    finally:
        db.close()


def get_task_manifest(task_id: int, refresh: bool = True) -> dict | None:
    path = _manifest_path_for_task(task_id)
    if path is None:
        return None
    if refresh or not path.exists():
        return finalize_task_artifacts(task_id)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return finalize_task_artifacts(task_id)


def _cached_task_manifest(task_id: int) -> dict | None:
    path = _manifest_path_for_task(task_id)
    if path is None or not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def public_manifest(manifest: dict | None) -> dict | None:
    """Add display-only absolute paths to an already-authorized manifest."""
    if not manifest:
        return None
    result = json.loads(json.dumps(manifest, ensure_ascii=False))
    for artifact in result.get("artifacts") or []:
        relative_path = artifact.get("relative_path")
        if isinstance(relative_path, str) and relative_path:
            candidate = (_output_root() / relative_path).resolve(strict=False)
            if _is_under_output_root(candidate):
                artifact["absolute_path"] = str(candidate)
    run_relative = result.get("run_directory")
    if isinstance(run_relative, str) and run_relative:
        candidate = (_output_root() / run_relative).resolve(strict=False)
        if _is_under_output_root(candidate):
            result["absolute_run_directory"] = str(candidate)
    return result


def engine_run_directory(analysis: EngineAnalysis) -> Path:
    engine = _slug(analysis.engine, "engine")
    target = _slug(analysis.target_name, "target")
    return _output_root() / "runs" / f"engine_{engine}_{int(analysis.id):06d}_{target}_{_timestamp(analysis.created_at)}"


def engine_output_directory(engine: str, analysis_id: int) -> Path:
    """Return the stable, writable output directory for an engine analysis.

    ``engine`` is checked against the stored record so a caller cannot use an
    analysis id from a different engine to obtain a misleading run path.
    """
    db = SessionLocal()
    try:
        analysis = db.query(EngineAnalysis).filter(
            EngineAnalysis.id == int(analysis_id)
        ).first()
        if not analysis:
            raise ValueError(f"Engine analysis {analysis_id} was not found")
        if engine and str(analysis.engine).lower() != str(engine).lower():
            raise ValueError(f"Engine analysis {analysis_id} does not belong to {engine}")
        path = engine_run_directory(analysis)
    finally:
        db.close()
    return _prepare_run_directory(path)


def finalize_engine_artifacts(analysis_id: int) -> dict | None:
    """Create the same manifest contract for analyses run from engine pages."""
    db = SessionLocal()
    try:
        analysis = db.query(EngineAnalysis).filter(EngineAnalysis.id == int(analysis_id)).first()
        if not analysis:
            return None
        engine = analysis.engine
        target_name = analysis.target_name
        status = analysis.status
        stage = analysis.stage
        error = analysis.error or ""
        created_at = analysis.created_at
        sample_id = analysis.sample_id or 0
        result = analysis.result or {}
        artifacts = _collect_artifacts_from_states({"analysis": {"outputs": result}})
        run_dir = engine_run_directory(analysis)
    finally:
        db.close()
    run_dir = _prepare_run_directory(run_dir)
    artifacts = materialize_run_artifacts(run_dir, artifacts)
    artifacts = _ensure_run_root_markdown(run_dir, artifacts)
    manifest = {
        "schema_version": MANIFEST_VERSION,
        "run": {
            "kind": "engine",
            "id": int(analysis_id),
            "engine": engine,
            "name": target_name,
            "status": status,
            "stage": stage,
            "error": error,
            "sample_id": sample_id,
            "created_at": created_at.isoformat() + "Z" if created_at else None,
        },
        "run_directory": _relative(run_dir),
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "artifacts": artifacts,
    }
    (run_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return manifest


def _engine_manifest_path(engine: str, analysis_id: int) -> Path | None:
    db = SessionLocal()
    try:
        analysis = db.query(EngineAnalysis).filter(
            EngineAnalysis.id == int(analysis_id), EngineAnalysis.engine == engine
        ).first()
        return engine_run_directory(analysis) / MANIFEST_NAME if analysis else None
    finally:
        db.close()


def get_engine_manifest(engine: str, analysis_id: int, refresh: bool = True) -> dict | None:
    path = _engine_manifest_path(engine, analysis_id)
    if path is None:
        return None
    if refresh or not path.exists():
        return finalize_engine_artifacts(analysis_id)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return finalize_engine_artifacts(analysis_id)


def _cached_engine_manifest(engine: str, analysis_id: int) -> dict | None:
    path = _engine_manifest_path(engine, analysis_id)
    if path is None or not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_artifact_runs(limit: int = 100) -> list[dict]:
    db = SessionLocal()
    try:
        tasks = db.query(GraphTask).order_by(GraphTask.id.desc()).limit(max(1, min(int(limit), 500))).all()
        rows = [
            {
                "run_type": "graph",
                "task_id": task.id,
                "name": task.name,
                "status": task.status,
                "workflow_id": task.workflow_id,
                "sample_id": task.sample_id or 0,
                "created_at": task.created_at.isoformat() + "Z" if task.created_at else None,
            }
            for task in tasks
        ]
        analyses = db.query(EngineAnalysis).order_by(EngineAnalysis.id.desc()).limit(max(1, min(int(limit), 500))).all()
        engine_rows = [
            {
                "run_type": "engine",
                "analysis_id": analysis.id,
                "engine": analysis.engine,
                "name": analysis.target_name,
                "status": analysis.status,
                "sample_id": analysis.sample_id or 0,
                "created_at": analysis.created_at.isoformat() + "Z" if analysis.created_at else None,
            }
            for analysis in analyses
        ]
    finally:
        db.close()
    for row in rows:
        manifest = _cached_task_manifest(row["task_id"])
        row["artifact_count"] = len((manifest or {}).get("artifacts") or [])
        row["manifest_ready"] = bool(manifest)
    for row in engine_rows:
        manifest = _cached_engine_manifest(row["engine"], row["analysis_id"])
        row["artifact_count"] = len((manifest or {}).get("artifacts") or [])
        row["manifest_ready"] = bool(manifest)
    combined = rows + engine_rows
    combined.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    return combined[:max(1, min(int(limit), 500))]


def _registered_path_from_manifest(manifest: dict | None, artifact_id: str) -> tuple[dict, Path] | None:
    if not manifest:
        return None
    for artifact in manifest.get("artifacts") or []:
        if artifact.get("id") != artifact_id:
            continue
        relative_path = artifact.get("relative_path")
        if not isinstance(relative_path, str) or not relative_path:
            return None
        path = (_output_root() / relative_path).resolve(strict=False)
        if not _is_under_output_root(path) or not path.exists():
            return None
        return artifact, path
    return None


def _registered_path(task_id: int, artifact_id: str) -> tuple[dict, Path] | None:
    return _registered_path_from_manifest(get_task_manifest(task_id, refresh=False), artifact_id)


def registered_artifact(task_id: int, artifact_id: str) -> tuple[dict, Path] | None:
    return _registered_path(task_id, artifact_id)


def registered_engine_artifact(engine: str, analysis_id: int, artifact_id: str) -> tuple[dict, Path] | None:
    return _registered_path_from_manifest(get_engine_manifest(engine, analysis_id, refresh=False), artifact_id)


def _open_registered(found: tuple[dict, Path] | None, folder: bool = False) -> dict:
    if not found:
        raise ValueError("Artifact is not registered for this run")
    artifact, path = found
    if not folder and path.is_file():
        os.startfile(str(path))
        return {"ok": True, "artifact": artifact, "opened": str(path), "folder": False}
    target = path
    if folder and path.is_file():
        command = ["explorer.exe", f"/select,{path}"]
    else:
        command = ["explorer.exe", str(target)]
    subprocess.Popen(command, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return {"ok": True, "artifact": artifact, "opened": str(path), "folder": bool(folder)}


def open_artifact(task_id: int, artifact_id: str, folder: bool = False) -> dict:
    return _open_registered(_registered_path(task_id, artifact_id), folder)


def open_engine_artifact(engine: str, analysis_id: int, artifact_id: str, folder: bool = False) -> dict:
    return _open_registered(registered_engine_artifact(engine, analysis_id, artifact_id), folder)


def open_run_folder(task_id: int) -> dict:
    manifest = get_task_manifest(task_id, refresh=False)
    if not manifest:
        raise ValueError("Task output manifest was not found")
    run_dir = (_output_root() / manifest["run_directory"]).resolve(strict=False)
    if not _is_under_output_root(run_dir) or not run_dir.exists():
        raise ValueError("Task output directory is not available")
    subprocess.Popen(["explorer.exe", str(run_dir)], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return {"ok": True, "opened": str(run_dir)}


def open_engine_run_folder(engine: str, analysis_id: int) -> dict:
    manifest = get_engine_manifest(engine, analysis_id, refresh=False)
    if not manifest:
        raise ValueError("Engine output manifest was not found")
    run_dir = (_output_root() / manifest["run_directory"]).resolve(strict=False)
    if not _is_under_output_root(run_dir) or not run_dir.exists():
        raise ValueError("Engine output directory is not available")
    subprocess.Popen(["explorer.exe", str(run_dir)], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return {"ok": True, "opened": str(run_dir)}


def open_output_root() -> dict:
    """Open the configured root used by legacy PE runs and manifest-backed runs."""
    output_root = _output_root()
    output_root.mkdir(parents=True, exist_ok=True)
    subprocess.Popen(
        ["explorer.exe", str(output_root)],
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return {"ok": True, "opened": str(output_root)}
