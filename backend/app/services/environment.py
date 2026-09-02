"""Runtime environment preflight and repository bootstrap orchestration."""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from ..core.config import config


_lock = threading.Lock()
_state = {
    "status": "idle",
    "started_at": None,
    "finished_at": None,
    "return_code": None,
    "logs": deque(maxlen=240),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _which(*names: str) -> str:
    for name in names:
        resolved = shutil.which(name)
        if resolved:
            return resolved
    return ""


def _java_major(java_path: str) -> int:
    if not java_path:
        return 0
    try:
        result = subprocess.run(
            [java_path, "-version"], capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        text = (result.stdout or "") + (result.stderr or "")
        import re
        match = re.search(r'version\s+"(\d+)', text)
        return int(match.group(1)) if match else 0
    except Exception:
        return 0


def inspect_environment() -> dict:
    """Return installation state without spawning external installers."""
    from .ghidra_bridge import find_ghidra_home

    root = config.BASE_DIR
    python_venv = root / ".venv" / "Scripts" / "python.exe"
    node = _which("node.exe", "node")
    npm = _which("npm.cmd", "npm.exe", "npm")
    java = _which("java.exe", "java")
    java_major = _java_major(java)
    ghidra_home = find_ghidra_home()
    checks = [
        {
            "key": "python_venv", "name": "Python virtual environment",
            "ready": python_venv.exists(), "required": True, "path": str(python_venv),
            "remedy": "Python 3.11 and repository dependencies",
        },
        {
            "key": "node", "name": "Node.js and npm",
            "ready": bool(node and npm), "required": False,
            "path": node or npm, "remedy": "Node.js LTS and workflow editor build",
        },
        {
            "key": "workflow_frontend", "name": "Workflow editor build",
            "ready": (root / "frontend" / "wf-dist" / "index.html").exists(), "required": False,
            "path": str(root / "frontend" / "wf-dist"), "remedy": "npm ci and npm run build",
        },
        {
            "key": "java", "name": "Java 21",
            "ready": java_major >= 21, "required": False,
            "path": java, "version": java_major, "remedy": "Microsoft OpenJDK 21",
        },
        {
            "key": "ghidra", "name": "Ghidra headless",
            "ready": bool(ghidra_home), "required": False,
            "path": ghidra_home, "remedy": "official Ghidra runtime with SHA-256 verification",
        },
        {
            "key": "upx", "name": "UPX",
            "ready": Path(config.UPX_PATH).exists(), "required": False,
            "path": str(config.UPX_PATH), "remedy": "official UPX release",
        },
        {
            "key": "pe_sieve", "name": "PE-sieve",
            "ready": Path(config.PESIEVE_PATH).exists(), "required": False,
            "path": str(config.PESIEVE_PATH), "remedy": "official PE-sieve release with SHA-256 verification",
        },
        {
            "key": "il2cpp_dumper", "name": "Il2CppDumper",
            "ready": Path(config.IL2CPP_DUMPER_PATH).exists(), "required": False,
            "path": str(config.IL2CPP_DUMPER_PATH),
            "remedy": "official Perfare/Il2CppDumper source build with DummyDll enabled",
        },
        {
            "key": "vmware", "name": "VMware runtime",
            "ready": Path(config.VMWARE_RUN).exists(), "required": False,
            "path": str(config.VMWARE_RUN), "remedy": "optional: local sandbox remains available",
        },
    ]
    missing = [item["key"] for item in checks if item["required"] and not item["ready"]]
    with _lock:
        job = {
            "status": _state["status"],
            "started_at": _state["started_at"],
            "finished_at": _state["finished_at"],
            "return_code": _state["return_code"],
            "logs": list(_state["logs"]),
        }
    return {
        "ready": not missing,
        "missing": missing,
        "checks": checks,
        "job": job,
        "auto_setup": os.environ.get("REVLAB_AUTO_SETUP", "0") == "1",
    }


def _append_log(message: str) -> None:
    message = message.strip()
    if not message:
        return
    with _lock:
        _state["logs"].append({"at": _now(), "message": message[-1000:]})


def _run_setup() -> None:
    script = config.BASE_DIR / "scripts" / "setup.ps1"
    powershell = _which("powershell.exe", "pwsh.exe", "powershell") or "powershell.exe"
    command = [
        powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
        "-All", "-PersistEnv",
    ]
    _append_log("Starting automatic repository setup")
    try:
        process = subprocess.Popen(
            command, cwd=str(config.BASE_DIR), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        assert process.stdout is not None
        for line in process.stdout:
            _append_log(line)
        return_code = process.wait()
        with _lock:
            _state["return_code"] = return_code
            _state["status"] = "completed" if return_code == 0 else "failed"
            _state["finished_at"] = _now()
        _append_log("Automatic setup completed" if return_code == 0 else "Automatic setup failed")
    except Exception as error:
        with _lock:
            _state["return_code"] = -1
            _state["status"] = "failed"
            _state["finished_at"] = _now()
        _append_log(f"Automatic setup failed: {error}")


def prepare_environment(force: bool = False) -> dict:
    """Start one background setup job, or report that configuration is ready."""
    current = inspect_environment()
    with _lock:
        if _state["status"] == "running":
            return {"ok": True, "started": False, "reason": "already_running", **current}
        if current["ready"] and not force:
            return {"ok": True, "started": False, "reason": "already_ready", **current}
        _state["status"] = "running"
        _state["started_at"] = _now()
        _state["finished_at"] = None
        _state["return_code"] = None
        _state["logs"].clear()
    threading.Thread(target=_run_setup, daemon=True, name="revlab-environment-setup").start()
    return {"ok": True, "started": True, "reason": "setup_started", **inspect_environment()}


def ensure_environment_async() -> dict:
    """Trigger automatic bootstrap only when a required check is missing."""
    status = inspect_environment()
    if status["auto_setup"] and not status["ready"]:
        return prepare_environment()
    return status
