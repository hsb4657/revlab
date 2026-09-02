"""Ghidra Headless 反编译桥接"""
import json
import hashlib
import subprocess
from pathlib import Path

from ..core.config import config

GHIDRA_SCRIPT = config.GHIDRA_DIR / "scripts" / "export_decompile.java"


def find_ghidra_home() -> str:
    def _valid_home(value: str | Path) -> bool:
        root = Path(value)
        return root.is_dir() and (root / "support" / "analyzeHeadless.bat").is_file()

    if config.GHIDRA_HOME and _valid_home(config.GHIDRA_HOME):
        return config.GHIDRA_HOME
    import glob
    candidates = [
        r"C:\Program Files\ghidra*", r"C:\ghidra*", r"D:\ghidra*",
        r"C:\Tools\ghidra*", r"C:\Program Files\Ghidra*",
        str(Path(__file__).resolve().parents[2] / "ghidra" / "ghidra*"),
    ]
    for pat in candidates:
        for p in sorted(glob.glob(pat)):
            if _valid_home(p):
                return p
    return ""


def ghidra_available() -> bool:
    return bool(find_ghidra_home())


def decompile_with_ghidra(sample_path: str, out_json: str, timeout: int = 600) -> dict:
    """调用 analyzeHeadless 反编译全部函数,输出 JSON。"""
    home = find_ghidra_home()
    if not home:
        return {"ok": False, "message": "Ghidra not found. Run scripts/install-ghidra.ps1"}
    ah = Path(home) / "support" / "analyzeHeadless.bat"
    proj_dir = config.GHIDRA_DIR / "projects"
    proj_dir.mkdir(parents=True, exist_ok=True)
    # A shared project name lets concurrent tasks overwrite each other's
    # imported program. Derive one deterministic project per output artifact.
    project_key = hashlib.sha256(str(Path(out_json).resolve()).encode("utf-8")).hexdigest()[:16]
    proj = f"revlab_{project_key}"
    log = config.GHIDRA_DIR / "ghidra_run.log"
    out_json = str(Path(out_json))
    script = str(GHIDRA_SCRIPT)
    if not Path(script).exists():
        return {"ok": False, "message": f"ghidra export script missing: {script}"}

    cmd = [str(ah), str(proj_dir), proj, "-import", sample_path,
           "-scriptPath", str(Path(script).parent),
            "-postScript", "export_decompile.java", out_json,
           "-scriptlog", str(log), "-overwrite"]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if Path(out_json).exists() and Path(out_json).stat().st_size > 0:
            return {"ok": True, "path": out_json, "message": "decompiled",
                    "rc": p.returncode}
        tail = (p.stdout or b"").decode("latin-1", "ignore")[-800:]
        return {"ok": False, "message": "ghidra produced no output", "log_tail": tail,
                "rc": p.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "message": f"ghidra timeout ({timeout}s)"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def load_decompile(json_path: str) -> dict:
    try:
        with open(json_path, encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return {}
