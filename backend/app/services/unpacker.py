"""脱壳引擎:已知壳自动解压(UPX 等) + 通用内存转储(PE-sieve) + IAT 修复"""
import subprocess
from pathlib import Path

from ..core.config import config


def _run_tool(cmd: list, timeout: int = 120) -> tuple:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, (p.stdout or b"").decode("latin-1", "replace"), (p.stderr or b"").decode("latin-1", "replace")
    except FileNotFoundError:
        return -1, "", f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"


def unpack_known(sample_path: str, packer_verdict: str, out_dir: str) -> dict:
    """对已知壳执行解压,返回产物路径。"""
    verdict = packer_verdict.lower()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {"ok": False, "path": "", "message": "", "tool": ""}

    if "upx" in verdict:
        upx = config.UPX_PATH
        if not Path(upx).exists():
            return {**result, "message": "UPX not found. Run scripts/download_tools.ps1"}
        out = out_dir / f"{Path(sample_path).stem}_upx.exe"
        rc, so, se = _run_tool([upx, "-d", "-o", str(out), sample_path])
        if rc == 0 and out.exists():
            result.update(ok=True, path=str(out), tool="upx", message="UPX unpacked")
        else:
            result["message"] = f"UPX unpack failed (rc={rc}): {se or so}"[:300]
        return result

    # Other packers require the explicit, approved dynamic dump path. Do not
    # claim a fallback has happened when no process was inspected.
    result["message"] = f"no automated unpacker for '{packer_verdict}'; approved memory dump required"
    return result


def dump_with_pesieve(pid: int, out_dir: str, label: str = "dump") -> dict:
    """用 PE-sieve 从运行进程转储 PE 并修复 IAT。"""
    tool = config.PESIEVE_PATH
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if not Path(tool).exists():
        return {"ok": False, "message": "pe-sieve not found. Run scripts/download_tools.ps1"}
    rc, so, se = _run_tool([
        tool, "/pid", str(pid), "/out", str(out_dir),
        "/ofn", label, "/no_hooks", "/quiet",
    ], timeout=180)
    dumped = list(out_dir.glob(f"{label}*"))
    return {
        "ok": rc == 0 and len(dumped) > 0,
        "path": str(dumped[0]) if dumped else "",
        "message": (so or se)[-1000:],
        "tool": "pe-sieve",
        "files": [str(p) for p in dumped],
    }


def rebuild_pe(path: str, out_path: str) -> dict:
    """用 lief 重建 PE(用于修复损坏头/重写节区)。"""
    try:
        import lief
        binary = lief.PE.parse(path)
        if binary is None:
            return {"ok": False, "message": "lief failed to parse"}
        binary.write(out_path)
        return {"ok": True, "path": out_path, "message": "rebuilt with lief"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def memory_dump_fallback(pid: int, out_dir: str) -> dict:
    """备用转储:minidump + 读取进程内存(极简实现)。"""
    result = {"ok": False, "message": ""}
    try:
        result["message"] = "fallback memory dump is limited; use pe-sieve for full IAT-repaired dump"
    except Exception as e:
        result["message"] = str(e)
    return result
