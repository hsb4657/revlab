"""本机受控动态执行与行为监控。"""
import datetime
import ctypes
import os
import shlex
import subprocess
import threading
import time
from pathlib import Path

import psutil

from ..core.config import config


class SandboxError(Exception):
    pass


def _split_process_args(args: str) -> list[str]:
    """Parse a Windows command-line fragment without invoking a shell."""
    if not args:
        return []
    if os.name != "nt":
        return shlex.split(args)
    argc = ctypes.c_int()
    shell32 = ctypes.windll.shell32
    kernel32 = ctypes.windll.kernel32
    shell32.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    # The Windows API treats argv[0] specially; prepend a harmless executable
    # token so a fragment such as ``--name="a b"`` is parsed correctly.
    argv = shell32.CommandLineToArgvW("revlab-sample.exe " + args, ctypes.byref(argc))
    if not argv:
        raise ValueError("invalid command-line arguments")
    try:
        return [argv[index] for index in range(1, argc.value)]
    finally:
        kernel32.LocalFree(ctypes.cast(argv, ctypes.c_void_p))


def _run(cmd: list, timeout: int = 120) -> tuple:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, (p.stdout or b"").decode("latin-1", "replace"), (p.stderr or b"").decode("latin-1", "replace")
    except FileNotFoundError:
        return -1, "", f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"


# ---------------------------------------------------------------- monitor
class BehaviorMonitor:
    """运行期间持续采样:进程树 / 文件系统 / 注册表 变更。"""

    def __init__(self, watch_dirs: list = None, watch_reg: list = None, interval: float = 1.0):
        self.watch_dirs = watch_dirs or []
        self.interval = interval
        self.watch_reg = watch_reg or [
            (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
            (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
        ]
        self.running = False
        self._thread = None
        self.processes = []
        self.files = []
        self.registry = []
        self.dns = []
        self._reg_base = {}
        self._file_base = {}
        self._proc_base = set()

    def _snapshot_files(self) -> dict:
        snap = {}
        for d in self.watch_dirs:
            if not os.path.isdir(d):
                continue
            for root, _, files in os.walk(d):
                for f in files:
                    try:
                        p = Path(root) / f
                        st = p.stat()
                        snap[str(p)] = (st.st_size, int(st.st_mtime))
                    except Exception:
                        continue
        return snap

    def _reg_snapshot(self) -> dict:
        snap = {}
        for key, _ in self.watch_reg:
            rc, so, _ = _run(["reg", "query", key, "/s"], timeout=30)
            if rc == 0:
                snap[key] = so
        return snap

    def _proc_snapshot(self) -> list:
        out = []
        for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "create_time"]):
            try:
                info = proc.info
                out.append({"pid": info["pid"], "ppid": info["ppid"], "name": info["name"],
                            "exe": info["exe"] or "", "cmdline": " ".join(proc.cmdline())[:200],
                            "started": datetime.datetime.fromtimestamp(info["create_time"]).isoformat()})
            except Exception:
                continue
        return out

    def start(self, baseline: bool = True):
        self.running = True
        if baseline:
            self._proc_base = {p["pid"] for p in self._proc_snapshot()}
            self._file_base = self._snapshot_files()
            self._reg_base = self._reg_snapshot()
            self.processes = self._proc_snapshot()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while self.running:
            try:
                procs = self._proc_snapshot()
                for n in procs:
                    if n["pid"] not in self._proc_base and all(n["pid"] != x["pid"] for x in self.processes):
                        self.processes.append(n)
                fs = self._snapshot_files()
                for p, meta in fs.items():
                    if p not in self._file_base or self._file_base[p] != meta:
                        self.files.append({"path": p, "size": meta[0], "changed": datetime.datetime.now().isoformat()})
                reg = self._reg_snapshot()
                for key, base in self._reg_base.items():
                    if reg.get(key) != base:
                        self.registry.append({"key": key, "changed": datetime.datetime.now().isoformat(),
                                              "details": "registry subtree changed"})
                        self._reg_base[key] = reg.get(key, "")
            except Exception:
                pass
            time.sleep(self.interval)

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)

    def summary(self) -> dict:
        seen = set()
        files = []
        for f in self.files:
            if f["path"] not in seen:
                seen.add(f["path"])
                files.append(f)
        return {
            "processes": self.processes,
            "new_processes": [p for p in self.processes if p["pid"] not in self._proc_base],
            "files": files[:500],
            "registry": self.registry[:200],
            "dns": self.dns,
        }


# ---------------------------------------------------------------- sandbox
class LocalSandbox:
    """本机受控运行:低优先级 + 严格超时 + 进程树终止。"""

    def __init__(self, timeout: int = 60, workdir: str = "", monitor=None):
        self.timeout = timeout
        self.workdir = workdir or str(Path(config.WORKSPACE_DIR))
        self.monitor = monitor or BehaviorMonitor()
        self.result = {}

    def run(self, sample_path: str, args: str = "", on_started=None) -> dict:
        Path(self.workdir).mkdir(parents=True, exist_ok=True)
        self.monitor.start()
        started = time.time()
        try:
            arg_tokens = _split_process_args(str(args))
        except ValueError as exc:
            self.monitor.stop()
            return {"ok": False, "error": f"invalid sandbox arguments: {exc}"}
        try:
            proc = subprocess.Popen(
                [str(sample_path), *arg_tokens], cwd=self.workdir, shell=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=0x00000008 | 0x00000200,  # DETACHED | CREATE_NEW_CONSOLE
            )
            pid = proc.pid
            startup_observer = {}
            if on_started is not None:
                try:
                    startup_observer = on_started(pid) or {}
                except Exception as exc:
                    startup_observer = {"ok": False, "error": str(exc)}
            try:
                proc.wait(timeout=self.timeout)
                rc = proc.returncode
                ran_seconds = round(time.time() - started, 1)
            except subprocess.TimeoutExpired:
                _kill_tree(pid)
                rc = "timeout"
                ran_seconds = self.timeout
        except Exception as e:
            self.monitor.stop()
            return {"ok": False, "error": str(e)}
        time.sleep(1)
        self.monitor.stop()
        self.result = {
            "ok": True,
            "executed": True,
            "execution_status": "timeout" if rc == "timeout" else "completed",
            "runner": "local",
            "pid": pid,
            "returncode": rc,
            "ran_seconds": ran_seconds,
            "network_policy": "host_network",
            "behavior": self.monitor.summary(),
            "startup_observer": startup_observer,
        }
        return self.result


def _kill_tree(pid: int):
    try:
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            try:
                child.kill()
            except Exception:
                pass
        parent.kill()
    except Exception:
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
        except Exception:
            pass


def sandbox_capabilities() -> dict:
    """Describe the only supported dynamic backend without running a sample."""
    requested = str(config.DYNAMIC_BACKEND or "local").strip().lower()
    if requested in {"auto", "host", "local", "native"}:
        requested = "local"
    else:
        requested = "local"
    return {
        "requested": requested,
        "selected": "local",
        "host_execution_allowed": False,
        "requires_confirmation": True,
        "backends": {
            "local": {"available": True, "network": "host_network",
                      "gui": False, "requires_confirmation": True,
                      "description": "本机受控执行，超时终止进程树"},
            "sandboxie": {"available": False, "disabled": True,
                          "reason": "已禁用第三方沙箱后端"},
            "windows_sandbox": {"available": False, "disabled": True,
                                 "reason": "已禁用虚拟化沙箱后端"},
            "vmware": {"available": False, "disabled": True,
                       "reason": "已禁用虚拟机后端"},
        },
        "message": "本机受控执行；每次开始前都需要用户确认",
    }


def create_sandbox(mode: str = "", timeout: int | None = None,
                   confirm_host_execution: bool = False,
                   confirm_local_execution: bool | None = None) -> object:
    """Create the local runner after an explicit per-run confirmation.

    ``confirm_host_execution`` is accepted as a compatibility alias for older
    saved workflows. It never means that a VM or third-party sandbox is used.
    """
    requested = str(mode or config.DYNAMIC_BACKEND or "auto").strip().lower()
    if requested in {"auto", "host", "local", "native"}:
        requested = "local"
    confirmed = bool(confirm_host_execution)
    if confirm_local_execution is not None:
        confirmed = bool(confirm_local_execution)
    run_timeout = int(timeout or config.SANDBOX_TIMEOUT)
    if requested != "local":
        raise SandboxError("仅支持本机动态执行；沙箱、虚拟机后端已禁用")
    if not confirmed:
        raise SandboxError("本机执行需要本次明确确认；未启动样本")
    return LocalSandbox(timeout=run_timeout)
