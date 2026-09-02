"""沙箱抽象层:VMware 快照回滚 / 本地受控运行 + 动态行为监控"""
import datetime
import ctypes
import json
import os
import shlex
import shutil
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
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
            "pid": pid,
            "returncode": rc,
            "ran_seconds": ran_seconds,
            "behavior": self.monitor.summary(),
            "startup_observer": startup_observer,
        }
        return self.result


def _sandboxie_start_path() -> Path | None:
    """Find Sandboxie-Plus without changing machine state."""
    configured = str(getattr(config, "SANDBOXIE_START", "") or "").strip()
    candidates = [Path(configured)] if configured else []
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    for root in (program_files, program_files_x86):
        candidates.extend((
            Path(root) / "Sandboxie-Plus" / "Start.exe",
            Path(root) / "Sandboxie" / "Start.exe",
        ))
    found = shutil.which("Start.exe")
    if found:
        candidates.append(Path(found))
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.resolve()
        except OSError:
            continue
    return None


class SandboxieRunner:
    """Small Sandboxie-Plus adapter for a bounded one-shot run.

    Sandboxie owns the isolation boundary. REVLab only starts the sample with
    ``/wait`` and terminates the named box on timeout; it never starts a VM or
    changes Sandboxie settings globally.
    """

    backend = "sandboxie"

    def __init__(self, timeout: int = 60):
        self.timeout = max(1, min(int(timeout or 60), 600))
        self.start_exe = _sandboxie_start_path()
        if not self.start_exe:
            raise SandboxError(
                "Sandboxie-Plus is not installed; install it or choose another backend"
            )
        self.box_name = str(getattr(config, "SANDBOXIE_BOX", "REVLab") or "REVLab")

    def _terminate_box(self) -> None:
        try:
            subprocess.run(
                [str(self.start_exe), f"/box:{self.box_name}", "/terminate"],
                capture_output=True, timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    def run_and_capture(self, host_sample: str, host_result_dir: str,
                        run_args: str = "", timeout: int | None = None) -> dict:
        if timeout is not None:
            self.timeout = max(1, min(int(timeout or self.timeout), 600))
        sample = Path(host_sample)
        if not sample.is_file():
            return {"ok": False, "executed": False, "execution_status": "failed",
                    "runner": self.backend, "error": f"sample not found: {host_sample}"}
        result_dir = Path(host_result_dir)
        result_dir.mkdir(parents=True, exist_ok=True)
        try:
            args = _split_process_args(str(run_args or ""))
        except ValueError as exc:
            return {"ok": False, "executed": False, "execution_status": "failed",
                    "runner": self.backend, "error": f"invalid sandbox arguments: {exc}"}
        monitor = BehaviorMonitor(watch_dirs=[str(result_dir)])
        command = [str(self.start_exe), f"/box:{self.box_name}", "/wait", str(sample), *args]
        started = time.time()
        monitor.start()
        process = None
        try:
            process = subprocess.Popen(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            try:
                process.wait(timeout=self.timeout)
                execution_status = "completed"
                returncode = process.returncode
            except subprocess.TimeoutExpired:
                self._terminate_box()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                execution_status = "timeout"
                returncode = "timeout"
            time.sleep(0.5)
            return {
                "ok": True,
                "executed": True,
                "execution_status": execution_status,
                "runner": self.backend,
                "box": self.box_name,
                "returncode": returncode,
                "ran_seconds": round(time.time() - started, 1),
                "behavior": monitor.summary(),
            }
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ok": False, "executed": False, "execution_status": "failed",
                    "runner": self.backend, "error": str(exc)}
        finally:
            monitor.stop()


class WindowsSandbox:
    """Ephemeral Windows Sandbox runner with networking disabled.

    The sandbox is deliberately self-contained: the input is copied into a
    read-only mapped folder, only a small output folder is writable, and the
    guest shuts itself down after the bounded run.  The class is optional and
    reports a capability error when the Windows Sandbox feature is absent.
    """

    backend = "windows_sandbox"

    def __init__(self, timeout: int = 60):
        self.timeout = max(1, min(int(timeout or 60), 600))
        self.executable = Path(config.WINDOWS_SANDBOX_EXE)
        if not self.executable.exists():
            raise SandboxError(
                "Windows Sandbox is not installed; enable the Containers-DisposableClientVM feature"
            )

    @staticmethod
    def _ps_quote(value: str) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    def _write_guest_script(self, path: Path, guest_sample: str, args: str) -> None:
        # The script emits JSON into the mapped output folder and then powers
        # off the disposable guest, which lets the host wait without a GUI.
        sample = self._ps_quote(guest_sample)
        arg_string = self._ps_quote(args or "")
        timeout_ms = self.timeout * 1000
        script = f"""$ErrorActionPreference = 'Continue'
$out = 'C:\\RevLab\\Output'
$sample = {sample}
$argString = {arg_string}
$before = @(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine)
$started = Get-Date
$proc = Start-Process -FilePath $sample -ArgumentList $argString -PassThru -WorkingDirectory 'C:\\RevLab\\Output'
$timedOut = -not $proc.WaitForExit({timeout_ms})
if ($timedOut) {{
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  $exitCode = 'timeout'
}} else {{ $exitCode = $proc.ExitCode }}
Start-Sleep -Milliseconds 500
$after = @(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine)
$result = [ordered]@{{
  ok = $true
  executed = $true
  execution_status = if ($timedOut) {{ 'timeout' }} else {{ 'completed' }}
  returncode = $exitCode
  ran_seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
  processes_before = $before
  processes_after = $after
}}
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'dynamic.json') -Encoding UTF8
shutdown.exe /s /t 0 /f
"""
        path.write_text(script, encoding="utf-8")

    def run_and_capture(self, host_sample: str, host_result_dir: str,
                        run_args: str = "", timeout: int | None = None) -> dict:
        if timeout is not None:
            self.timeout = max(1, min(int(timeout or self.timeout), 600))
        sample = Path(host_sample)
        if not sample.is_file():
            return {"ok": False, "executed": False, "execution_status": "failed",
                    "runner": self.backend, "error": f"sample not found: {host_sample}"}
        root = Path(host_result_dir) / f"windows_sandbox_{uuid.uuid4().hex[:12]}"
        input_dir = root / "input"
        output_dir = root / "output"
        input_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        guest_sample = r"C:\RevLab\Input\sample.exe"
        try:
            shutil.copy2(sample, input_dir / "sample.exe")
            self._write_guest_script(output_dir / "run.ps1", guest_sample, run_args)
            config_xml = ET.Element("Configuration")
            ET.SubElement(config_xml, "Networking").text = "Disable"
            folders = ET.SubElement(config_xml, "MappedFolders")
            for host, guest, read_only in (
                (input_dir, r"C:\RevLab\Input", "true"),
                (output_dir, r"C:\RevLab\Output", "false"),
            ):
                folder = ET.SubElement(folders, "MappedFolder")
                ET.SubElement(folder, "HostFolder").text = str(host.resolve())
                ET.SubElement(folder, "SandboxFolder").text = guest
                ET.SubElement(folder, "ReadOnly").text = read_only
            command = ET.SubElement(config_xml, "LogonCommand")
            ET.SubElement(command, "Command").text = (
                r"powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass "
                r"-File C:\RevLab\Output\run.ps1"
            )
            wsb = root / "run.wsb"
            ET.ElementTree(config_xml).write(wsb, encoding="utf-8", xml_declaration=True)
            process = subprocess.Popen(
                [str(self.executable), str(wsb)], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            deadline = time.time() + self.timeout + 45
            while time.time() < deadline and not (output_dir / "dynamic.json").exists():
                if process.poll() is not None and not (output_dir / "dynamic.json").exists():
                    break
                time.sleep(0.25)
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
            result_path = output_dir / "dynamic.json"
            if not result_path.exists():
                return {"ok": False, "executed": False,
                        "execution_status": "failed", "runner": self.backend,
                        "error": "Windows Sandbox exited without a result",
                        "artifact_dir": str(root)}
            result = json.loads(result_path.read_text(encoding="utf-8-sig"))
            result.update({"runner": self.backend, "artifact_dir": str(root)})
            return result
        except Exception as exc:
            return {"ok": False, "executed": False, "execution_status": "failed",
                    "runner": self.backend, "error": str(exc),
                    "artifact_dir": str(root)}


class VMSandbox:
    """VMware 沙箱:快照回滚 → 拷贝样本 → 运行 → 回拷结果。"""

    def __init__(self, vmx: str, snapshot: str, guest_path: str,
                 vm_user: str = "", vm_pass: str = ""):
        self.vmx = vmx
        self.snapshot = snapshot
        self.guest_path = guest_path
        self.cred = (["-gu", vm_user, "-gp", vm_pass] if vm_user else [])
        if not Path(config.VMWARE_RUN).exists():
            raise SandboxError(f"vmrun not found: {config.VMWARE_RUN}")

    def revert(self) -> bool:
        rc, so, se = _run([config.VMWARE_RUN, "revertToSnapshot", self.vmx, self.snapshot], timeout=300)
        return rc == 0

    def ensure_power(self) -> bool:
        rc, so, se = _run([config.VMWARE_RUN, "start", self.vmx], timeout=300)
        return rc == 0 or "already" in (so + se).lower()

    def wait_guest(self, retries: int = 60) -> bool:
        for _ in range(retries):
            rc, _, _ = _run([config.VMWARE_RUN, "checkToolsState", self.vmx], timeout=60)
            if rc == 0:
                return True
            time.sleep(5)
        return False

    def copy_in(self, host: str) -> bool:
        rc, _, _ = _run([config.VMWARE_RUN, *self.cred, "copyFileFromHostToGuest",
                         self.vmx, host, self.guest_path], timeout=300)
        return rc == 0

    def run_guest(self, args: str = "", timeout: int = 120) -> dict:
        cmd = [config.VMWARE_RUN, *self.cred, "runProgramInGuest", self.vmx,
               "-activeWindow", f"{self.guest_path} {args}".strip()]
        rc, so, se = _run(cmd, timeout=timeout)
        return {"ok": rc == 0, "rc": rc, "out": so, "err": se}

    def copy_out(self, guest: str, host: str) -> bool:
        rc, _, _ = _run([config.VMWARE_RUN, *self.cred, "copyFileFromGuestToHost",
                         self.vmx, guest, host], timeout=300)
        return rc == 0

    def run_and_capture(self, host_sample: str, host_result_dir: str,
                        run_args: str = "", timeout: int = 120) -> dict:
        """完整流程:回滚 → 运行 → 回拷转储产物。"""
        host_result_dir = Path(host_result_dir)
        host_result_dir.mkdir(parents=True, exist_ok=True)
        if not self.revert():
            return {"ok": False, "error": "revert failed"}
        if not self.ensure_power():
            return {"ok": False, "error": "start failed"}
        if not self.wait_guest():
            return {"ok": False, "error": "guest tools not ready"}
        if not self.copy_in(host_sample):
            return {"ok": False, "error": "copy in failed"}
        run = self.run_guest(run_args, timeout=timeout)
        return {"ok": run["ok"], "run": run, "collected": []}


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


def vm_configured() -> bool:
    """Return whether an explicitly selected VMware snapshot is usable."""
    return bool(
        config.USE_SANDBOX_VM
        and config.VM_SNAPSHOT
        and os.environ.get("REVLAB_VM_VMX", "")
        and Path(config.VMWARE_RUN).exists()
    )


def windows_sandbox_available() -> bool:
    return os.name == "nt" and Path(config.WINDOWS_SANDBOX_EXE).exists()


def sandboxie_available() -> bool:
    return os.name == "nt" and _sandboxie_start_path() is not None


def sandbox_capabilities() -> dict:
    """Describe safe dynamic backends without starting any process."""
    vm = vm_configured()
    si = sandboxie_available()
    ws = windows_sandbox_available()
    host = bool(config.ALLOW_HOST_EXECUTION)
    requested = str(config.DYNAMIC_BACKEND or "auto").lower()
    if requested in {"quick", "isolated", "sandboxie-plus", "sandboxie"}:
        requested = "sandboxie"
    elif requested in {"windows-sandbox"}:
        requested = "windows_sandbox"
    if requested == "auto":
        # VMware is intentionally manual-only. Merely finding a VM must not
        # power it on or surprise the user with a long boot.
        selected = "sandboxie" if si else ("windows_sandbox" if ws else "blocked")
    elif requested == "host":
        selected = "host" if host else "blocked"
    elif requested == "vmware":
        selected = "vmware" if vm else "blocked"
    elif requested == "windows_sandbox":
        selected = "windows_sandbox" if ws else "blocked"
    elif requested == "sandboxie":
        selected = "sandboxie" if si else "blocked"
    else:
        selected = "blocked"
    return {
        "requested": requested,
        "selected": selected,
        "host_execution_allowed": host,
        "backends": {
            "sandboxie": {"available": si, "network": "sandbox_policy", "gui": False,
                          "path": str(_sandboxie_start_path() or "")},
            "windows_sandbox": {"available": ws, "network": "disabled", "gui": False},
            "vmware": {"available": vm, "network": "depends_on_vmx", "gui": False,
                       "manual_only": True},
            "host": {"available": host, "requires_confirmation": not host,
                     "network": "host_network", "gui": False},
        },
        "message": (
            "Sandboxie-Plus 轻量隔离"
            if selected == "sandboxie" else
            "短时 Windows Sandbox"
            if selected == "windows_sandbox" else
            "已配置的 VMware 快照"
            if selected == "vmware" else
            "明确允许的宿主机执行"
            if selected == "host" else
            "没有可用的隔离动态后端；未执行样本"
        ),
    }


def create_sandbox(mode: str = "", timeout: int | None = None,
                   confirm_host_execution: bool = False) -> object:
    """Create the explicitly selected safe runner; fail closed otherwise."""
    requested = str(mode or config.DYNAMIC_BACKEND or "auto").strip().lower()
    if requested in {"quick", "isolated", "sandboxie-plus", "sandboxie"}:
        requested = "sandboxie"
    elif requested in {"windows-sandbox"}:
        requested = "windows_sandbox"
    if requested == "auto":
        requested = sandbox_capabilities()["selected"]
    run_timeout = int(timeout or config.SANDBOX_TIMEOUT)
    if requested == "sandboxie":
        if not sandboxie_available():
            raise SandboxError(
                "Sandboxie-Plus is unavailable; install it or choose another backend"
            )
        return SandboxieRunner(timeout=run_timeout)
    if requested == "windows_sandbox":
        if not windows_sandbox_available():
            raise SandboxError(
                "Windows Sandbox is unavailable; enable Containers-DisposableClientVM "
                "or select a configured isolated backend"
            )
        return WindowsSandbox(timeout=run_timeout)
    if requested == "vmware":
        if not vm_configured():
            raise SandboxError(
                "VMware backend is not configured; set REVLAB_SANDBOX_VM=1, "
                "REVLAB_VM_VMX and REVLAB_VM_SNAPSHOT"
            )
        return VMSandbox(os.environ["REVLAB_VM_VMX"], config.VM_SNAPSHOT, config.VM_GUEST_PATH)
    if requested == "host":
        # A direct request may carry a one-shot user confirmation.  The AI
        # tool loop never sets this flag, so it cannot silently escape the
        # isolated backends.  The environment switch remains the convenient
        # opt-in for a dedicated lab machine.
        if not config.ALLOW_HOST_EXECUTION and not confirm_host_execution:
            raise SandboxError(
                "Host execution requires explicit per-run confirmation; use an isolated "
                "backend or confirm_host_execution=true in a deliberate lab run"
            )
        return LocalSandbox(timeout=run_timeout)
    raise SandboxError("No isolated dynamic backend is available; sample was not executed")
