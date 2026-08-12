# Windows Setup

REVLab includes a repeatable Windows bootstrap. It creates one repository-local
Python virtual environment, installs the backend and MCP dependencies, installs
the Vue Flow editor dependencies, builds `frontend/wf-dist`, and prints a clear
capability summary before the application is started.

## Quick Start

From the repository root, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1
```

Double-click users can run `scripts\setup.bat`, which forwards the same options
to the PowerShell entrypoint.

This core setup requires Python 3.10+ and Node.js 18+. It does not download
large optional tools by default. Start REVLab after a successful setup with:

```powershell
.\scripts\start.bat
```

The main application is available at `http://127.0.0.1:8000/`. Open its
**Workflow** page to use the embedded visual editor alongside preset switching,
run history, live node states, and the artifact center. The `/wf/` route is the
same editor surface used by the main application and is primarily useful for
direct technical troubleshooting.

## Complete Setup

For a fresh Windows machine with `winget` available, use the complete command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -All -PersistEnv
```

`-All` performs these operations in order:

1. Installs missing Python 3.11, Node.js LTS, and OpenJDK 21 through `winget`.
2. Creates or reuses `.venv`, then installs `backend/requirements.txt` and
   `mcp_server/requirements.txt`.
3. Runs `npm ci` for `frontend/workflow` and rebuilds `frontend/wf-dist`.
4. Downloads the latest official Ghidra archive, verifies its SHA-256, and
   installs it at `ghidra/runtime`.
5. Downloads optional UPX and PE-sieve tooling.
6. Runs Python compilation and the repository test suite.

Ghidra is a large download. Use the core command when only the static and graph
workflow capabilities are needed, then add Ghidra later with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -InstallGhidra -PersistEnv
```

## Setup Options

| Option | Effect |
| --- | --- |
| `-All` | Installs missing runtime prerequisites, Ghidra, optional PE tools, and runs verification. |
| `-InstallPrerequisites` | Uses `winget` only when Python, Node.js, or a required JDK is missing. |
| `-InstallGhidra` | Runs `scripts/install-ghidra.ps1`; Java 21 is checked first. |
| `-InstallTools` | Downloads optional UPX and PE-sieve tooling. |
| `-PersistEnv` | Stores the resolved `GHIDRA_HOME` in the current user's environment. |
| `-Verify` | Runs `compileall` and `unittest discover -s backend/tests -v`. |
| `-SkipPython` / `-SkipFrontend` | Skips one setup phase for troubleshooting. |
| `-PythonExe` / `-NodeExe` | Uses an explicit executable path instead of PATH discovery. |

The script is idempotent: it reuses `.venv`, package lockfiles, installed tools,
and a valid Ghidra runtime. Runtime downloads and generated analysis artifacts
are excluded from Git.

## Configuration

Copy `.env.example` to `.env` before using `scripts/start.ps1` if paths or
dynamic-analysis defaults need to be changed. The launch script loads this file
only into the application process; it never writes secrets or paths back to the
repository.

AI provider configuration is intentionally stored through the web application's
model settings panel. It is kept in local runtime data and is not committed.

## Expected Capability Summary

The setup summary always reports the resolved Python executable, Node.js
version, Ghidra state, UPX state, and PE-sieve state. Missing optional tools are
shown as warnings. A nonzero exit code indicates that a required setup phase or
an explicitly requested optional installation did not complete.
