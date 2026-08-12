@echo off
setlocal
cd /d "%~dp0.."
set "PYTHON=%CD%\.venv\Scripts\python.exe"
if not exist "%PYTHON%" (
  echo REVLab .venv is missing. Run scripts\setup.ps1 first.
  exit /b 1
)
echo REVLab MCP Server (HTTP mode) http://127.0.0.1:8765/mcp
"%PYTHON%" -m mcp_server.server --port 8765
endlocal
