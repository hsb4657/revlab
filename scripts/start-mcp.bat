@echo off
setlocal
cd /d "%~dp0.."
echo REVLab MCP Server (HTTP mode) http://127.0.0.1:8765/mcp
python -m mcp_server.server --port 8765
endlocal
