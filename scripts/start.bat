@echo off
setlocal
cd /d "%~dp0.."

echo ============================================
echo   REVLab - Windows PE 逆向工作流
echo   [实验室自研软件合规逆向测试]
echo ============================================
echo.

REM 检查后端依赖
python -c "import fastapi, uvicorn, pefile, capstone, lief, sqlalchemy" >nul 2>&1
if errorlevel 1 (
  echo [安装] 正在安装后端依赖...
  pip install -r backend\requirements.txt || (echo 依赖安装失败 & pause & exit /b 1)
)

echo [启动] 后端 API  http://127.0.0.1:8000
echo [启动] MCP Server stdio / HTTP 端口 8765
echo.
start "REVLab MCP" cmd /k "python -m mcp_server.server --port 8765"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload --app-dir backend

endlocal
