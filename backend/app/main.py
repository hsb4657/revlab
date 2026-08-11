"""REVLab 后端入口"""
import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .api.routes import router as api_router
from .api.workflow2_routes import router as wf2_router
from .core.config import BASE_DIR
from .core.database import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(title="REVLab - Windows PE 逆向工作流", version="2.0.0",
              description="实验室自研软件合规逆向测试平台")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def _startup():
    init_db()
    from .services.settings import apply_settings
    apply_settings()
    from .services.workflow import init_default_workflows
    init_default_workflows()
    from .workflow_engine.manager import init_builtin_templates
    init_builtin_templates()
    from .workflow_engine.engine import recover_engine_tasks
    recover_engine_tasks()

app.include_router(api_router)
app.include_router(wf2_router)

# 静态前端
_frontend = Path(__file__).resolve().parents[2] / "frontend"
_wfdist = Path(__file__).resolve().parents[2] / "frontend" / "wf-dist"

if _frontend.exists():
    app.mount("/static", StaticFiles(directory=str(_frontend)), name="frontend")
    # Vue Flow 画布编辑器(独立构建产物)须在根挂载之前注册
    if _wfdist.exists():
        app.mount("/wf", StaticFiles(directory=str(_wfdist), html=True), name="wf-editor")
    app.mount("/", StaticFiles(directory=str(_frontend), html=True), name="root")
else:
    @app.get("/")
    def root():
        return {"app": "REVLab", "note": "frontend/ 不存在,仅提供 API"}
