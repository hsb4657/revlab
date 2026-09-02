"""REVLab 后端入口"""
import logging
import os
import secrets
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .api.routes import router as api_router
from .api.workflow2_routes import router as wf2_router
from .api.artifact_routes import router as artifact_router
from .core.config import BASE_DIR, config
from .core.database import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(title="REVLab - Windows PE 逆向工作流", version="2.0.0",
              description="实验室自研软件合规逆向测试平台")

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(config.CORS_ORIGINS),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def require_token_for_remote_api(request: Request, call_next):
    """Keep the powerful local API local unless an explicit token is configured."""
    # Browsers send CORS preflight requests without application credentials;
    # let the CORS middleware answer OPTIONS, while every actual API call
    # still requires the token for non-loopback clients.
    if request.url.path.startswith("/api") and request.method != "OPTIONS":
        host = (request.client.host if request.client else "").lower()
        local_hosts = {"127.0.0.1", "::1", "localhost", "testclient"}
        if host not in local_hosts:
            supplied = request.headers.get("X-REVLab-Token", "")
            if not config.API_TOKEN or not secrets.compare_digest(supplied, config.API_TOKEN):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Remote API access requires X-REVLab-Token"},
                )
    return await call_next(request)

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
    # Setup is an explicit user action. Starting the web UI must not begin
    # downloading tools or dependencies in the background.

app.include_router(api_router)
app.include_router(wf2_router)
app.include_router(artifact_router)

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
