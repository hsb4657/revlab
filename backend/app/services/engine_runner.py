"""通用引擎专项分析执行器(UE / Unity 共用)
约定:每个引擎模块必须提供
  STAGES: 阶段名列表
  TITLES: {stage: 中文名}
  execute_stage(stage, ctx, result) -> dict  # 执行单阶段,返回要并入 result 的 dict
  describe(analysis) -> dict                 # 生成 summary(可选)
ctx = {"params": {...}, "target_path": str, "sample_path": str|None, "data": bytes|None,
       "analysis_id": int, "workdir": Path}
"""
from __future__ import annotations
import copy
import logging
import threading
import traceback
from datetime import datetime
from pathlib import Path

from ..core.database import SessionLocal
from ..models.sample import EngineAnalysis

log = logging.getLogger("revlab.engine")

ENGINE_MODULES = {}  # engine -> module(dict 缓存)


def _load_engine(engine: str):
    if engine in ENGINE_MODULES:
        return ENGINE_MODULES[engine]
    if engine == "ue":
        from ..services import ue as m
    elif engine == "unity":
        from ..services import unity as m
    else:
        raise ValueError(f"unknown engine: {engine}")
    if not hasattr(m, "execute_stage"):
        raise ValueError(f"engine module '{engine}' missing execute_stage")
    ENGINE_MODULES[engine] = m
    return m


def engine_spec(engine: str) -> dict:
    m = _load_engine(engine)
    return {"engine": engine, "stages": m.STAGES, "titles": m.TITLES}


def _save(analysis_id: int, **kw):
    db = SessionLocal()
    try:
        a = db.query(EngineAnalysis).filter(EngineAnalysis.id == analysis_id).first()
        if a:
            for k, v in kw.items():
                setattr(a, k, v)
            db.commit()
    finally:
        db.close()


def _get_result(analysis_id: int) -> dict:
    db = SessionLocal()
    try:
        a = db.query(EngineAnalysis).filter(EngineAnalysis.id == analysis_id).first()
        return copy.deepcopy(a.result or {}) if a else {}
    finally:
        db.close()


def _node_update(analysis_id: int, result: dict, stage: str, status: str, started=None, finished=None, error=""):
    nodes = result.setdefault("_stages", [])
    node = next((n for n in nodes if n["name"] == stage), None)
    if node is None:
        m = _load_engine(_engine_of(analysis_id))
        node = {"name": stage, "title": m.TITLES.get(stage, stage), "status": "pending",
                "started": None, "finished": None, "duration": 0, "error": ""}
        nodes.append(node)
    node["status"] = status
    if started:
        node["started"] = started
    if finished:
        node["finished"] = finished
        if started:
            try:
                st = datetime.fromisoformat(started.replace("Z", ""))
                en = datetime.fromisoformat(finished.replace("Z", ""))
                node["duration"] = round((en - st).total_seconds(), 1)
            except Exception:
                node["duration"] = 0
    if error:
        node["error"] = error


def _engine_of(analysis_id: int) -> str:
    db = SessionLocal()
    try:
        a = db.query(EngineAnalysis).filter(EngineAnalysis.id == analysis_id).first()
        return a.engine if a else "ue"
    finally:
        db.close()


class EngineRunner:
    def __init__(self, analysis_id: int, engine: str):
        self.analysis_id = analysis_id
        self.engine = engine

    def run(self):
        m = _load_engine(self.engine)
        db = SessionLocal()
        try:
            a = db.query(EngineAnalysis).filter(EngineAnalysis.id == self.analysis_id).first()
            params = dict(a.result.get("_params", {})) if a and a.result else {}
            target_path = a.target_path if a else ""
            sample_path = ""
        finally:
            db.close()
        data = None
        if sample_path and Path(sample_path).exists():
            data = Path(sample_path).read_bytes()

        ctx = {"params": params, "target_path": target_path,
               "sample_path": sample_path, "data": data,
               "analysis_id": self.analysis_id,
               "workdir": Path(target_path) if target_path else None}
        result = {"_params": params}

        self._mark("running", "")
        try:
            for stage in m.STAGES:
                self._mark("running", stage)
                started = datetime.utcnow().isoformat() + "Z"
                # 初始化节点(含后续阶段)
                nodes = result.setdefault("_stages", [])
                for s in m.STAGES:
                    if not any(n["name"] == s for n in nodes):
                        nodes.append({"name": s, "title": m.TITLES.get(s, s), "status": "pending",
                                      "started": None, "finished": None, "duration": 0, "error": ""})
                _node_update(self.analysis_id, result, stage, "running", started=started)
                result["_stages"] = nodes
                self._persist(result)
                try:
                    stage_out = m.execute_stage(stage, ctx, result)
                    if isinstance(stage_out, dict):
                        # 阶段输出并入 result(不覆盖 _stages/_params)
                        stage_out.pop("_stages", None)
                        stage_out.pop("_params", None)
                        result[stage] = stage_out
                except Exception as se:
                    log.exception("engine %s stage %s failed", self.engine, stage)
                    _node_update(self.analysis_id, result, stage, "error",
                                 started=started, finished=datetime.utcnow().isoformat() + "Z",
                                 error=str(se))
                    self._persist(result)
                    raise
                _node_update(self.analysis_id, result, stage, "done",
                             started=started, finished=datetime.utcnow().isoformat() + "Z")
                self._persist(result)
                log.info("engine %s stage %s done (analysis %s)", self.engine, stage, self.analysis_id)
            # 汇总
            if hasattr(m, "summarize"):
                result["summary"] = m.summarize(result)
            self._persist(result)
            self._mark("done", "")
            return {"ok": True}
        except Exception as e:
            log.exception("engine %s failed", self.engine)
            self._mark("error", "", error=f"{e}\n{traceback.format_exc()}")
            return {"ok": False, "error": str(e)}

    def _mark(self, status: str, stage: str, error: str = ""):
        _save(self.analysis_id, status=status, stage=stage, error=error)

    def _persist(self, result: dict):
        db = SessionLocal()
        try:
            a = db.query(EngineAnalysis).filter(EngineAnalysis.id == self.analysis_id).first()
            if a:
                a.result = copy.deepcopy(result)
                db.commit()
        finally:
            db.close()


def start_analysis(engine: str, target_name: str, target_path: str,
                   sample_id: int = 0, version: str = "", params: dict = None) -> dict:
    """创建引擎分析记录并后台执行。"""
    _load_engine(engine)  # 提前校验模块存在
    db = SessionLocal()
    try:
        rec = EngineAnalysis(engine=engine, target_name=target_name, target_path=target_path,
                             sample_id=sample_id, version=version,
                             status="pending",
                             result={"_params": params or {}, "_stages": []})
        db.add(rec)
        db.commit()
        aid = rec.id
    finally:
        db.close()

    def _run():
        EngineRunner(aid, engine).run()
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return {"ok": True, "id": aid, "engine": engine}


def list_analyses(engine: str) -> list:
    db = SessionLocal()
    try:
        rows = db.query(EngineAnalysis).filter(EngineAnalysis.engine == engine) \
            .order_by(EngineAnalysis.id.desc()).limit(200).all()
        return [{
            "id": a.id, "engine": a.engine, "target_name": a.target_name,
            "target_path": a.target_path, "sample_id": a.sample_id,
            "version": a.version, "status": a.status, "stage": a.stage,
            "error": a.error,
            "created_at": a.created_at.isoformat() + "Z" if a.created_at else None,
            "report_paths": a.report_paths or {},
        } for a in rows]
    finally:
        db.close()


def get_analysis(analysis_id: int) -> dict:
    db = SessionLocal()
    try:
        a = db.query(EngineAnalysis).filter(EngineAnalysis.id == analysis_id).first()
        if not a:
            return None
        return {
            "id": a.id, "engine": a.engine, "target_name": a.target_name,
            "target_path": a.target_path, "sample_id": a.sample_id,
            "version": a.version, "status": a.status, "stage": a.stage,
            "error": a.error, "result": a.result or {},
            "report_paths": a.report_paths or {},
            "created_at": a.created_at.isoformat() + "Z" if a.created_at else None,
        }
    finally:
        db.close()


def delete_analysis(analysis_id: int) -> bool:
    db = SessionLocal()
    try:
        a = db.query(EngineAnalysis).filter(EngineAnalysis.id == analysis_id).first()
        if not a:
            return False
        db.delete(a)
        db.commit()
        return True
    finally:
        db.close()
