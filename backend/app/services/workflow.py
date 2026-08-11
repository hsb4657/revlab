"""工作流定义服务:默认工作流初始化 + 自定义工作流 CRUD + 编排"""
import json
from pathlib import Path

from ..core.database import SessionLocal
from ..models.sample import Workflow

# 阶段元数据:名称 → (中文描述, 默认参数 schema, 可选值)
STAGE_META = {
    "identify": {
        "title": "指纹识别 & PE 静态解析",
        "desc": "哈希指纹、PE 头/节区/导入导出/字符串/签名/Rich",
        "params": {
            "string_min_len": {"label": "字符串最小长度", "type": "int", "default": 6, "min": 3, "max": 32},
        },
    },
    "unpack": {
        "title": "壳检测 & 脱壳",
        "desc": "30+ 特征库检测,已知壳解压(UPX),必要时内存转储",
        "params": {
            "memory_dump": {"label": "允许内存转储通用脱壳", "type": "bool", "default": True},
        },
    },
    "disassemble": {
        "title": "反汇编 & 交叉引用",
        "desc": "Capstone x86/x64,入口反汇编,Call/Jmp Xref",
        "params": {
            "max_insns": {"label": "入口指令上限", "type": "int", "default": 5000, "min": 100, "max": 100000},
        },
    },
    "decompile": {
        "title": "Ghidra 反编译",
        "desc": "Ghidra Headless 导出函数级 C 伪代码",
        "params": {
            "max_functions": {"label": "导出函数上限", "type": "int", "default": 200, "min": 1, "max": 2000},
        },
    },
    "dynamic": {
        "title": "动态沙箱 & 网络抓包",
        "desc": "受控运行,进程/文件/注册表监控,pktmon 抓包",
        "params": {
            "timeout": {"label": "运行超时(秒)", "type": "int", "default": 60, "min": 5, "max": 600},
            "capture_duration": {"label": "抓包时长(秒)", "type": "int", "default": 30, "min": 5, "max": 600},
        },
    },
    "report": {
        "title": "聚合报告",
        "desc": "生成 JSON/HTML/Markdown 多维报告",
        "params": {
            "formats": {"label": "输出格式", "type": "multi", "default": ["html", "json", "markdown"],
                        "options": ["html", "json", "markdown"]},
        },
    },
}

DEFAULT_STAGE_ORDER = ["identify", "unpack", "disassemble", "decompile", "dynamic", "report"]


def default_workflow() -> dict:
    """默认全自动工作流。"""
    return {
        "name": "full-auto",
        "description": "全自动深度分析:静态→脱壳→反汇编→反编译→动态→报告",
        "is_default": 1,
        "stages": [
            {"name": n, "enabled": True,
             "params": {k: v.get("default") for k, v in STAGE_META[n]["params"].items()}}
            for n in DEFAULT_STAGE_ORDER
        ],
    }


def init_default_workflows():
    """启动时初始化默认工作流(若不存在)。"""
    db = SessionLocal()
    try:
        if db.query(Workflow).filter(Workflow.name == "full-auto").first() is None:
            wf = default_workflow()
            db.add(Workflow(**wf))
            db.commit()
        # 仅静态的轻量工作流
        if db.query(Workflow).filter(Workflow.name == "static-only").first() is None:
            db.add(Workflow(
                name="static-only", description="仅静态分析:识别/壳检测/反汇编/反编译,不运行样本",
                is_default=0,
                stages=[
                    {"name": "identify", "enabled": True, "params": {"string_min_len": 6}},
                    {"name": "unpack", "enabled": True, "params": {"memory_dump": False}},
                    {"name": "disassemble", "enabled": True, "params": {"max_insns": 5000}},
                    {"name": "decompile", "enabled": True, "params": {"max_functions": 200}},
                    {"name": "dynamic", "enabled": False, "params": {"timeout": 60, "capture_duration": 30}},
                    {"name": "report", "enabled": True, "params": {"formats": ["html", "json", "markdown"]}},
                ]))
            db.commit()
    finally:
        db.close()


def list_workflows() -> list:
    db = SessionLocal()
    try:
        rows = db.query(Workflow).order_by(Workflow.is_default.desc(), Workflow.id).all()
        return [{"id": w.id, "name": w.name, "description": w.description,
                 "is_default": w.is_default, "enabled": w.enabled,
                 "stages": w.stages} for w in rows]
    finally:
        db.close()


def get_workflow(name: str):
    db = SessionLocal()
    try:
        w = db.query(Workflow).filter(Workflow.name == name).first()
        return None if w is None else {
            "id": w.id, "name": w.name, "description": w.description,
            "is_default": w.is_default, "enabled": w.enabled, "stages": w.stages}
    finally:
        db.close()


def create_workflow(name: str, description: str = "", stages: list = None) -> dict:
    db = SessionLocal()
    try:
        if db.query(Workflow).filter(Workflow.name == name).first():
            raise ValueError(f"workflow '{name}' already exists")
        if not stages:
            stages = [{"name": n, "enabled": True,
                       "params": {k: v.get("default") for k, v in STAGE_META[n]["params"].items()}}
                      for n in DEFAULT_STAGE_ORDER]
        w = Workflow(name=name, description=description, stages=stages)
        db.add(w)
        db.commit()
        return {"ok": True, "name": name}
    finally:
        db.close()


def update_workflow(name: str, description: str = None, enabled: bool = None,
                    stages: list = None) -> dict:
    db = SessionLocal()
    try:
        w = db.query(Workflow).filter(Workflow.name == name).first()
        if w is None:
            raise ValueError(f"workflow '{name}' not found")
        if description is not None:
            w.description = description
        if enabled is not None:
            w.enabled = int(enabled)
        if stages is not None:
            w.stages = stages
        db.commit()
        return {"ok": True, "name": name}
    finally:
        db.close()


def delete_workflow(name: str) -> dict:
    db = SessionLocal()
    try:
        w = db.query(Workflow).filter(Workflow.name == name).first()
        if w is None:
            raise ValueError(f"workflow '{name}' not found")
        if w.is_default:
            raise ValueError("cannot delete default workflow")
        db.delete(w)
        db.commit()
        return {"ok": True}
    finally:
        db.close()


def enabled_stages(workflow: dict) -> list:
    """返回工作流中启用的阶段名列表(按用户顺序)。"""
    if not workflow or not workflow.get("stages"):
        return DEFAULT_STAGE_ORDER
    return [s["name"] for s in workflow["stages"] if s.get("enabled", True)]


def stage_params(workflow: dict, stage: str) -> dict:
    for s in (workflow or {}).get("stages", []):
        if s["name"] == stage:
            return s.get("params", {})
    return {}
