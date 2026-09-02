from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text

from ..core.database import Base


class Sample(Base):
    __tablename__ = "samples"

    id = Column(Integer, primary_key=True)
    file_name = Column(String(512), nullable=False)
    stored_path = Column(String(1024), nullable=False)
    file_size = Column(Integer, default=0)
    workflow_name = Column(String(64), default="full-auto")

    md5 = Column(String(32), index=True)
    sha1 = Column(String(40), index=True)
    sha256 = Column(String(64), index=True)
    imphash = Column(String(32), index=True)
    ssdeep = Column(String(128), default="")

    machine = Column(String(64))
    arch = Column(String(16))
    is_pe = Column(Integer, default=0)
    is_64bit = Column(Integer, default=0)
    subsystem = Column(String(64))
    entry_point = Column(String(32))
    image_base = Column(String(32))

    packer_hits = Column(JSON, default=list)
    packer_verdict = Column(String(64), default="")

    status = Column(String(32), default="uploaded")  # uploaded/analyzing/analyzed/error
    stage = Column(String(64), default="idle")       # 流水线当前阶段

    summary = Column(JSON, default=dict)             # 汇总(节区/熵/导入导出统计等)
    report_path = Column(String(1024))
    unpacked_path = Column(String(1024))
    pcap_path = Column(String(1024))
    decompiled_path = Column(String(1024))

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    error = Column(Text, default="")


class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id = Column(Integer, primary_key=True)
    sample_id = Column(Integer, ForeignKey("samples.id"), index=True)
    stage = Column(String(64))
    engine = Column(String(64))
    success = Column(Integer, default=0)
    detail = Column(JSON, default=dict)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime)
    error = Column(Text, default="")


class Workflow(Base):
    """可自定义的分析工作流定义。"""
    __tablename__ = "workflows"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, index=True)
    description = Column(String(512), default="")
    is_default = Column(Integer, default=0)
    enabled = Column(Integer, default=1)
    stages = Column(JSON, default=list)   # [{name, enabled, params:{...}}, ...]
    created_at = Column(DateTime, default=datetime.utcnow)


class EngineAnalysis(Base):
    """引擎专项分析记录(UE / Unity),支持阶段进度可视化与历史回溯。"""
    __tablename__ = "engine_analyses"

    id = Column(Integer, primary_key=True)
    engine = Column(String(16), index=True)          # "ue" / "unity"
    target_name = Column(String(512), default="")
    target_path = Column(String(1024), default="")
    sample_id = Column(Integer, default=0, index=True)
    version = Column(String(32), default="")
    status = Column(String(32), default="pending")   # pending/running/done/error
    stage = Column(String(64), default="")
    result = Column(JSON, default=dict)              # 分析结果(含 _stages 进度节点)
    report_paths = Column(JSON, default=dict)
    error = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class GraphWorkflow(Base):
    """图化工作流定义(节点+边+变量,支持分支/条件/并行)。"""
    __tablename__ = "graph_workflows"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, index=True)
    description = Column(String(512), default="")
    nodes = Column(JSON, default=list)      # [{id,label,type,params,x,y}]
    edges = Column(JSON, default=list)      # [{id,from,to,condition?,is_default?}]
    variables = Column(JSON, default=list)  # [{key,name,type,default,required,source_type,source_node_id}]
    is_builtin = Column(Integer, default=0) # 预置模板(PE全自动/UE/Unity)
    enabled = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class GraphTask(Base):
    """图工作流运行实例。"""
    __tablename__ = "graph_tasks"

    id = Column(Integer, primary_key=True)
    workflow_id = Column(Integer, index=True)
    sample_id = Column(Integer, index=True, default=0)
    workflow_version = Column(String(64), default="")
    definition_snapshot = Column(JSON, default=dict)
    name = Column(String(128), default="")
    status = Column(String(32), default="pending")   # pending/running/completed/failed/stopped
    status_version = Column(Integer, default=0)
    cancel_requested = Column(Integer, default=0)
    heartbeat_at = Column(DateTime)
    node_states = Column(JSON, default=dict)         # {node_id: {status, outputs, attempts, error, started_at, finished_at}}
    variables = Column(JSON, default=dict)           # 变量池(用户填参 + 节点输出)
    error = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AIChatSession(Base):
    """Persistent AI conversation metadata.

    The messages intentionally live in a separate table so a session can grow
    without serializing an ever-growing JSON column on every reply.
    """
    __tablename__ = "ai_chat_sessions"

    id = Column(String(36), primary_key=True)
    title = Column(String(256), default="New conversation")
    model = Column(String(256), default="")
    reasoning = Column(String(32), default="balanced")
    sample_id = Column(Integer, default=0, index=True)
    system_prompt = Column(Text, default="")
    summary = Column(Text, default="")
    summary_upto = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AIChatMessage(Base):
    """A single immutable turn in a persistent AI chat session."""
    __tablename__ = "ai_chat_messages"

    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), ForeignKey("ai_chat_sessions.id"), index=True)
    role = Column(String(16), default="user")
    content = Column(Text, default="")
    model = Column(String(256), default="")
    reasoning = Column(String(32), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
