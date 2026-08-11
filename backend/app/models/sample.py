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
