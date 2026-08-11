"""REVLab MCP Server:将逆向分析能力暴露给 AI 智能体
用法:
  python -m mcp_server.server                 # stdio(默认,适配 Claude Code/Codex/Cursor)
  python -m mcp_server.server --port 8765     # streamable-http(适配自定义客户端)
"""
import argparse
import json
import sys
from pathlib import Path

# 使 backend 可导入
_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from app.core.config import config  # noqa: E402
from app.core.database import SessionLocal, init_db  # noqa: E402
from app.models.sample import Sample  # noqa: E402
from app.orchestrator.pipeline import Runner  # noqa: E402
from app.services import hash as hash_svc  # noqa: E402
from app.services import packer, pcap, strings  # noqa: E402
from app.services import disassembler, pe_parser  # noqa: E402
from app.services import report as report_svc  # noqa: E402
from app.services.unpacker import unpack_known  # noqa: E402
from app.services.ghidra_bridge import decompile_with_ghidra, load_decompile, ghidra_available  # noqa: E402

init_db()
mcp = FastMCP("revlab")


def _sample(sample_id: int) -> Sample:
    db = SessionLocal()
    try:
        s = db.query(Sample).filter(Sample.id == sample_id).first()
        if s is None:
            raise ValueError(f"sample #{sample_id} not found")
        return s
    finally:
        db.close()


def _path(sample_id: int) -> str:
    return _sample(sample_id).stored_path


def _load(sample_id: int) -> bytes:
    return Path(_path(sample_id)).read_bytes()


def _j(data) -> str:
    return json.dumps(data, ensure_ascii=False, indent=1, default=str)


# ================================================================ 样本库
@mcp.tool()
def list_samples() -> str:
    """列出样本库中的样本(最近200个)。"""
    db = SessionLocal()
    try:
        rows = db.query(Sample).order_by(Sample.id.desc()).limit(200).all()
        return _j([{"id": s.id, "name": s.file_name, "sha256": s.sha256,
                    "machine": s.machine, "packer": s.packer_verdict,
                    "status": s.status, "stage": s.stage} for s in rows])
    finally:
        db.close()


@mcp.tool()
def register_sample(path: str) -> str:
    """将本地文件登记入库,返回 sample_id。path 为样本文件的绝对路径。"""
    p = Path(path)
    if not p.exists():
        return _j({"ok": False, "error": f"file not found: {path}"})
    data = p.read_bytes()
    import pefile
    try:
        pe = pefile.PE(data=data)
    except Exception:
        pe = None
    hashes = hash_svc.compute_hashes(data, pe)
    db = SessionLocal()
    try:
        exist = db.query(Sample).filter(Sample.sha256 == hashes["sha256"]).first()
        if exist:
            return _j({"ok": True, "id": exist.id, "duplicate": True})
        s = Sample(file_name=p.name, stored_path=str(p), file_size=len(data),
                   md5=hashes["md5"], sha1=hashes["sha1"], sha256=hashes["sha256"],
                   imphash=hashes["imphash"], ssdeep=hashes["ssdeep"], status="uploaded")
        db.add(s)
        db.commit()
        return _j({"ok": True, "id": s.id, "sha256": hashes["sha256"]})
    finally:
        db.close()


# ================================================================ 静态分析
@mcp.tool()
def get_pe_info(sample_id: int) -> str:
    """获取样本 PE 头/架构/子系统/安全特性等核心信息。"""
    return _j(pe_parser.parse_pe(_load(sample_id), _path(sample_id)))


@mcp.tool()
def list_sections(sample_id: int) -> str:
    """列出节区表(名称/VA/大小/熵/标志/可疑标记)。"""
    pe = pe_parser.parse_pe(_load(sample_id), _path(sample_id))
    return _j(pe.get("sections", []))


@mcp.tool()
def get_imports_exports(sample_id: int) -> str:
    """获取导入表/导出表/延迟导入/TLS回调。"""
    pe = pe_parser.parse_pe(_load(sample_id), _path(sample_id))
    return _j({"imports": pe.get("imports", []), "delayed_imports": pe.get("delayed_imports", []),
               "exports": pe.get("exports", []), "tls_callbacks": pe.get("tls_callbacks", [])})


@mcp.tool()
def extract_strings(sample_id: int, min_len: int = 6, interesting_only: bool = True) -> str:
    """提取字符串。interesting_only=True 时只返回含 url/api/dll 等关键词的兴趣项。"""
    data = _load(sample_id)
    alls = strings.extract_strings(data, min_len=min_len)
    if interesting_only:
        return _j(strings.interesting_strings(alls))
    return _j(alls)


@mcp.tool()
def detect_packer(sample_id: int) -> str:
    """检测壳/加密封装(节区特征/熵/导入异常/签名字符串)。"""
    data = _load(sample_id)
    pe = pe_parser.parse_pe(data, _path(sample_id))
    return _j(packer.detect_packer(pe, None, data))


@mcp.tool()
def disassemble(sample_id: int, address: str = "", max_insns: int = 1000) -> str:
    """反汇编。address 为起始 VA(默认入口点)。"""
    s = _sample(sample_id)
    data = _load(sample_id)
    arch = s.arch or "x64"
    image_base = int(s.image_base or "0x140000000", 16)
    start = int(address, 16) if address else int(s.entry_point or "0", 16)
    r = disassembler.disassemble_at(data, start, image_base, arch,
                                    max_insns=max_insns)
    return _j({"arch": arch, "start": hex(start), "count": r.get("count", 0),
               "insns": r.get("insns", [])})


@mcp.tool()
def analyze_pe(sample_id: int) -> str:
    """一键全量静态分析:PE信息+壳检测+字符串,返回完整结构化结果。"""
    data = _load(sample_id)
    path = _path(sample_id)
    import pefile
    pe = pefile.PE(data=data)
    hashes = hash_svc.compute_hashes(data, pe)
    pe_result = pe_parser.parse_pe(data, path)
    pe_result["packer"] = packer.detect_packer(pe_result, pe, data)
    return _j({"hashes": hashes, "pe": pe_result,
               "strings": strings.extract_strings(data, min_len=6)})


# ================================================================ 脱壳
@mcp.tool()
def unpack_known(sample_id: int) -> str:
    """对已知壳(UPX等)自动解压,返回脱壳产物路径与二次分析。"""
    s = _sample(sample_id)
    r = unpack_known(s.stored_path, s.packer_verdict or "", str(config.UNPACKED_DIR))
    out = {"ok": r.get("ok"), "path": r.get("path"), "message": r.get("message")}
    if r.get("ok") and r.get("path"):
        udata = Path(r["path"]).read_bytes()
        upe = pe_parser.parse_pe(udata, r["path"])
        out["unpacked_analysis"] = {
            "pe": upe,
            "hashes": hash_svc.compute_hashes(udata, None),
            "packer": packer.detect_packer(upe, None, udata),
        }
    return _j(out)


# ================================================================ 反编译
@mcp.tool()
def decompile_ghidra(sample_id: int) -> str:
    """Ghidra Headless 反编译,返回函数列表与 C 代码。"""
    s = _sample(sample_id)
    if not ghidra_available():
        return _j({"ok": False, "message": "Ghidra not installed"})
    out_json = str(config.GHIDRA_DIR / "decomp" / f"mcp_{sample_id}.json")
    Path(out_json).parent.mkdir(parents=True, exist_ok=True)
    r = decompile_with_ghidra(s.stored_path, out_json)
    if not r.get("ok"):
        return _j(r)
    funcs = load_decompile(out_json)
    return _j({"ok": True, "function_count": len(funcs),
               "functions": [{"addr": k, "name": v.get("name"), "signature": v.get("signature"),
                              "c": v.get("c", "")} for k, v in funcs.items()]})


# ================================================================ 动态/网络
@mcp.tool()
def run_dynamic(sample_id: int, timeout: int = 60) -> str:
    """在沙箱中运行样本,监控进程/文件/注册表行为(受控环境)。"""
    from app.services import sandbox
    s = _sample(sample_id)
    sb = sandbox.create_sandbox()
    if isinstance(sb, sandbox.VMSandbox):
        r = sb.run_and_capture(s.stored_path, str(config.UNPACKED_DIR), config.SANDBOX_RUN_ARGS, timeout)
        return _j(r)
    mon = sandbox.BehaviorMonitor(watch_dirs=[str(Path(s.stored_path).parent)])
    sb = sandbox.LocalSandbox(timeout=timeout, monitor=mon)
    return _j(sb.run(s.stored_path, config.SANDBOX_RUN_ARGS))


@mcp.tool()
def capture_network(sample_id: int = 0, duration: int = 30) -> str:
    """抓包并解析(DNS/HTTP/TLS-SNI/连接)。sample_id=0 时仅抓包不运行样本。"""
    out = str(config.CAPTURES_DIR / "manual.pcap")
    r = pcap.capture_network(duration, out)
    return _j(r)


# ================================================================ 报告/流水线
@mcp.tool()
def generate_report(sample_id: int) -> str:
    """基于已分析结果生成报告(JSON/HTML/Markdown),返回路径。"""
    s = _sample(sample_id)
    data = _load(sample_id)
    hashes = hash_svc.compute_hashes(data, None)
    pe_result = pe_parser.parse_pe(data, s.stored_path)
    pe_result["packer"] = packer.detect_packer(pe_result, None, data)
    rep = report_svc.build_report(
        {"file_name": s.file_name, "file_size": len(data), "sha256": s.sha256,
         "md5": s.md5, "imphash": s.imphash},
        {"pe": pe_result, "strings": strings.extract_strings(data, min_len=6)})
    paths = report_svc.save_report(rep, config.REPORTS_DIR, s.file_name)
    return _j({"ok": True, **paths})


@mcp.tool()
def run_pipeline(sample_id: int) -> str:
    """运行全自动分析流水线(静态→脱壳→反汇编→反编译→动态→报告)。耗时较长。"""
    r = Runner(sample_id).run(resume=True)
    return _j(r)


def main():
    ap = argparse.ArgumentParser(description="REVLab MCP Server")
    ap.add_argument("--port", type=int, default=0, help="HTTP 端口(设置则启用 streamable-http,否则 stdio)")
    ap.add_argument("--stdio", action="store_true", help="强制 stdio 模式")
    args = ap.parse_args()
    if args.stdio or not args.port:
        mcp.run()
    else:
        print(f"REVLab MCP server listening on http://127.0.0.1:{args.port}/mcp", flush=True)
        mcp.run(transport="streamable-http", host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
