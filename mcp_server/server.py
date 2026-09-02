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
def dynamic_capabilities() -> str:
    """返回动态分析后端能力；只做探测，不启动 VM 或样本。"""
    from app.services import sandbox
    return _j(sandbox.sandbox_capabilities())


@mcp.tool()
def run_dynamic(sample_id: int, timeout: int = 60, mode: str = "auto",
                confirm_host_execution: bool = False) -> str:
    """短时运行样本；默认选择隔离后端，宿主机仅接受一次性明确确认。"""
    from app.services import sandbox
    s = _sample(sample_id)
    try:
        sb = sandbox.create_sandbox(mode=mode, timeout=timeout,
                                    confirm_host_execution=confirm_host_execution)
    except sandbox.SandboxError as exc:
        return _j({"ok": True, "executed": False,
                   "execution_status": "blocked_by_policy", "message": str(exc),
                   "capabilities": sandbox.sandbox_capabilities()})
    if isinstance(sb, sandbox.SandboxieRunner):
        r = sb.run_and_capture(s.stored_path, str(config.CAPTURES_DIR), config.SANDBOX_RUN_ARGS, timeout)
        return _j({**r, "executed": bool(r.get("executed")), "runner": "sandboxie"})
    if isinstance(sb, sandbox.VMSandbox):
        r = sb.run_and_capture(s.stored_path, str(config.UNPACKED_DIR), config.SANDBOX_RUN_ARGS, timeout)
        return _j({**r, "executed": bool(r.get("ok")), "runner": "vmware"})
    if isinstance(sb, sandbox.WindowsSandbox):
        r = sb.run_and_capture(s.stored_path, str(config.CAPTURES_DIR), config.SANDBOX_RUN_ARGS, timeout)
        return _j({**r, "executed": bool(r.get("executed")), "runner": "windows_sandbox"})
    mon = sandbox.BehaviorMonitor(watch_dirs=[str(Path(s.stored_path).parent)])
    sb = sandbox.LocalSandbox(timeout=timeout, monitor=mon)
    result = sb.run(s.stored_path, config.SANDBOX_RUN_ARGS)
    return _j({**result, "executed": bool(result.get("ok")), "runner": "local"})


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


# ================================================================ UE 虚幻引擎分析
@mcp.tool()
def ue_versions() -> str:
    """列出内置 UE 虚幻引擎版本知识库(版本/结构/索引方式)。"""
    from app.services.ue.versions import all_versions, UE_VERSIONS, FNAME_DETAILS
    return _j([{"version": v, "engine": UE_VERSIONS[v]["engine"], "family": UE_VERSIONS[v]["family"],
                "fname": UE_VERSIONS[v]["fname"],
                "fname_detail": FNAME_DETAILS.get(UE_VERSIONS[v]["fname"]),
                "note": UE_VERSIONS[v]["note"]} for v in all_versions()])


@mcp.tool()
def ue_analyze(sample_id: int, version: str = "") -> str:
    """对样本执行 UE 分析:版本识别 → 三大件(GNames/GObjects/GWorld)定位 → FName 解密分析 → 加密检测。version 可选。"""
    from app.services.ue.analyzer import analyze_sample
    try:
        return _j({"ok": True, "result": analyze_sample(sample_id, version=version)})
    except ValueError as e:
        return _j({"ok": False, "error": str(e)})


@mcp.tool()
def ue_fetch_source(version: str) -> str:
    """按需拉取指定 UE 版本的关键源码头文件(仅少量小文件,本地缓存),用于结构交叉校验。"""
    from app.services.ue.source_fetcher import fetch_version_sources
    try:
        return _j({"ok": True, **fetch_version_sources(version, cache=True)})
    except Exception as e:
        return _j({"ok": False, "error": str(e)})


@mcp.tool()
def ue_report(sample_id: int, version: str = "") -> str:
    """对样本执行 UE 分析并生成报告(JSON/HTML/Markdown)。"""
    from app.services.ue.analyzer import ue_report
    try:
        return _j(ue_report(sample_id, version=version))
    except ValueError as e:
        return _j({"ok": False, "error": str(e)})


# ================================================================ Unity 引擎分析
def _trim_result(result: dict) -> dict:
    """精简引擎分析结果:剔除 _stages/_params 进度与超大字段,保留关键统计。"""
    r = dict(result or {})
    r.pop("_stages", None)
    r.pop("_params", None)
    keep_keys = ("sdk", "decrypt", "build_type", "unity_version")
    out = {}
    for k, v in r.items():
        if k == "summary":
            out[k] = v
        elif isinstance(v, dict):
            kept = {kk: vv for kk, vv in v.items() if kk in keep_keys}
            if kept:
                out[k] = kept
    return out


@mcp.tool()
def unity_analyze(path: str, version: str = "") -> str:
    """对游戏目录执行 Unity 分析(版本识别 → 解密 → SDK 统计等)。path 为游戏文件夹绝对路径。"""
    from app.services.engine_runner import start_analysis
    p = Path(path)
    if not p.exists():
        return _j({"ok": False, "error": "path not found"})
    r = start_analysis("unity", p.name, str(p), version=version)
    return _j({"ok": True, "id": r.get("id"), "engine": "unity",
               "note": "后台执行,可用 unity_status 查询"})


@mcp.tool()
def unity_status(analysis_id: int) -> str:
    """查询 Unity 分析任务状态与精简结果。"""
    from app.services.engine_runner import get_analysis
    a = get_analysis(analysis_id)
    if a is None:
        return _j({"ok": False, "error": f"analysis #{analysis_id} not found"})
    return _j({"id": a["id"], "status": a["status"], "stage": a["stage"],
               "target_name": a["target_name"], "version": a["version"],
               "result": _trim_result(a.get("result") or {})})


@mcp.tool()
def unity_dump_sdk(path: str) -> str:
    """直接对游戏目录执行 SDK 提取(不入库)。path 为游戏文件夹绝对路径。"""
    from app.services.engine_runner import start_analysis
    p = Path(path)
    if not p.exists():
        return _j({"ok": False, "error": "path not found"})
    r = start_analysis("unity", p.name, str(p), params={"dump_sdk_only": True})
    return _j({"ok": True, "id": r.get("id"), "engine": "unity",
               "note": f"任务已提交,SDK 产出位于配置报告目录 {config.REPORTS_DIR}"})


@mcp.tool()
def engine_analyses(engine: str) -> str:
    """列出指定引擎的历史分析任务列表(排除 result)。engine 为 ue / unity。"""
    from app.services.engine_runner import list_analyses
    return _j(list_analyses(engine))


# ================================================================ 图化工作流(MCP 完全接入)
@mcp.tool()
def wf_workflows() -> str:
    """列出全部图化工作流(内置模板与自定义),含节点/边数量。"""
    from app.workflow_engine import manager as wfm
    return _j(wfm.list_workflows())


@mcp.tool()
def wf_get(workflow_id: int) -> str:
    """获取工作流完整定义:节点列表(类型/参数)、边、运行变量。"""
    from app.workflow_engine import manager as wfm
    return _j(wfm.get_workflow(workflow_id))


@mcp.tool()
def wf_node_types() -> str:
    """列出节点注册表(所有可用节点类型/参数 schema),用于理解工作流能力。"""
    from app.workflow_engine.nodes.base import list_node_types
    return _j(list_node_types())


@mcp.tool()
def wf_create_task(workflow_id: int, name: str = "", sample_path: str = "",
                   sample_id: int = 0, variables: str = "{}") -> str:
    """为工作流创建运行任务。sample_path 为样本绝对路径(自动登记为运行变量);
    variables 为 JSON 对象字符串(其它运行变量,如 {"ue_version":"5.5"})。"""
    import json as _json
    from app.workflow_engine import manager as wfm
    try:
        extra = _json.loads(variables or "{}")
    except ValueError as e:
        return _j({"ok": False, "error": f"variables 不是合法 JSON: {e}"})
    runtime = dict(extra)
    if sample_path:
        runtime.setdefault("sample_path", sample_path)
    try:
        r = wfm.create_task(int(workflow_id), name=name, variables=runtime,
                            sample_id=int(sample_id))
        return _j({"ok": True, "task_id": r.get("id")})
    except ValueError as e:
        return _j({"ok": False, "error": str(e)})


@mcp.tool()
def wf_run_task(task_id: int) -> str:
    """启动工作流任务(后台执行)。之后用 wf_task 轮询状态。"""
    from app.workflow_engine import manager as wfm
    try:
        return _j(wfm.run_task(int(task_id)))
    except ValueError as e:
        return _j({"ok": False, "error": str(e)})


@mcp.tool()
def wf_task(task_id: int) -> str:
    """查询任务状态:整体状态/错误、每个节点状态与输出、变量池。"""
    from app.workflow_engine import manager as wfm
    t = wfm.get_task(int(task_id))
    if not t:
        return _j({"ok": False, "error": f"task #{task_id} not found"})
    return _j(t)


@mcp.tool()
def wf_task_outputs(task_id: int, node_id: str = "") -> str:
    """提取任务中指定节点(或全部)的输出证据(变量池),精简后返回。
    用于让外部 AI 读取工作流各节点产出的分析证据。"""
    import json as _json
    from app.workflow_engine import manager as wfm

    def _trim(v, depth=0):
        if depth > 3:
            return "..."
        if isinstance(v, str):
            return v[:4000]
        if isinstance(v, list):
            return [_trim(i, depth + 1) for i in v[:40]]
        if isinstance(v, dict):
            return {str(k)[:64]: _trim(i, depth + 1) for k, i in list(v.items())[:60]}
        return v

    t = wfm.get_task(int(task_id))
    if not t:
        return _j({"ok": False, "error": f"task #{task_id} not found"})
    states = t.get("node_states") or {}
    if node_id:
        st = states.get(node_id)
        if not st:
            return _j({"ok": False, "error": f"node '{node_id}' not found"})
        return _j({"node": node_id, "status": st.get("status"),
                   "error": st.get("error", ""), "outputs": _trim(st.get("outputs") or {})})
    return _j({
        "task_id": task_id,
        "status": t.get("status"),
        "nodes": {
            nid: {
                "status": st.get("status"),
                "error": st.get("error", ""),
                "summary": (st.get("outputs") or {}).get("__summary", ""),
                "outputs": _trim({k: v for k, v in (st.get("outputs") or {}).items()
                                  if k not in ("__summary", "evidence", "raw_response")}),
                # AI_WAITING and AI tool nodes keep their traceable evidence
                # outside the ordinary scalar outputs.  Expose a bounded copy
                # here so an external agent can actually continue the task.
                "evidence": _trim((st.get("outputs") or {}).get("evidence") or {}),
                "tool_trace": _trim((st.get("outputs") or {}).get("tool_trace") or []),
            }
            for nid, st in states.items()
        },
        "variables": _trim({k: v for k, v in (t.get("variables") or {}).items()
                            if not str(k).startswith("_")}),
    })


@mcp.tool()
def wf_retry_node(task_id: int, node_id: str) -> str:
    """重跑任务中的单个节点(及其后未完成节点)。"""
    from app.workflow_engine.engine import retry_node
    return _j(retry_node(int(task_id), str(node_id)))


@mcp.tool()
def wf_skip_node(task_id: int, node_id: str) -> str:
    """跳过任务中的单个节点。"""
    from app.workflow_engine.engine import skip_node
    return _j(skip_node(int(task_id), str(node_id)))


@mcp.tool()
def wf_stop_task(task_id: int) -> str:
    """停止运行中的任务。"""
    from app.workflow_engine.engine import stop_task
    return _j({"ok": stop_task(int(task_id))})


@mcp.tool()
def wf_resolve_ai(task_id: int, node_id: str, ai_result: str = "{}") -> str:
    """外部 AI 提交分析结论(写入任务变量池的 _ai_decision_{node_id} 键)。
    之后调用 wf_retry_node(task_id, node_id) 重跑节点,节点将自动应用此结论。
    ai_result 为 JSON 字符串,结构需含 ai_output:true 标记(自动补充)。"""
    import json as _json
    from app.core.database import SessionLocal
    from app.models.sample import GraphTask
    try:
        payload = _json.loads(ai_result or "{}")
    except ValueError as e:
        return _j({"ok": False, "error": f"ai_result 不是合法 JSON: {e}"})
    if not isinstance(payload, dict):
        return _j({"ok": False, "error": "ai_result 必须是 JSON 对象"})
    payload["ai_output"] = True
    payload["configured"] = True
    payload["source"] = "external_ai_via_mcp"
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == int(task_id)).first()
        if not t:
            return _j({"ok": False, "error": f"task #{task_id} not found"})
        variables = dict(t.variables or {})
        variables[f"_ai_decision_{str(node_id)}"] = payload
        t.variables = variables
        db.commit()
        return _j({"ok": True, "task_id": int(task_id), "node": str(node_id),
                   "next_step": f"调用 wf_retry_node({task_id}, '{node_id}') 重跑节点以应用结论"})
    finally:
        db.close()


@mcp.tool()
def wf_list_tasks(workflow_id: int, limit: int = 20) -> str:
    """列出指定工作流的历史任务。"""
    from app.workflow_engine import manager as wfm
    return _j(wfm.list_tasks(int(workflow_id), limit))


@mcp.tool()
def wf_ue_assist(sample_id: int, version: str = "") -> str:
    """UE AI 辅助证据包:为外部 AI 直接提供可分析的静态证据
    (三大件候选/签名命中/GetName 反汇编/XOR 密钥/加密信号),无需内部 LLM 配置。"""
    from app.services import pe_parser
    from app.services.ue import ai_assist
    from app.services.ue.analyzer import analyze_sample
    s = _sample(sample_id)
    data = Path(s.stored_path).read_bytes()
    pe = pe_parser.parse_pe(data, s.stored_path)
    result = analyze_sample(sample_id, version=version)
    evidence = ai_assist.build_ue_evidence(result, data, pe)
    return _j({"ok": True, "evidence": evidence})


@mcp.tool()
def wf_ai_inject(task_id: int, node_name: str = "ue_ai_assist", ai_result: str = "{}") -> str:
    """将外部 AI 的辅助分析结论注入任务变量池(自动打 ai_output 标记)。
    报告节点(ue_report / report / unity_report)渲染时会收集并展示。
    注入后调用 wf_retry_node(task_id, report节点id) 重跑报告节点即可生效。
    结构约定(ue_ai_assist):
      three_majors.{gobjects,gnames,gworld,gengine}.{rva,rva_hex,absolute_va_hex,confidence,reason}
      getname_algorithm.{model,block_bits,entry_stride,header_info_offset,wide_bit,length_shift,key_hex,description,steps}
      decryption_algorithm.{detected,algorithm,key_hex,description,steps}
      notes:[...]"""
    import json as _json
    from app.core.database import SessionLocal
    from app.models.sample import GraphTask
    try:
        payload = _json.loads(ai_result or "{}")
    except ValueError as e:
        return _j({"ok": False, "error": f"ai_result 不是合法 JSON: {e}"})
    if not isinstance(payload, dict):
        return _j({"ok": False, "error": "ai_result 必须是 JSON 对象"})
    payload["ai_output"] = True
    payload["configured"] = True
    payload["source"] = "mcp_external_ai"
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == int(task_id)).first()
        if not t:
            return _j({"ok": False, "error": f"task #{task_id} not found"})
        variables = dict(t.variables or {})
        variables[str(node_name)] = payload
        states = dict(t.node_states or {})
        st = dict(states.get(str(node_name)) or {})
        st["outputs"] = payload
        st["status"] = st.get("status", "completed")
        states[str(node_name)] = st
        t.variables = variables
        t.node_states = states
        db.commit()
        return _j({"ok": True, "task_id": t.id, "node": str(node_name),
                   "hint": "调用 wf_retry_node 重跑报告节点后,报告将包含 AI 辅助分析章节"})
    finally:
        db.close()


@mcp.tool()
async def wf_regen_report(task_id: int, node_id: str = "report") -> str:
    """同步重新生成报告节点(不经过引擎调度)。用于外部 AI 注入结论(wf_ai_inject)后
    立即刷新报告。node_id 取报告节点 id(ue_report / report / unity_report)。"""
    from app.core.database import SessionLocal
    from app.models.sample import GraphTask, GraphWorkflow
    from app.workflow_engine.nodes.base import get_node_class
    from app.workflow_engine.variables import resolve
    from app.services.artifacts import task_output_directory
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == int(task_id)).first()
        if not t:
            return _j({"ok": False, "error": f"task #{task_id} not found"})
        wf = db.query(GraphWorkflow).filter(GraphWorkflow.id == t.workflow_id).first()
        node_def = next((n for n in (wf.nodes or []) if n.get("id") == str(node_id)), None)
        if node_def is None:
            return _j({"ok": False, "error": f"workflow 中无节点 '{node_id}'"})
        cls = get_node_class(node_def.get("type"))
        if cls is None:
            return _j({"ok": False, "error": f"未知节点类型: {node_def.get('type')}"})
        params = dict(node_def.get("params") or {})
        variables = dict(t.variables or {})
        for k, v in params.items():
            if isinstance(v, str) and "{{" in v:
                params[k] = resolve(v, variables)
        ctx = {"node": node_def, "params": params, "pool": variables,
               "task_id": t.id, "output_dir": str(task_output_directory(t.id))}
    finally:
        db.close()
    try:
        res = await cls().execute(ctx)
    except Exception as e:
        return _j({"ok": False, "error": f"报告节点执行异常: {e}"})
    outputs = getattr(res, "outputs", None)
    if getattr(res, "status", "failed") == "failed":
        return _j({"ok": False, "error": getattr(res, "error", "unknown")})
    db = SessionLocal()
    try:
        t = db.query(GraphTask).filter(GraphTask.id == int(task_id)).first()
        variables = dict(t.variables or {})
        variables[str(node_id)] = outputs
        states = dict(t.node_states or {})
        st = dict(states.get(str(node_id)) or {})
        st["status"] = "completed"
        st["outputs"] = outputs
        st["error"] = ""
        states[str(node_id)] = st
        t.variables = variables
        t.node_states = states
        db.commit()
        paths = (outputs or {}).get("report_paths") or {}
        return _j({"ok": True, "node": str(node_id),
                   "summary": getattr(res, "summary", ""),
                   "report_paths": paths})
    finally:
        db.close()


def main():
    ap = argparse.ArgumentParser(description="REVLab MCP Server")
    ap.add_argument("--port", type=int, default=0, help="HTTP 端口(设置则启用 streamable-http,否则 stdio)")
    ap.add_argument("--stdio", action="store_true", help="强制 stdio 模式")
    args = ap.parse_args()
    if args.stdio or not args.port:
        mcp.run()
    else:
        from copy import deepcopy
        s = deepcopy(mcp.settings)
        s.host = "127.0.0.1"
        s.port = args.port
        mcp.settings = s
        print(f"REVLab MCP server listening on http://127.0.0.1:{args.port}/mcp", flush=True)
        mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
