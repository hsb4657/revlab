"""流水线编排器:按(自定义)工作流串联各分析阶段,记录阶段状态与日志,支持断点续跑"""
import copy
import logging
import traceback
from datetime import datetime
from pathlib import Path

from ..core.config import config
from ..core.database import SessionLocal
from ..models.sample import Sample, AnalysisRecord

from ..services import hash as hash_svc
from ..services import pe_parser, packer, strings, disassembler, report as report_svc
from ..services import unpacker, pcap as pcap_svc, sandbox as sandbox_svc
from ..services.ghidra_bridge import decompile_with_ghidra, load_decompile, ghidra_available
from ..services import workflow as wf_svc

log = logging.getLogger("revlab.pipeline")

DEFAULT_STAGES = ["identify", "unpack", "disassemble", "decompile", "dynamic", "report"]
STAGE_TITLES = {k: v["title"] for k, v in wf_svc.STAGE_META.items()}


def _load_pe_fast(data: bytes):
    try:
        import pefile
        return pefile.PE(data=data)
    except Exception:
        return None


class Runner:
    def __init__(self, sample_id: int, workflow: dict = None):
        self.sample_id = sample_id
        self.workflow = workflow or wf_svc.default_workflow()
        self.stage_params = {s["name"]: s.get("params", {}) for s in self.workflow.get("stages", [])}
        self.done = set()

    def _params(self, stage: str) -> dict:
        return self.stage_params.get(stage, {})

    def _load_sample(self) -> Sample:
        db = SessionLocal()
        try:
            return db.query(Sample).filter(Sample.id == self.sample_id).first()
        finally:
            db.close()

    def _mark(self, stage: str, status: str, sample: Sample = None, error: str = ""):
        db = SessionLocal()
        try:
            s = db.query(Sample).filter(Sample.id == self.sample_id).first()
            s.stage = stage
            s.status = status
            if error:
                s.error = error
            elif status in ("analyzing", "analyzed"):
                s.error = ""
            db.commit()
        finally:
            db.close()

    def _update_status_node(self, stage: str, status: str, started: str = None,
                            finished: str = None, error: str = ""):
        """更新可视化状态节点(summary._pipeline_status)。"""
        db = SessionLocal()
        try:
            s = db.query(Sample).filter(Sample.id == self.sample_id).first()
            summary = copy.deepcopy(s.summary or {})  # 修改前深拷贝,避免污染旧值
            nodes = summary.get("_pipeline_status", [])
            node = next((n for n in nodes if n["name"] == stage), None)
            if node is None:
                node = {"name": stage, "title": STAGE_TITLES.get(stage, stage),
                        "status": "pending", "started": None, "finished": None,
                        "duration": 0, "error": ""}
                nodes.append(node)
            node["status"] = status
            if started:
                node["started"] = started
            if finished:
                node["finished"] = finished
                try:
                    from datetime import datetime as dt
                    st = dt.fromisoformat(node["started"].replace("Z", "")) if node["started"] else None
                    en = dt.fromisoformat(finished.replace("Z", ""))
                    node["duration"] = round((en - st).total_seconds(), 1) if st else 0
                except Exception:
                    node["duration"] = 0
            if error:
                node["error"] = error
            # 按工作流阶段顺序排序
            order = {n: i for i, n in enumerate(DEFAULT_STAGES)}
            nodes.sort(key=lambda x: order.get(x["name"], 99))
            summary["_pipeline_status"] = nodes
            s.summary = summary  # 独立副本,内容与旧值不同,触发 JSON 列更新
            db.commit()
        finally:
            db.close()

    def _record(self, stage: str, engine: str, success: bool, detail: dict, error: str = "",
                started: datetime = None):
        db = SessionLocal()
        try:
            rec = AnalysisRecord(
                sample_id=self.sample_id, stage=stage, engine=engine,
                success=int(success), detail=detail or {}, error=error,
                started_at=started or datetime.utcnow(), finished_at=datetime.utcnow(),
            )
            db.add(rec)
            db.commit()
        finally:
            db.close()

    # ------------------------------------------------------------ stages
    def _stage_identify(self, data: bytes, path: str) -> dict:
        p = self._params("identify")
        pe = _load_pe_fast(data)
        hashes = hash_svc.compute_hashes(data, pe)
        pe_result = pe_parser.parse_pe(data, path)
        pe_result["packer"] = packer.detect_packer(pe_result, pe, data)
        strings_res = strings.extract_strings(data, min_len=int(p.get("string_min_len", 6)))
        pe_result["pdb"] = strings.pdb_hint(strings_res)
        return {
            "hashes": hashes,
            "pe": pe_result,
            "strings": strings_res,
            "string_count": len(strings_res),
        }

    def _stage_unpack(self, data: bytes, path: str, pe_result: dict) -> dict:
        verdict = (pe_result.get("packer") or {}).get("verdict", "")
        out = {"verdict": verdict, "unpacked": None}
        if verdict and verdict not in ("Not packed (likely)", "Packed/Protected (unknown)"):
            r = unpacker.unpack_known(path, verdict, str(config.UNPACKED_DIR))
            out["unpacked"] = r
            if r.get("ok") and r.get("path"):
                udata = Path(r["path"]).read_bytes()
                upe = pe_parser.parse_pe(udata, r["path"])
                upe["packer"] = packer.detect_packer(upe, _load_pe_fast(udata), udata)
                out["unpacked_analysis"] = {
                    "hashes": hash_svc.compute_hashes(udata, _load_pe_fast(udata)),
                    "pe": upe,
                    "strings": strings.extract_strings(udata, min_len=6),
                }
        return out

    def _stage_disassemble(self, data: bytes, pe_result: dict) -> dict:
        p = self._params("disassemble")
        arch = "x64" if pe_result.get("is_64bit") else "x86"
        image_base = int(pe_result.get("image_base", "0x0"), 16)
        ep = int(pe_result.get("entry_point", "0x0"), 16) - image_base
        dis = disassembler.disassemble_entry(data, ep, image_base, arch,
                                             max_insns=int(p.get("max_insns", 5000)),
                                             sections=pe_result.get("sections"))
        xrefs = disassembler.compute_xrefs(dis.get("insns", []))
        return {"arch": arch, "count": dis.get("count", 0),
                "insns": dis.get("insns", [])[:2000], "xrefs": xrefs,
                "functions_hint": len(set(xrefs.get("call_targets", [])) | set(xrefs.get("jmp_targets", [])))}

    def _stage_decompile(self, path: str) -> dict:
        p = self._params("decompile")
        if not config.ENABLE_GHIDRA or not ghidra_available():
            return {"ok": False, "message": "Ghidra 未安装,跳过反编译"}
        out_json = str(config.GHIDRA_DIR / "decomp" / f"{self.sample_id}.json")
        Path(out_json).parent.mkdir(parents=True, exist_ok=True)
        r = decompile_with_ghidra(path, out_json)
        if r.get("ok"):
            funcs = load_decompile(out_json)
            maxf = int(p.get("max_functions", 200))
            return {"ok": True, "path": out_json, "function_count": len(funcs),
                    "functions": [{"addr": k, "name": v.get("name"), "signature": v.get("signature"),
                                   "c": v.get("c", "")[:4000]} for k, v in funcs.items()][:maxf]}
        return {"ok": False, "message": r.get("message", ""), "log_tail": r.get("log_tail", "")}

    def _stage_dynamic(self, path: str) -> dict:
        p = self._params("dynamic")
        timeout = int(p.get("timeout", 60))
        pcap_path = str(config.CAPTURES_DIR / f"{self.sample_id}.pcap")
        net = {}
        if not config.USE_SANDBOX_VM and not config.ALLOW_HOST_EXECUTION:
            return {
                "sandbox": "blocked", "executed": False, "network": net,
                "execution_status": "blocked_by_policy",
                "message": "Host execution is disabled; configure VMware or explicitly enable it in an isolated lab.",
            }
        import subprocess as sp
        try:
            need_admin = sp.run(["pktmon", "list"], capture_output=True).returncode != 0
        except (FileNotFoundError, sp.TimeoutExpired):
            # pktmon is a Windows optional capability. The sample can still
            # run when it is unavailable; the result will report no capture.
            need_admin = True
        monitor = sandbox_svc.BehaviorMonitor(watch_dirs=[str(Path(path).parent)])
        sb = sandbox_svc.create_sandbox()
        if isinstance(sb, sandbox_svc.VMSandbox):
            run = sb.run_and_capture(path, str(config.UNPACKED_DIR),
                                     config.SANDBOX_RUN_ARGS, timeout=timeout)
            return {"sandbox": "vmware", "run": run, "network": net,
                    "error": "" if run.get("ok") else run.get("error", "")}
        capture = pcap_svc.start_capture_session(pcap_path) if not need_admin else None
        run = sb.run(path, config.SANDBOX_RUN_ARGS)
        if capture:
            capture_result = pcap_svc.finish_capture_session(capture)
            if capture_result.get("ok"):
                net = capture_result
                run["behavior"]["dns"] = net.get("dns_queries", [])
            else:
                net = capture_result
        return {"sandbox": "local", "run": run, "network": net,
                "pcap_path": pcap_path if net.get("ok") else "",
                "admin_required": need_admin}

    def _stage_report(self, sample: Sample, results: dict) -> dict:
        p = self._params("report")
        sample_info = {
            "file_name": sample.file_name, "file_size": sample.file_size,
            "sha256": sample.sha256, "md5": sample.md5, "imphash": sample.imphash,
        }
        rep = report_svc.build_report(sample_info, results)
        paths = report_svc.save_report(rep, config.REPORTS_DIR, sample.file_name)
        return {"paths": paths}

    # ------------------------------------------------------------ orchestrator
    def run(self, resume: bool = True):
        sample = self._load_sample()
        if sample is None:
            return {"error": "sample not found"}
        path = sample.stored_path
        data = Path(path).read_bytes()
        results = {}
        if resume and sample.summary:
            results = sample.summary
            self.done = set(results.get("_stages", []))

        stages = [s["name"] for s in self.workflow.get("stages", [])
                  if s.get("enabled", True)]
        # 初始化状态节点(含禁用的标记为 skipped)
        _init_nodes(self.sample_id, self.workflow)

        try:
            for st in stages:
                if st in self.done and resume:
                    continue
                started = datetime.utcnow()
                started_iso = started.isoformat() + "Z"
                self._mark(st, "analyzing")
                self._update_status_node(st, "running", started=started_iso)
                try:
                    if st == "identify":
                        r = self._stage_identify(data, path)
                        self._apply_identify(r)
                        results["hashes"] = r["hashes"]
                        results["pe"] = r["pe"]
                        results["strings"] = r["strings"]
                    elif st == "unpack":
                        r = self._stage_unpack(data, path, results.get("pe", {}))
                        if r.get("unpacked_analysis"):
                            results["unpacked"] = r["unpacked_analysis"]
                        results["packer"] = {"verdict": r["verdict"],
                                             "unpacked_path": (r.get("unpacked") or {}).get("path", "")}
                    elif st == "disassemble":
                        results["disassembly"] = self._stage_disassemble(data, results.get("pe", {}))
                    elif st == "decompile":
                        results["decompile"] = self._stage_decompile(path)
                    elif st == "dynamic":
                        results["dynamic"] = self._stage_dynamic(path)
                        results["network"] = results["dynamic"].get("network", {})
                        results["behavior"] = (results["dynamic"].get("run") or {}).get("behavior", {})
                        if results["dynamic"].get("pcap_path"):
                            db = SessionLocal()
                            try:
                                s2 = db.query(Sample).filter(Sample.id == self.sample_id).first()
                                if s2:
                                    s2.pcap_path = results["dynamic"]["pcap_path"]
                                    db.commit()
                            finally:
                                db.close()
                    elif st == "report":
                        r = self._stage_report(sample, results)
                        results["report"] = r
                        db = SessionLocal()
                        try:
                            s2 = db.query(Sample).filter(Sample.id == self.sample_id).first()
                            s2.report_path = (r["paths"] or {}).get("html", "")
                            db.commit()
                        finally:
                            db.close()
                    self.done.add(st)
                    results["_stages"] = list(self.done)
                    self._record(st, "revlab-pipeline", True, {}, started=started)
                    self._update_status_node(st, "done",
                                             started=started_iso,
                                             finished=datetime.utcnow().isoformat() + "Z")
                except Exception as se:
                    log.exception("stage %s failed", st)
                    self._record(st, "revlab-pipeline", False, {}, str(se), started=started)
                    self._update_status_node(st, "error", started=started_iso,
                                             finished=datetime.utcnow().isoformat() + "Z",
                                             error=str(se))
                    raise
                # 中间结果持久化(断点续跑),保留可视化状态节点
                db = SessionLocal()
                try:
                    s3 = db.query(Sample).filter(Sample.id == self.sample_id).first()
                    merged = copy.deepcopy(dict(results))
                    cur = s3.summary or {}
                    if cur.get("_pipeline_status"):
                        merged["_pipeline_status"] = copy.deepcopy(cur["_pipeline_status"])
                    s3.summary = merged
                    db.commit()
                finally:
                    db.close()
                log.info("stage %s done for sample %s", st, self.sample_id)
        except Exception as e:
            failed_stage = locals().get("st", sample.stage or "unknown")
            self._mark(failed_stage, "error", error=f"{e}\n{traceback.format_exc()}")
            return {"ok": False, "error": str(e), "stage": failed_stage}

        self._mark("report", "analyzed")
        db = SessionLocal()
        try:
            s4 = db.query(Sample).filter(Sample.id == self.sample_id).first()
            final_summary = dict(s4.summary or {})
            final_summary.pop("_stages", None)
            s4.summary = final_summary
            s4.workflow_name = self.workflow.get("name", "full-auto")
            db.commit()
        finally:
            db.close()
        return {"ok": True, "stages": list(self.done), "report": results.get("report")}

    def _apply_identify(self, r: dict):
        db = SessionLocal()
        try:
            s = db.query(Sample).filter(Sample.id == self.sample_id).first()
            for k, v in r["hashes"].items():
                if k in ("md5", "sha1", "sha256", "imphash", "ssdeep", "size"):
                    if k == "size":
                        s.file_size = v
                    else:
                        setattr(s, k, v)
            s.machine = (r["pe"] or {}).get("machine")
            s.arch = "x64" if (r["pe"] or {}).get("is_64bit") else "x86"
            s.is_pe = int((r["pe"] or {}).get("is_pe", 0))
            s.subsystem = (r["pe"] or {}).get("subsystem")
            s.entry_point = (r["pe"] or {}).get("entry_point")
            s.image_base = (r["pe"] or {}).get("image_base")
            s.packer_hits = ((r["pe"] or {}).get("packer") or {}).get("hits", [])
            s.packer_verdict = ((r["pe"] or {}).get("packer") or {}).get("verdict", "")
            db.commit()
        finally:
            db.close()


def _init_nodes(sample_id: int, workflow: dict):
    """初始化状态节点:工作流所有阶段,禁用的标 skipped。"""
    db = SessionLocal()
    try:
        s = db.query(Sample).filter(Sample.id == sample_id).first()
        summary = copy.deepcopy(s.summary or {})
        nodes = summary.get("_pipeline_status", [])
        for st in workflow.get("stages", []):
            node = next((n for n in nodes if n["name"] == st["name"]), None)
            if node is None:
                nodes.append({"name": st["name"], "title": STAGE_TITLES.get(st["name"], st["name"]),
                              "status": "skipped" if not st.get("enabled", True) else "pending",
                              "started": None, "finished": None, "duration": 0, "error": ""})
        order = {n: i for i, n in enumerate(DEFAULT_STAGES)}
        nodes.sort(key=lambda x: order.get(x["name"], 99))
        summary["_pipeline_status"] = nodes
        s.summary = summary
        db.commit()
    finally:
        db.close()


def analyze_in_background(sample_id: int, workflow: dict = None):
    def _run():
        Runner(sample_id, workflow=workflow).run(resume=True)
    import threading
    t = threading.Thread(target=_run, daemon=True)
    t.start()
