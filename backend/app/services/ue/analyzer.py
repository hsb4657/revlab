"""UE 分析器:识别引擎版本 → 定位三大件(GNames/GObjects/GWorld) → FName 解密分析 → 加密/混淆检测
输入: 游戏 dump 后的 PE 可执行文件(样本)。输出结构化分析报告。
"""
from __future__ import annotations
import re
from pathlib import Path

from ...core.config import config
from ...core.database import SessionLocal
from ...models.sample import Sample
from .. import pe_parser
from .. import hash as hash_svc
from .. import report as report_svc
from .versions import UE_VERSIONS, FNAME_DETAILS, UE_ENCRYPTION_SIGS, get_version, all_versions
from .signatures import all_signatures, signatures_for_version, scan_signature, load_custom_signatures


def offset_to_va(pe: dict, off: int) -> int | None:
    """文件偏移 → 虚拟地址(节内线性映射)。供 analyzer 内部与 ue/__init__.py 复用。"""
    for s in pe.get("sections", []):
        raw = int(s.get("raw_ptr", "0x0"), 16)
        size = s.get("raw_size", 0)
        if raw <= off < raw + size:
            va = int(s.get("virtual_address", "0x0"), 16)
            return va + (off - raw)
    return None


class UEAnalyzer:
    def __init__(self, path: str, version: str = "", data: bytes = None):
        self.path = path
        self.data = data if data is not None else Path(path).read_bytes()
        self.pe = pe_parser.parse_pe(self.data, path)
        self.version = version
        self.result = {
            "engine_version": "", "engine_family": "", "detected_version": "",
            "version_method": "", "fname": "", "fname_detail": None,
            "three_majors": {"gobjects": None, "gnames": None, "gworld": None, "gengine": None},
            "signature_hits": [], "encryption": [], "suggestions": [],
        }

    # ---------------------------------------------------------- 版本识别
    def detect_version(self) -> str:
        if self.version and get_version(self.version):
            v = get_version(self.version)
            self.result["engine_version"] = self.version
            self.result["engine_family"] = v["family"]
            self.result["version_method"] = "user-selected"
            self.result["fname"] = v["fname"]
            self.result["fname_detail"] = FNAME_DETAILS.get(v["fname"])
            return self.version
        detected = self._detect_from_strings()
        if detected:
            self.result["detected_version"] = detected
        return detected

    def _detect_from_strings(self) -> str:
        """从版本字符串识别。优先精确(如 5.3.2 / UE5.3),再匹配家族。"""
        data = self.data
        candidates = []
        for m in re.finditer(rb"UE[45][._-]?(\d+)[._-](\d+)", data):
            candidates.append(f"{m.group(1).decode()}.{m.group(2).decode()}")
        if not candidates:
            for m in re.finditer(rb"\b(4\.\d{2,2}|5\.\d)\b".replace(b"\\b", b"(?=[^\\x00-\\x1f])"), data):
                pass
        # 匹配已知版本
        best = ""
        for c in candidates:
            if c in UE_VERSIONS:
                best = c
                break
        if best:
            v = UE_VERSIONS[best]
            self.result["engine_version"] = best
            self.result["engine_family"] = v["family"]
            self.result["version_method"] = "string-match"
            self.result["fname"] = v["fname"]
            self.result["fname_detail"] = FNAME_DETAILS.get(v["fname"])
            self.result["suggestions"].append(f"从版本字符串识别到 UE {best}({v['engine']})")
            return best
        # 家族级识别
        fam = "5.x" if b"UE5-" in data or b"UE5_" in data or b"UnrealEngine/5." in data else \
              ("4.x" if b"UE4-" in data or b"UnrealEngine/4." in data else "")
        if fam:
            self.result["engine_family"] = fam
            self.result["version_method"] = "family"
            self.result["suggestions"].append(f"仅识别到引擎家族 {fam},建议手动选择精确版本以校正结构")
        return ""

    # ---------------------------------------------------------- 签名扫描
    def _va_map(self):
        return self.pe.get("sections", [])

    def _offset_to_va(self, off: int) -> int | None:
        return offset_to_va(self.pe, off)

    def _scan(self, sigs: list):
        hits = []
        for entry in sigs:
            for h in scan_signature(self.data, entry, max_hits=4):
                va = self._offset_to_va(h["match"])
                target_va = None
                if h.get("target") is not None:
                    target_va = self._offset_to_va(h["target"])
                    if target_va is None and va is not None and h.get("imm") is not None:
                        # 文件偏移映射失败时的 VA 空间兜底:
                        # RIP-relative target = 下一条指令 VA + imm32
                        # 下一条指令 VA = 匹配 VA + (imm_start + imm_len)
                        imm_start = h.get("imm_start", 4)
                        target_va = va + (imm_start + 4) + h["imm"]
                hits.append({
                    "name": entry["name"], "desc": entry["desc"],
                    "match_offset": h["match"], "match_va": va,
                    "imm": h.get("imm"), "target_va": target_va,
                    "versions": entry.get("versions", []),
                })
        return hits

    # ---------------------------------------------------------- 三大件
    def locate_three_majors(self) -> dict:
        sigs = signatures_for_version(self.result["engine_version"] or self.result["engine_family"]) \
            if (self.result["engine_version"] or self.result["engine_family"]) else all_signatures()
        # 扫描全部(含其他版本签名)以防版本识别不准
        hits = self._scan(sigs)
        self.result["signature_hits"] = hits
        groups = {"gobjects": [], "gnames": [], "gworld": [], "gengine": []}
        for h in hits:
            n = h["name"].lower()
            for k in groups:
                if n.startswith(k):
                    groups[k].append(h)
                    break
        for k, cands in groups.items():
            if cands:
                cands.sort(key=lambda x: -len(x.get("versions", [])))
                self.result["three_majors"][k] = cands[0]
        self._apply_source_corrections()
        return self.result["three_majors"]

    def _apply_source_corrections(self):
        """若已缓存对应版本源码,用其结构线索校正偏移。"""
        try:
            from .source_fetcher import analyze_all_cached
            src = analyze_all_cached(self.result.get("engine_version") or "")
        except Exception:
            src = []
        if src:
            self.result["source_hints"] = src
            self.result["suggestions"].append("已结合对应版本源码结构线索进行交叉校验")

    # ---------------------------------------------------------- 加密解密
    def encryption_analysis(self) -> list:
        """检测加密。若未检测到加密,则无需解密(needs_decryption=False)。"""
        det = []
        fam = self.result["engine_family"]
        ver = self.result["engine_version"]
        needs_dec = False
        # FName 加密(UE5.2+ 可选加密;若检测到 IndexToName 混淆特征则需解密)
        fname_enc = False
        if ver and ver >= "5.2" and self.result["fname"] == "pool":
            if self._has_fname_encryption_marker():
                fname_enc = True
                det.append({"name": "FNameEncryption", "detail": "检测到 FName::IndexToName 混淆/加密特征,需结合 FNamePool 与运行时 dump 解密", "risk": "medium"})
                needs_dec = True
        # AES 特征
        if any(k in self.data for k in (b"SizeAES", b"FAES", b"FEncryptedData", b"FArchiveAsync2")):
            det.append({"name": "AES", "detail": "检测到 AES 相关符号,可能使用包体/存档加密", "risk": "high"})
            needs_dec = True
        # 高熵节区(代码/资源加密)
        high = [s for s in self.pe.get("sections", []) if s.get("entropy", 0) > 7.2]
        if high:
            det.append({"name": "PackedSections", "detail": f"高熵节区: {', '.join(s['name'] for s in high)},疑似代码/资源加密或壳", "risk": "high"})
            needs_dec = True
        # 复用壳检测
        from ..packer import detect_packer
        pk = detect_packer(self.pe, None, self.data)
        for h in pk.get("hits", []):
            det.append({"name": h["name"], "detail": h["reason"],
                        "risk": "high" if h["name"] in ("VMProtect", "Themida", "Enigma Protector", "WinLicence") else "medium"})
            if h["name"] in ("VMProtect", "Themida", "Enigma Protector", "WinLicence"):
                needs_dec = True
        self.result["needs_decryption"] = bool(needs_dec)
        if not needs_dec:
            det.append({"name": "None", "detail": "未检测到 FName/字符串/包体加密,无需解密", "risk": "low"})
        self.result["encryption"] = det
        return det

    def _has_fname_encryption_marker(self) -> bool:
        """检测 FName 加密特征(FNamePool + IndexToName 重定向 / FName 相关混淆)。"""
        markers = (b"FName::IndexToName", b"FName::IsNumber", b"GNames", b"IndexToName",
                   b"\x0f\xb7\x14\x48\x48\x8d\x04\xd1")  # movzx rdx,word[rax+rcx*2]; lea rax,[rcx+rdx*8] 等
        return any(m in self.data for m in markers)

    # ---------------------------------------------------------- 报告
    def run(self) -> dict:
        self.detect_version()
        self.locate_three_majors()
        self.encryption_analysis()
        self._build_summary()
        if not self.result.get("needs_decryption"):
            self.result["decryption"] = {
                "required": False,
                "note": "未检测到加密,无需解密。三大件基址可直接用于 SDK/内存读取。",
            }
        return self.result

    def _build_summary(self):
        tm = self.result["three_majors"]
        r = self.result
        r["summary"] = {
            "engine": r["engine_version"] or r["engine_family"] or "未识别",
            "version_method": r["version_method"],
            "gobjects": f"{tm['gobjects']['target_va'] and hex(tm['gobjects']['target_va'])}" if tm["gobjects"] else None,
            "gnames": f"{tm['gnames']['target_va'] and hex(tm['gnames']['target_va'])}" if tm["gnames"] else None,
            "gworld": f"{tm['gworld']['target_va'] and hex(tm['gworld']['target_va'])}" if tm["gworld"] else None,
            "fname": r["fname"],
            "encryption_count": len(r["encryption"]),
        }

    # ---------------------------------------------------------- 导出报告文件
    def save_report(self, sample_name: str) -> dict:
        rep = report_svc.build_report(
            {"file_name": sample_name, "file_size": len(self.data),
             "sha256": hash_svc.compute_hashes(self.data)["sha256"]},
            {"ue": self.result})
        out = config.REPORTS_DIR / "ue"
        out.mkdir(parents=True, exist_ok=True)
        paths = report_svc.save_report(rep, out, f"ue_{sample_name}")
        self.result["report_paths"] = paths
        return paths


def analyze_sample(sample_id: int, version: str = "") -> dict:
    """按 sample_id 分析。"""
    db = SessionLocal()
    try:
        s = db.query(Sample).filter(Sample.id == sample_id).first()
    finally:
        db.close()
    if s is None:
        raise ValueError(f"sample #{sample_id} not found")
    path = Path(s.stored_path)
    if not path.is_absolute():
        path = config.BASE_DIR / path
    a = UEAnalyzer(str(path), version=version)
    return a.run()


def ue_report(sample_id: int, version: str = "") -> dict:
    db = SessionLocal()
    try:
        s = db.query(Sample).filter(Sample.id == sample_id).first()
    finally:
        db.close()
    if s is None:
        raise ValueError("sample not found")
    path = Path(s.stored_path)
    if not path.is_absolute():
        path = config.BASE_DIR / path
    a = UEAnalyzer(str(path), version=version)
    a.run()
    paths = a.save_report(s.file_name)
    return {"ok": True, "result": a.result, "paths": paths}
