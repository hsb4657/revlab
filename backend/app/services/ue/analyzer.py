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
from .versions import (
    UE_VERSIONS,
    FNAME_DETAILS,
    UE_ENCRYPTION_SIGS,
    get_version,
    all_versions,
    get_version_layout,
    get_gobjects_layout_profiles,
    normalize_version,
    version_candidates,
)
from .signatures import all_signatures, signatures_for_version, scan_signature, load_custom_signatures
from .layout_analysis import (
    analyze_fname_algorithm,
    analyze_reflection_layouts,
    describe_global_candidate,
)
from .static_evidence import analyze_static_evidence


# A dumped PE has no live module base, object memory, or runtime name decoder.
# Keep the required follow-up evidence explicit so reports never imply that a
# static signature match was observed in a running process.
_RUNTIME_COLLECTION_PLAN = [
    {
        "id": "module_base",
        "item": "加载与 dump 相同构建的进程并记录模块基址",
        "evidence": "模块基址、映像范围和构建哈希",
        "acceptance": "基址和映像范围与样本架构/节区一致",
    },
    {
        "id": "three_majors",
        "item": "读取 GObjects/GNames(GNamePool)/GWorld/GEngine 候选地址",
        "evidence": "指针可读性、指向模块/堆的范围和对象数组头字段",
        "acceptance": "连续读取不越界，结构字段满足对应 UE 布局不变量",
    },
    {
        "id": "fname_decode",
        "item": "用候选 FName 算法解码至少两个已知名称",
        "evidence": "比较索引、块/条目地址、Info、宽字符位和解码文本",
        "acceptance": "多个已知名称稳定解码且索引边界一致",
    },
    {
        "id": "reflection_walk",
        "item": "遍历 UObject/UClass/UFunction/FProperty 反射链",
        "evidence": "对象类型、字段名、字段偏移、数组计数和父子关系",
        "acceptance": "链路可重复遍历，字段偏移与目标构建的运行时对象一致",
    },
    {
        "id": "decryption",
        "item": "在解密/混淆分支记录明文前后校验和与调用链",
        "evidence": "解密函数入口、输入输出缓冲区、密钥/轮次线索和校验结果",
        "acceptance": "明文结构可解析，且同一构建重复运行结果一致",
    },
]


def _runtime_validation_contract(observations: dict | None = None) -> dict:
    """Return the evidence boundary for dump-only analysis.

    ``runtime_observations`` is intentionally an input contract for a future
    instrumented collector.  The analyzer itself never launches the target.
    """
    observations = observations or {}
    supplied = bool(observations)
    return {
        "analysis_mode": "static_dump_plus_observations" if supplied else "static_dump_only",
        "execution_available": False,
        "requires_runtime_execution": True,
        "evidence_status": "provided" if supplied else "not_collected",
        "evidence_source": "external_runtime_observations" if supplied else "none",
        "reason": "Dump 文件只能提供静态字节和节区证据，不能观察进程内存、对象遍历或运行时解密。",
        "static_limitations": [
            "静态签名命中只能标记为 candidate，不能升级为 confirmed。",
            "GNames/GObjects/GWorld/GEngine 指针需要加载后范围和结构校验。",
            "FName 解码与反射字段偏移需要运行时对象/名称样本复核。",
            "检测到保护或加密信号时，解密状态保持 pending，直到记录运行时调用链和明文校验。",
        ],
        "collection_plan": list(_RUNTIME_COLLECTION_PLAN),
        "observations_supplied": sorted(str(key) for key in observations),
    }


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
    def __init__(self, path: str, version: str = "", data: bytes = None,
                 runtime_observations: dict | None = None):
        self.path = path
        self.data = data if data is not None else Path(path).read_bytes()
        self.pe = pe_parser.parse_pe(self.data, path)
        self.version = version
        self.runtime_observations = runtime_observations or {}
        self.result = {
            "engine_version": "", "engine_family": "", "detected_version": "",
            "version_method": "", "version_status": "unconfirmed", "ue_generation": "unknown",
            "version_candidates": [], "version_evidence": [],
            "fname": "", "fname_detail": None,
            "three_majors": {"gobjects": None, "gnames": None, "gworld": None, "gengine": None},
            "major_candidates": {"gobjects": [], "gnames": [], "gworld": [], "gengine": []},
            "signature_hits": [], "encryption": [], "suggestions": [],
            "fname_analysis": None, "reflection": None, "layout_profiles": [],
            "version_layout": None,
            "get_name_xor": None, "plaintext_candidates": {},
        }

    # ---------------------------------------------------------- 版本识别
    def detect_version(self) -> str:
        selected = normalize_version(self.version)
        if selected and get_version(selected):
            v = get_version(selected)
            self._apply_version(selected, v, method="user-selected", status="candidate")
            self.result["version_evidence"].append({
                "kind": "user_selected", "detail": f"Requested UE {selected} profile.",
            })
            return selected
        if selected.startswith("5."):
            # A future UE5 branch selected by the user still has a useful
            # modern-family candidate. It must not be mislabeled as a known
            # minor profile.
            self._apply_ue5_family_candidate(selected, method="user-selected-family")
            self.result["version_evidence"].append({
                "kind": "user_selected_unknown_minor", "detail": f"Requested UE {selected}; no exact profile is registered.",
            })
            return ""
        detected = self._detect_from_strings()
        if detected:
            self.result["detected_version"] = detected
        return detected

    def _apply_version(self, version: str, metadata: dict, *, method: str, status: str) -> None:
        """Apply a known minor profile while preserving candidate semantics."""
        self.result["engine_version"] = version
        self.result["engine_family"] = metadata.get("family", "")
        self.result["ue_generation"] = metadata.get("generation") or (
            "UE5" if version.startswith("5.") else "UE4" if version.startswith("4.") else "unknown"
        )
        self.result["version_method"] = method
        self.result["version_status"] = status
        self.result["version_candidates"] = [version]
        self.result["fname"] = metadata.get("fname", "")
        self.result["fname_detail"] = FNAME_DETAILS.get(self.result["fname"])
        self.result["version_layout"] = get_version_layout(version)

    def _apply_ue5_family_candidate(self, requested: str = "", *, method: str) -> None:
        """Expose every modern UE5 profile when no exact build branch is known."""
        self.result["engine_version"] = ""
        self.result["engine_family"] = "5.x"
        self.result["ue_generation"] = "UE5"
        self.result["version_method"] = method
        self.result["version_status"] = "family_candidate"
        self.result["version_candidates"] = version_candidates(requested, "5.x")
        self.result["fname"] = "pool"
        self.result["fname_detail"] = FNAME_DETAILS.get("pool")
        self.result["version_layout"] = {
            "version": requested or "5.x",
            "generation": "UE5",
            "candidate_profiles": list(self.result["version_candidates"]),
            "fname": get_version_layout("5.8").get("fname", {}),
            "gobjects": get_version_layout("5.8").get("gobjects", {}),
            "reflection": get_version_layout("5.8").get("reflection", {}),
            "validation_state": "candidate",
            "runtime_validation_required": True,
        }

    def _detect_from_strings(self) -> str:
        """Identify UE4/UE5 minor candidates from ASCII and UTF-16 strings.

        Engine strings are build hints, not proof of exact in-memory layout.
        A known branch remains ``candidate``; an unknown UE5 minor expands to
        all registered UE5 layout profiles for downstream scoring.
        """
        raw = self.data
        candidates: list[tuple[str, str, int]] = []
        patterns = (
            rb"(?:UE|UnrealEngine[\\/ _-]*)([45])(?:[._ -])(\d{1,2})(?:[._ -]\d+)?",
            rb"\+\+UE([45])\+(\d{1,2})(?:\+\d+)?",
        )
        for pattern in patterns:
            for match in re.finditer(pattern, raw, re.IGNORECASE):
                candidates.append((f"{match.group(1).decode()}.{match.group(2).decode()}", "ascii_string", match.start()))
        # Do not decode an entire multi-hundred-MB dump as UTF-16. Probe only
        # the bounded windows that begin with a UTF-16LE ``UE`` marker.
        utf16_marker = b"U\x00E\x00"
        probe_at = 0
        while len(candidates) < 96:
            marker_at = raw.find(utf16_marker, probe_at)
            if marker_at < 0:
                break
            window = raw[marker_at:marker_at + 96].decode("utf-16le", "ignore")
            for pattern in (
                r"UE([45])(?:[._ -])(\d{1,2})(?:[._ -]\d+)?",
                r"UE([45])\+(\d{1,2})(?:\+\d+)?",
            ):
                match = re.search(pattern, window, re.IGNORECASE)
                if match:
                    candidates.append((f"{match.group(1)}.{match.group(2)}", "utf16le_string", marker_at))
            probe_at = marker_at + len(utf16_marker)
        # A plain 5.8 string is intentionally lower-confidence because it can
        # occur in unrelated version data. It is retained only as a fallback.
        if not candidates:
            for match in re.finditer(rb"(?<![0-9])([45])\.(\d{1,2})(?:\.\d+)?(?![0-9])", raw):
                candidates.append((f"{match.group(1).decode()}.{match.group(2).decode()}", "ascii_plain_version", match.start()))

        unique: list[tuple[str, str, int]] = []
        seen: set[tuple[str, str]] = set()
        for candidate in candidates:
            dedupe_key = (candidate[0], candidate[1])
            if dedupe_key not in seen:
                seen.add(dedupe_key)
                unique.append(candidate)
        self.result["version_evidence"] = [
            {"kind": source, "version": value, "offset": offset, "validation_state": "candidate"}
            for value, source, offset in unique[:24]
        ]
        known = next((value for value, _, _ in unique if value in UE_VERSIONS), "")
        if known:
            metadata = UE_VERSIONS[known]
            self._apply_version(known, metadata, method="string-match", status="candidate")
            # _apply_version sets a concise primary candidate. Preserve all
            # string-observed values for the workflow UI and report.
            self.result["version_candidates"] = list(dict.fromkeys(value for value, _, _ in unique))
            self.result["suggestions"].append(f"从版本字符串识别到 UE {known}({metadata['engine']})，布局仍需运行时校验")
            return known
        ue5_seen = next((value for value, _, _ in unique if value.startswith("5.")), "")
        if ue5_seen:
            self._apply_ue5_family_candidate(ue5_seen, method="string-family")
            self.result["version_evidence"].append({
                "kind": "unknown_ue5_minor", "version": ue5_seen,
                "detail": "No exact registered profile; using UE5 family candidates.",
                "validation_state": "candidate",
            })
            self.result["suggestions"].append(f"识别到 UE {ue5_seen}，使用 UE5 通用候选布局并等待构建级验证")
            return ""
        # Family-level markers cover stripped builds which no longer retain a
        # parseable minor version string.
        lowered = raw.lower()
        if any(marker in lowered for marker in (b"ue5", b"unrealengine/5.", b"fnameentryid", b"fnamepool")):
            self._apply_ue5_family_candidate(method="family-marker")
            self.result["version_evidence"].append({"kind": "ue5_marker", "validation_state": "candidate"})
            self.result["suggestions"].append("仅识别到 UE5 家族标记，已展开 UE5.0–5.8 布局候选")
        elif any(marker in lowered for marker in (b"ue4", b"unrealengine/4.", b"tnameentryarray")):
            self.result["engine_family"] = "4.x"
            self.result["ue_generation"] = "UE4"
            self.result["version_method"] = "family-marker"
            self.result["version_status"] = "family_candidate"
            self.result["version_candidates"] = version_candidates(family="4.x")
            self.result["suggestions"].append("仅识别到 UE4 家族标记，建议选择精确版本以校正结构")
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
                    "status": "candidate",
                    "validation_state": "candidate",
                    "confidence": min(80, 45 + len(entry.get("versions", [])) * 3),
                    "score": min(80, 45 + len(entry.get("versions", [])) * 3),
                    "evidence_status": "static_candidate",
                    "evidence": [{
                        "kind": "static_signature",
                        "detail": entry["name"],
                        "match_offset": h["match"],
                        "match_va": va,
                    }],
                })
        return hits

    # ---------------------------------------------------------- 三大件
    def locate_three_majors(self) -> dict:
        # Scan all exact signatures. A title may retain an older access motif
        # even when its engine metadata identifies a newer minor release.
        sigs = all_signatures()
        hits = self._scan(sigs)
        self.result["signature_hits"] = hits
        groups = {"gobjects": [], "gnames": [], "gworld": [], "gengine": []}
        for h in hits:
            n = h["name"].lower()
            for k in groups:
                if n.startswith(k):
                    groups[k].append(h)
                    break
        labels = {
            "gobjects": "GObjects",
            "gnames": "GNames/FNamePool",
            "gworld": "GWorld",
            "gengine": "GEngine",
        }
        for k, cands in groups.items():
            if cands:
                cands.sort(key=lambda x: -len(x.get("versions", [])))
                normalized = [describe_global_candidate(candidate, labels[k]) for candidate in cands]
                self.result["major_candidates"][k] = normalized
                self.result["three_majors"][k] = normalized[0]
            else:
                self.result["major_candidates"][k] = []
                self.result["three_majors"][k] = describe_global_candidate(None, labels[k])
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
        static_getname = (self.result.get("static_evidence") or {}).get("getname") or {}
        if static_getname.get("xor_candidate"):
            det.append({
                "name": "GetNameXOR",
                "detail": "GetName/FName 标记与可疑 XOR 指令共存；这是静态候选，不等于已得到密钥或明文",
                "risk": "medium",
                "validation_state": "candidate",
                "evidence": static_getname.get("xor_hits", [])[:24],
            })
            needs_dec = True
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
            det.append({"name": "PackedSections", "detail": f"高熵节区: {', '.join(s['name'] for s in high)},需要保护/压缩复核；不能单凭熵值判定已加密", "risk": "medium", "validation_state": "candidate"})
        # 复用壳检测
        from ..packer import detect_packer
        pk = detect_packer(self.pe, None, self.data)
        for h in pk.get("hits", []):
            det.append({"name": h["name"], "detail": h["reason"],
                        "risk": "high" if h["name"] in ("VMProtect", "Themida", "Enigma Protector", "WinLicence") else "medium"})
            if h["name"] in ("VMProtect", "Themida", "Enigma Protector", "WinLicence") and h.get("evidence_strength") == "strong":
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
        # A dump often retains engine strings while the original signature
        # used by a particular dumper has changed.  Keep a second, explainable
        # evidence pass so missing GNames/GEngine signatures become ranked
        # candidates instead of an empty result.  These are still static
        # candidates; only a live object/name walk can promote them.
        self.result["static_evidence"] = analyze_static_evidence(self.data, self.pe)
        static = self.result["static_evidence"]
        if not self.result.get("engine_family") and static.get("engine_family_guess") not in (None, "unknown"):
            self.result["engine_family"] = static["engine_family_guess"]
            self.result["version_method"] = self.result.get("version_method") or "static-marker-family"
        if not self.result.get("fname") and static.get("marker_hits", {}).get("fname"):
            # UE4.23+ name-pool is the most useful default for modern dumps;
            # retain the direct-array candidate in fname_analysis as a second
            # model rather than silently discarding it.
            self.result["fname"] = "pool"
        if not self.result.get("version_layout"):
            selected_version = self.result.get("engine_version") or self.result.get("detected_version") or ""
            self.result["version_layout"] = get_version_layout(selected_version) if selected_version else None
        fallback_groups = static.get("global_candidates", {}) or {}
        xref_groups = static.get("string_xref_globals", {}) or {}
        labels = {
            "gobjects": "GObjects",
            "gnames": "GNames/FNamePool",
            "gworld": "GWorld",
            "gengine": "GEngine",
        }
        for role_index, (key, label) in enumerate(labels.items()):
            current = self.result.get("three_majors", {}).get(key) or {}
            candidates = list(self.result.get("major_candidates", {}).get(key) or [])
            fallback = list(fallback_groups.get(key) or [])
            if fallback:
                # Keep the original signature hits first, then append the
                # string/RIP-relative candidates with their source intact.
                existing_keys = {(item.get("target_va"), item.get("match_offset")) for item in candidates}
                candidates.extend(
                    describe_global_candidate(item, label)
                    for item in fallback
                    if (item.get("target_va"), item.get("match_offset")) not in existing_keys
                )
            self.result["major_candidates"][key] = candidates[:96]
            if current.get("target_va") is None:
                # 没有签名命中时,检查字符串交叉引用结果(高置信度)
                xref_cands = xref_groups.get(key, [])
                best_xref = next((c for c in xref_cands if c.get("confidence", 0) >= 55), None)
                if best_xref:
                    # 字符串 xref 找到了高置信度候选,使用它
                    selected = describe_global_candidate(best_xref, label)
                    selected["status"] = "candidate"
                    selected["validation_state"] = "candidate"
                    selected["source"] = "string_cross_reference"
                    self.result["three_majors"][key] = selected
                else:
                    unresolved = describe_global_candidate(None, label)
                    unresolved["status"] = "not_located"
                    unresolved["validation_state"] = "unconfirmed"
                    unresolved["reason"] = (
                        "No role-specific exact signature matched. Generic RIP candidates "
                        "are listed separately and are not accepted as a base offset."
                    )
                    self.result["three_majors"][key] = unresolved
            else:
                self.result["three_majors"][key].setdefault("ambiguity", False)
        self.result["static_evidence"]["selected_globals"] = {
            key: self.result["three_majors"].get(key) for key in labels
        }
        self.result["string_xref_globals"] = xref_groups
        self.encryption_analysis()
        # Keep FName, reflection, and field layouts as separate evidence-
        # bearing contracts. Static values remain candidates until a runtime
        # validator observes the pointed-to memory and decoded names.
        self.result["fname_analysis"] = analyze_fname_algorithm(
            self.data,
            engine_version=self.result.get("engine_version", ""),
            engine_family=self.result.get("engine_family", ""),
            fname_model=self.result.get("fname", ""),
            gnames=self.result["three_majors"].get("gnames"),
            runtime_observations=self.runtime_observations,
        )
        self.result["reflection"] = analyze_reflection_layouts(
            self.data,
            engine_version=self.result.get("engine_version", ""),
            engine_family=self.result.get("engine_family", ""),
            fname_model=self.result.get("fname", ""),
            gnames=self.result["three_majors"].get("gnames"),
            runtime_observations=self.runtime_observations,
        )
        self.result["get_name_xor"] = self.result["fname_analysis"].get("get_name_xor", {})
        # The broad static pass catches stripped-symbol builds where the XOR
        # instruction is far from the retained GetName string.  Merge its
        # evidence without changing the stricter layout-level validation state.
        broad_getname = static.get("getname", {}) or {}
        narrow_getname = self.result["get_name_xor"] or {}
        if broad_getname.get("xor_candidate"):
            narrow_getname = dict(narrow_getname)
            narrow_getname["broad_static_scan"] = broad_getname
            narrow_getname["status"] = narrow_getname.get("status") or "candidate"
            narrow_getname["validation_state"] = narrow_getname.get("validation_state") or "candidate"
            narrow_getname["runtime_validation_required"] = True
            self.result["get_name_xor"] = narrow_getname
            self.result["fname_analysis"]["get_name_xor"] = narrow_getname
        self.result["plaintext_candidates"] = {}
        for key in ("gobjects", "gnames", "gworld", "gengine"):
            candidates = list((self.result.get("major_candidates") or {}).get(key) or [])
            values = [item.get("plaintext_candidate") for item in candidates if item.get("plaintext_candidate")]
            if not values:
                selected = (self.result.get("three_majors") or {}).get(key) or {}
                if selected.get("plaintext_candidate"):
                    values = [selected["plaintext_candidate"]]
            self.result["plaintext_candidates"][key] = values
        self.result["layout_profiles"] = self.result["reflection"].get("profile_candidates", [])
        self.result["decryption"] = {
            "required": bool(self.result.get("needs_decryption")),
            "status": "required_pending_validation" if self.result.get("needs_decryption") else "not_required",
            "signals": self.result.get("encryption", []),
            "runtime_evidence_required": True,
            "validation_plan": [
                "Confirm the candidate bytes in a loaded module or memory dump.",
                "Decode known FName entries and validate reflection pointer invariants.",
                "Record the build-specific result before promoting any candidate to confirmed.",
            ],
        }
        runtime_validation = _runtime_validation_contract(self.runtime_observations)
        self.result["runtime_validation"] = runtime_validation
        self.result["analysis_mode"] = runtime_validation["analysis_mode"]
        self.result["runtime_evidence_status"] = runtime_validation["evidence_status"]
        self.result["runtime_execution_available"] = runtime_validation["execution_available"]
        self.result["decryption"]["runtime_validation"] = runtime_validation
        self._build_summary()
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
            "validation_state": {
                key: (value or {}).get("validation_state", "unconfirmed")
                for key, value in tm.items()
            },
            "layout_profile_count": len(r.get("layout_profiles") or []),
            "field_offset_count": len((r.get("reflection") or {}).get("field_offset_candidates") or []),
            "version_layout": r.get("version_layout"),
            "three_major_scores": {
                key: (value or {}).get("score", 0)
                for key, value in tm.items()
            },
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
