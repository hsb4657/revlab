"""PE 壳/保护检测与策略规划。

Detection is deliberately evidence-based.  A printable vendor string alone
is kept as a weak signal; section layout, import starvation and entry-point
anomalies are stronger signals.  The returned strategy matrix lets a graph
branch to a known unpacker, a memory-dump/PE-sieve path, IAT repair, or manual
review instead of assuming one packer.
"""

# 节区名特征
_SECTION_PATTERNS = [
    (("upx0", "upx1", "upx2", "upx!"), "UPX"),
    (("aspack", "adata", ".aspack"), "ASPack"),
    ((".pec1", ".pec2", ".pecompact"), "PECompact"),
    (("petite", ".petite"), "Petite"),
    ((".mpress1", ".mpress2", ".adata"), "MPRESS"),
    ((".packed", ".packit"), "PackIt"),
    (("nsp0", "nsp1", ".nsp"), "NsPack"),
    ((".enigma1", ".enigma2", ".enigma3"), "Enigma Protector"),
    (("thew1", "thew2", "thew3", ".themida"), "Themida"),
    ((".vmp0", ".vmp1", ".vmp2", ".vmp3", ".vmp4"), "VMProtect"),
    ((".winlice", ".winlice0", ".winlice1"), "WinLicence"),
    ((".kkrunchy",), "kkrunchy"),
    ((".svkp",), "SVKP"),
    ((".y0da", ".y0da1"), "Y0da Cryptor"),
    ((".mpress", ".mpress1", ".mpress2"), "MPRESS"),
    (("pebundle",), "PEBundle"),
    ((".obfusc",), "Obfuscator"),
    (("md5t",), "MD5 Protector"),
    ((".guard1", ".guard2", ".gdata", ".gmain", ".grdata"), "Armadillo"),
    ((".taz", ".tazr", ".tazx"), "tELock"),
    ((".nsp0", ".nsp1", ".nsp2"), "NsPack"),
    ((".adata", ".aspack", ".atext"), "ASPack"),
    ((".bind", ".bindc", ".bindc2"), "PE-Bundler"),
    ((".vprotect",), "VProtect"),
    ((".upx",), "UPX"),
]

# 导入表异常特征:加壳程序常只导入少数几个 API
_SUSPECT_APIS = {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
                 "getprocaddress", "virtualalloc", "virtualprotect", "virtualfree",
                 "virtualquery", "virtualqueryex", "exitprocess", "loadresource",
                 "findresource", "getmodulehandlea", "getmodulehandlew", "localfree"}

# 常见壳签名字符串
_STRING_SIGS = [
    ("UPX!", "UPX"),
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("ASPack", "ASPack"),
    ("PECompact", "PECompact"),
    ("PETITE", "Petite"),
    ("MPRESS", "MPRESS"),
    ("Enigma", "Enigma Protector"),
    ("Themida", "Themida"),
    ("VMProtect", "VMProtect"),
    ("WinLicence", "WinLicence"),
    ("yoda's", "Y0da Cryptor"),
    ("NsPack", "NsPack"),
    ("tElock", "tELock"),
    ("Armadillo", "Armadillo"),
    (".net", "Mixed .NET"),
    ("molebox", "Molebox"),
    ("Protection ID", "---"),
]

_KNOWN_UNPACKERS = {
    "UPX": "upx",
}

_PROTECTION_FAMILIES = {
    "VMProtect": "virtualization",
    "Themida": "virtualization",
    "Enigma Protector": "virtualization",
    "WinLicence": "virtualization",
    "ASPack": "compression",
    "PECompact": "compression",
    "Petite": "compression",
    "MPRESS": "compression",
    "NsPack": "compression",
    "UPX": "compression",
    "Armadillo": "protector",
    "tELock": "protector",
    "Molebox": "virtualization",
    "Obfuscator": "obfuscation",
    "Mixed .NET": "managed-protection",
}


def detect_packer(pe_result: dict, pe=None, data: bytes = b"") -> dict:
    """Return a multi-family protection matrix and an executable plan."""
    hits = []
    names = []

    # 1. 节区名
    for sec in pe_result.get("sections", []):
        sname = sec["name"].lower()
        for pat, pname in _SECTION_PATTERNS:
            if sname in pat:
                hits.append({"name": pname, "reason": f"section name '{sec['name']}'",
                             "source": "section_name", "evidence_strength": "strong",
                             "confidence": 90, "family": _PROTECTION_FAMILIES.get(pname, "unknown")})
                names.append(pname)

    # 2. 熵
    high = [s for s in pe_result.get("sections", []) if s.get("entropy", 0) > 7.0]
    if len(high) >= 2:
        hits.append({"name": "HighEntropy", "reason": f"{len(high)} sections with entropy > 7.0 (compressed/encrypted code)",
                     "source": "section_entropy", "evidence_strength": "supporting",
                     "confidence": min(85, 45 + len(high) * 8), "family": "compression-or-encryption"})

    # 3. 导入表异常
    imports = pe_result.get("imports", [])
    all_funcs = {f["name"].lower() for imp in imports for f in imp.get("functions", [])}
    only_suspect = bool(all_funcs) and all(fn in _SUSPECT_APIS for fn in all_funcs)
    # 仅有少数 DLL 且函数都是 getprocaddress/loadlibrary 类
    tiny_import = len(imports) <= 3 and only_suspect
    if tiny_import and not pe_result.get("is_dotnet"):
        hits.append({"name": "SuspiciousImport", "reason": "imports limited to LoadLibrary/GetProcAddress pattern (typical packer stub)",
                     "source": "import_table", "evidence_strength": "strong", "confidence": 85,
                     "family": "loader-stub"})

    # 4. 签名字符串
    if data:
        low = data.lower()
        for sig, pname in _STRING_SIGS:
            if sig.lower().encode("latin-1", "ignore") in low:
                # A dependency may contain a vendor name in a string table.
                # Keep it as weak evidence unless corroborated by sections or
                # import/entry-point signals.
                hits.append({"name": pname, "reason": f"signature string '{sig}'",
                             "source": "string", "evidence_strength": "weak",
                             "confidence": 25, "family": _PROTECTION_FAMILIES.get(pname, "unknown")})
                names.append(pname)

    # 去重
    seen = set()
    uniq = []
    for h in hits:
        if h["name"] not in seen:
            seen.add(h["name"])
            uniq.append(h)

    # Upgrade a weak string only when another signal supports the same family.
    strong_names = {h["name"] for h in hits if h.get("evidence_strength") == "strong"}
    for hit in hits:
        if hit.get("evidence_strength") == "weak" and hit.get("name") in strong_names:
            hit["evidence_strength"] = "corroborated"
            hit["confidence"] = max(hit.get("confidence", 25), 70)

    # 判定:优先级最高的已知壳
    order = ["VMProtect", "Themida", "Enigma Protector", "WinLicence", "Armadillo",
             "UPX", "ASPack", "PECompact", "MPRESS", "NsPack", "Petite", "Y0da Cryptor",
             "tELock", "Molebox", "kkrunchy", "PEBundle"]
    verdict = ""
    for o in order:
        if o in seen:
            verdict = o
            break
    if not verdict and any(h.get("evidence_strength") in ("strong", "corroborated") for h in uniq):
        verdict = "Packed/Protected (unknown)"
    if not verdict and uniq:
        verdict = "Protection signal only"
    if not uniq:
        verdict = "Not packed (likely)"

    families: dict[str, dict] = {}
    for hit in uniq:
        family = hit.get("family") or "unknown"
        row = families.setdefault(family, {"family": family, "signals": [], "confidence": 0, "strong": False})
        row["signals"].append(hit["name"])
        row["confidence"] = max(row["confidence"], int(hit.get("confidence", 0)))
        row["strong"] = row["strong"] or hit.get("evidence_strength") in ("strong", "corroborated")

    # Strategies are data, so the graph can branch without knowing every
    # vendor-specific unpacker in Python code.
    has_strong = any(h.get("evidence_strength") in ("strong", "corroborated") for h in uniq)
    known = next((name for name in order if name in seen and name in _KNOWN_UNPACKERS), "")
    strategies = [
        {"id": "known_unpacker", "label": "已知壳专用解包", "applicable": bool(known),
         "tool": _KNOWN_UNPACKERS.get(known, ""), "reason": f"匹配 {known}" if known else "没有可直接调用的专用解包器"},
        {"id": "memory_dump", "label": "内存转储并重建 PE", "applicable": has_strong or bool(uniq),
         "tool": "pe-sieve", "reason": "适用于未知壳、虚拟化保护或入口点已重写的样本"},
        {"id": "iat_repair", "label": "IAT/重定位修复后验证", "applicable": has_strong,
         "tool": "pe-sieve-or-manual", "reason": "验证导入表、入口点和节区映射"},
        {"id": "manual_review", "label": "人工/调试器复核", "applicable": bool(uniq),
         "tool": "ghidra-or-debugger", "reason": "保护信号不足以自动决定时保留证据"},
    ]
    confidence = min(100, max([int(h.get("confidence", 0)) for h in uniq] or [0]) + (10 if tiny_import else 0))
    packed = bool(has_strong)
    return {
        "verdict": verdict, "hits": uniq, "confidence": confidence,
        "suspicious_imports": bool(tiny_import), "packed": packed,
        "families": list(families.values()), "strategies": strategies,
        "known_unpacker": known, "requires_memory_dump": bool(has_strong or (uniq and not known)),
        "evidence_summary": {
            "strong": sum(1 for h in uniq if h.get("evidence_strength") in ("strong", "corroborated")),
            "supporting": sum(1 for h in uniq if h.get("evidence_strength") == "supporting"),
            "weak": sum(1 for h in uniq if h.get("evidence_strength") == "weak"),
        },
    }
