"""壳/加密封装检测:节区特征 + 导入表异常 + 入口特征 + 熵"""

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


def detect_packer(pe_result: dict, pe=None, data: bytes = b"") -> dict:
    """返回 {verdict, hits:[{name, reason}], suspicious_imports, confidence}"""
    hits = []
    names = []

    # 1. 节区名
    for sec in pe_result.get("sections", []):
        sname = sec["name"].lower()
        for pat, pname in _SECTION_PATTERNS:
            if sname in pat:
                hits.append({"name": pname, "reason": f"section name '{sec['name']}'"})
                names.append(pname)

    # 2. 熵
    high = [s for s in pe_result.get("sections", []) if s.get("entropy", 0) > 7.0]
    if len(high) >= 2:
        hits.append({"name": "HighEntropy", "reason": f"{len(high)} sections with entropy > 7.0 (compressed/encrypted code)"})

    # 3. 导入表异常
    imports = pe_result.get("imports", [])
    all_funcs = {f["name"].lower() for imp in imports for f in imp.get("functions", [])}
    only_suspect = bool(all_funcs) and all(fn in _SUSPECT_APIS for fn in all_funcs)
    # 仅有少数 DLL 且函数都是 getprocaddress/loadlibrary 类
    tiny_import = len(imports) <= 3 and only_suspect
    if tiny_import and not pe_result.get("is_dotnet"):
        hits.append({"name": "SuspiciousImport", "reason": "imports limited to LoadLibrary/GetProcAddress pattern (typical packer stub)"})

    # 4. 签名字符串
    if data:
        low = data.lower()
        for sig, pname in _STRING_SIGS:
            if sig.lower().encode("latin-1", "ignore") in low:
                hits.append({"name": pname, "reason": f"signature string '{sig}'"})
                names.append(pname)

    # 去重
    seen = set()
    uniq = []
    for h in hits:
        if h["name"] not in seen:
            seen.add(h["name"])
            uniq.append(h)

    # 判定:优先级最高的已知壳
    order = ["VMProtect", "Themida", "Enigma Protector", "WinLicence", "Armadillo",
             "UPX", "ASPack", "PECompact", "MPRESS", "NsPack", "Petite", "Y0da Cryptor",
             "tELock", "Molebox", "kkrunchy", "PEBundle"]
    verdict = ""
    for o in order:
        if o in seen:
            verdict = o
            break
    if not verdict and uniq:
        verdict = "Packed/Protected (unknown)"
    if not uniq:
        verdict = "Not packed (likely)"

    confidence = min(100, len(uniq) * 25 + (30 if tiny_import else 0))
    return {"verdict": verdict, "hits": uniq, "confidence": confidence,
            "suspicious_imports": bool(tiny_import), "packed": bool(uniq)}
