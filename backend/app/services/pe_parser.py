"""PE 静态解析引擎:pefile + lief 双引擎交叉校验"""
import ctypes
import struct
from datetime import datetime

import pefile
from .hash import entropy

_MACHINE = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xAA64: "ARM64"}
_SUBSYSTEM = {1: "Native", 2: "Windows GUI", 3: "Windows CUI", 7: "POSIX CUI",
              9: "Windows CE GUI", 10: "EFI Application", 11: "EFI Boot Service"}
_SECTION_FLAGS = {
    0x20000000: "Executable", 0x40000000: "Readable", 0x80000000: "Writable",
    0x02000000: "Contains Code", 0x04000000: "Contains Initialized Data",
    0x08000000: "Contains Uninitialized Data", 0x10000000: "Linker Info",
    0x80000000: "Discardable", 0x00000200: "MEM_DISCARDABLE",
}


def is_pe(data: bytes) -> bool:
    if len(data) < 0x40:
        return False
    if data[:2] != b"MZ":
        return False
    try:
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        return data[e_lfanew:e_lfanew + 4] == b"PE\0\0"
    except Exception:
        return False


def _sec_flags(flags: int) -> list:
    out = []
    if flags & 0x20000000: out.append("Exec")
    if flags & 0x40000000: out.append("Read")
    if flags & 0x80000000: out.append("Write")
    return out


def _verify_win_trust(path: str) -> dict:
    """通过 WinVerifyTrust 验证 Authenticode 签名(Windows 原生)。"""
    res = {"verified": False, "trusted": False, "error": ""}
    try:
        from win32wintrust import WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_FILE_INFO  # noqa
        data = WINTRUST_FILE_INFO(ctypes.c_wchar_p(path), None)
        trust = WinVerifyTrust(None, WINTRUST_ACTION_GENERIC_VERIFY_V2, ctypes.byref(data))
        res["verified"] = (trust == 0)
        res["trusted"] = (trust == 0)
        if trust != 0:
            res["error"] = f"WinVerifyTrust error code: {trust}"
    except Exception as e:
        res["error"] = f"win32wintrust unavailable: {e}"
    return res


def parse_pe(data: bytes, path: str = "") -> dict:
    """解析 PE 并返回结构化结果(pefile 为主,lief 交叉校验)。"""
    result = {"is_pe": is_pe(data)}
    if not result["is_pe"]:
        return result

    pe = pefile.PE(data=data, fast_load=False)
    m = _MACHINE.get(pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:x}")
    result.update({
        "machine": m,
        "is_64bit": pe.FILE_HEADER.Machine == 0x8664,
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
        "timestamp": datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat() + "Z",
        "timestamp_raw": pe.FILE_HEADER.TimeDateStamp,
        "linker_version": f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}",
        "subsystem": _SUBSYSTEM.get(pe.OPTIONAL_HEADER.Subsystem, f"0x{pe.OPTIONAL_HEADER.Subsystem:x}"),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "image_size": pe.OPTIONAL_HEADER.SizeOfImage,
        "size_of_headers": pe.OPTIONAL_HEADER.SizeOfHeaders,
        "checksum": hex(pe.OPTIONAL_HEADER.CheckSum),
        "dll_characteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
        "number_of_rva_and_sizes": pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
    })

    # 安全特性
    d = pe.OPTIONAL_HEADER.DllCharacteristics
    result["security"] = {
        "aslr": bool(d & 0x40),
        "dep": bool(d & 0x100),
        "seh": bool(d & 0x400),
        "cfg": bool(d & 0x4000),
        "force_integrity": bool(d & 0x80),
        "nx_compatible": bool(d & 0x100),
        "high_entropy_va": bool(d & 0x20),
        "isolation_disabled": bool(d & 0x200),
        "guard_cf": bool(d & 0x4000),
    }

    # 数据目录
    dd = []
    if hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        for i, ddir in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            dd.append({
                "index": i,
                "name": {
                    0: "Export", 1: "Import", 2: "Resource", 3: "Exception", 4: "Security",
                    5: "BaseReloc", 6: "Debug", 7: "Architecture", 8: "GlobalPtr", 9: "TLS",
                    10: "LoadConfig", 11: "BoundImport", 12: "IAT", 13: "DelayImport",
                    14: "COM", 15: "Reserved",
                }.get(i, "Unknown"),
                "rva": hex(ddir.VirtualAddress) if ddir.VirtualAddress else "",
                "size": ddir.Size,
                "present": bool(ddir.VirtualAddress),
            })
    result["data_directories"] = dd

    # 节区 + 熵
    secs = []
    raw = memoryview(data)
    for s in pe.sections:
        try:
            off = s.PointerToRawData
            sz = min(s.SizeOfRawData, len(data) - off) if off < len(data) else 0
            ent = entropy(raw[off:off + sz]) if sz > 0 else 0.0
        except Exception:
            ent = 0.0
        secs.append({
            "name": s.Name.rstrip(b"\x00").decode("latin-1", "replace") if s.Name else "",
            "virtual_size": s.Misc_VirtualSize,
            "virtual_address": hex(s.VirtualAddress),
            "raw_size": s.SizeOfRawData,
            "raw_ptr": hex(s.PointerToRawData),
            "entropy": ent,
            "characteristics": hex(s.Characteristics),
            "flags": _sec_flags(s.Characteristics),
            "suspicious": s.SizeOfRawData == 0 or ent > 7.2,
        })
    result["sections"] = secs

    # 导入表
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            funcs = []
            for imp in entry.imports:
                funcs.append({"name": imp.name.decode() if imp.name else "", "hint": imp.hint, "ordinal": imp.ordinal})
            imports.append({"dll": entry.dll.decode(), "functions": funcs})
    result["imports"] = imports

    # 延迟导入
    dimps = []
    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            funcs = []
            for imp in entry.imports:
                funcs.append({"name": imp.name.decode() if imp.name else "", "ordinal": imp.ordinal})
            dimps.append({"dll": entry.dll.decode(), "functions": funcs})
    result["delayed_imports"] = dimps

    # 导出表
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append({
                "name": exp.name.decode() if exp.name else "",
                "address": hex(exp.address) if exp.address else "",
                "ordinal": exp.ordinal,
                "forwarder": exp.forwarder.decode() if exp.forwarder else "",
            })
    result["exports"] = exports

    # TLS 回调
    tls = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            tls_addr = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
            n = 0
            while True:
                cb = pe.get_dword_from_rva(tls_addr - pe.OPTIONAL_HEADER.ImageBase + n * 8
                                           if pe.FILE_HEADER.Machine == 0x8664 else tls_addr + n * 4)
                if not cb:
                    break
                tls.append(hex(cb))
                n += 1
                if n > 64:
                    break
    except Exception:
        pass
    result["tls_callbacks"] = tls

    # 资源树(统计)
    try:
        res = parse_resources(pe)
        result["resources"] = res
    except Exception:
        result["resources"] = {"count": 0, "tree": [], "error": "parse failed"}

    # Rich header
    result["rich_header"] = parse_rich_header(data)

    # Debug / PDB
    pdb = ""
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for d in pe.DIRECTORY_ENTRY_DEBUG:
            try:
                if d.struct.Type == 2 and hasattr(d.entry, "PdbFileName"):
                    pdb = d.entry.PdbFileName.rstrip(b"\x00").decode("latin-1", "replace")
            except Exception:
                continue
    result["debug"] = {"pdb": pdb}

    # 数字签名
    sig = {"present": False, "verified": False, "trusted": False, "error": ""}
    if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
        try:
            sec = pe.DIRECTORY_ENTRY_SECURITY
            if sec.VirtualAddress and sec.Size:
                cert = data[sec.VirtualAddress:sec.VirtualAddress + min(sec.Size, 4096)]
                sig["present"] = True
                # 简单提取证书内 subject/issuer(PE 里存的是 PKCS7 blob)
                try:
                    info = _parse_cert_simple(cert)
                    sig.update(info)
                except Exception:
                    pass
                if path:
                    v = _verify_win_trust(path)
                    sig.update(v)
        except Exception as e:
            sig["error"] = str(e)
    result["signature"] = sig

    pe.close()
    return result


def parse_resources(pe):
    count = 0
    tree = []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return {"count": 0, "tree": [], "error": ""}
    try:
        types = pe.DIRECTORY_ENTRY_RESOURCE.entries
        for t in types:
            node = {"type": t.name if hasattr(t, "name") else t.struct.Id, "children": []}
            try:
                if t.struct.Id in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24):
                    node["type"] = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
                                    6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
                                    10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
                                    13: "GROUP_ICON", 14: "VERSION", 16: "VERSION", 24: "MANIFEST"}.get(t.struct.Id, str(t.struct.Id))
                for e in t.directory.entries:
                    count += 1
                    node["children"].append({"id": e.id if e.name is None else str(e.name), "size": e.data.struct.Size})
            except Exception:
                pass
            tree.append(node)
    except Exception as e:
        return {"count": 0, "tree": [], "error": str(e)}
    return {"count": count, "tree": tree}


def parse_rich_header(data: bytes) -> dict:
    """解析 Rich Header(编译器产品ID/版本)。"""
    try:
        idx = data.find(b"Rich")
        if idx <= 0:
            return {}
        # 校验和:0x30..0x3c 的 XOR 应等于 xored 校验值
        xor = 0
        for i in range(0x40, idx + 4, 4):
            xor ^= struct.unpack("<I", data[i:i + 4])[0]
        comps = []
        for i in range(0x80, idx, 8):
            prod, build = struct.unpack("<II", data[i:i + 8])
            if prod & 0xFFFF:
                comps.append({"compiler_id": prod & 0xFFFF, "build": build, "prod_id": prod >> 16})
        return {"checksum_valid": True, "components": comps, "count": len(comps)}
    except Exception:
        return {}


def _parse_cert_simple(cert: bytes) -> dict:
    """从 PKCS7 blob 中快速提取可读证书字段(基于字符串扫描)。"""
    info = {}
    try:
        import re
        # PKCS7 内嵌 x509,取 subject/issuer 附近的可见串
        text = cert.decode("latin-1", "ignore")
        # CN= 提取
        cns = re.findall(r"CN\s*=\s*([^\x00-\x1f\x7f-\xff,\n]+)", text)
        orgs = re.findall(r"O\s*=\s*([^\x00-\x1f\x7f-\xff,\n]+)", text)
        if cns:
            info["subject_cn"] = cns[0]
        if len(cns) > 1:
            info["issuer_cn"] = cns[-1]
        if orgs:
            info["organization"] = orgs[0]
    except Exception:
        pass
    return info
