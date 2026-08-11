"""字符串提取:ASCII/Unicode,可配置最小长度与过滤"""
import re

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % 6)

# 常见噪声字符串
_NOISE = {
    "", ".text", ".data", ".rdata", ".bss", ".rsrc", ".pdata", ".reloc", ".idata",
    ".tls", ".xdata", ".edata", "Rich", "UPX0", "UPX1", "UPX!", "MZ", "PE\0\0",
    "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "VirtualAlloc", "VirtualFree",
    "VirtualProtect", "ExitProcess", "GetModuleHandleA", "GetModuleHandleW",
}


def extract_strings(data: bytes, min_len: int = 6, unicode: bool = True,
                    ascii_: bool = True, filter_noise: bool = True) -> list:
    """提取字符串。返回 [{type:'ascii'|'unicode', offset, value}]"""
    out = []
    if ascii_:
        for m in _ASCII_RE.finditer(data):
            s = m.group(0).decode("latin-1")
            if len(s) >= min_len and not (filter_noise and s in _NOISE):
                out.append({"type": "ascii", "offset": m.start(), "value": s})
    if unicode:
        u_re = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
        for m in u_re.finditer(data):
            raw = m.group(0)
            s = raw.decode("utf-16-le", errors="ignore")
            if len(s) >= min_len and not (filter_noise and s in _NOISE):
                out.append({"type": "unicode", "offset": m.start(), "value": s})
    return out


def interesting_strings(strings: list, keywords: tuple = ("http", "https", "cmd", "powershell",
                          "regsvr", "shell", "download", "upload", "encrypt", "decrypt",
                          "password", "passwd", "key", "token", "api", ".dll", ".exe", ".pdb",
                          "user", "admin", "socket", "connect", "CreateProcess", "WScript",
                          "url", "wininet", "winhttp", "Temp", "AppData", "SOFTWARE",
                          "\\\\", "runas", " -")):
    return [s for s in strings if any(k.lower() in s["value"].lower() for k in keywords)]


def pdb_hint(strings: list) -> str:
    for s in strings:
        if s["value"].endswith(".pdb"):
            return s["value"]
    return ""
