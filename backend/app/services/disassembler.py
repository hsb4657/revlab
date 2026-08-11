"""反汇编引擎:Capstone x86/x64 + 交叉引用 + 函数识别"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64


def _cs(arch: str):
    return Cs(CS_ARCH_X86, CS_MODE_64 if arch == "x64" else CS_MODE_32)


def _machine_to_arch(machine: str) -> str:
    return "x64" if machine == "x64" else "x86"


def disassemble(data: bytes, base: int = 0, arch: str = "x64",
                start: int = 0, size: int = 0, max_insns: int = 100000,
                show_bytes: bool = True) -> dict:
    """反汇编字节区间。
    start/size 为相对 data 的偏移;base 为文件映像基址。
    """
    if size <= 0:
        size = len(data) - start
    code = data[start:start + size]
    md = _cs(arch)
    md.detail = False
    insns = []
    ep = None
    try:
        for i in md.disasm(code, base + start):
            insns.append({
                "address": i.address,
                "bytes": i.bytes.hex() if show_bytes else "",
                "mnemonic": i.mnemonic,
                "op_str": i.op_str,
            })
            if len(insns) >= max_insns:
                break
    except Exception:
        pass
    return {"arch": arch, "base": base, "count": len(insns), "insns": insns}


def disassemble_at(data: bytes, addr: int, image_base: int = 0, arch: str = "x64",
                   max_insns: int = 100000, sections: list = None) -> dict:
    """从虚拟地址 addr 开始反汇编(自动映射到文件偏移)。
    sections: pe_result 的节区列表,用于 RVA→文件偏移映射;缺省按 [image_base, len(data)] 平铺。
    """
    rva = addr - image_base
    off = _rva_to_offset(rva, data, sections)
    if off is None:
        return {"error": "address out of file bounds", "count": 0, "insns": []}
    return disassemble(data, base=image_base, arch=arch, start=off, max_insns=max_insns)


def _rva_to_offset(rva: int, data: bytes, sections: list = None) -> int:
    """RVA → 文件偏移。优先使用节区映射。"""
    if sections:
        for s in sections:
            va = int(s.get("virtual_address", "0x0"), 16)
            vsz = s.get("virtual_size", 0) or s.get("raw_size", 0)
            if va <= rva < va + max(vsz, 1):
                raw = int(s.get("raw_ptr", "0x0"), 16)
                rel = rva - va
                off = raw + rel
                return off if off < len(data) else None
    # 兜底:头区平铺
    if 0 <= rva < len(data):
        return rva
    return None


def compute_xrefs(insns: list) -> dict:
    """统计 call/jmp 目标,生成交叉引用图。"""
    calls, jmps, refs = [], [], {}
    for it in insns:
        m = it["mnemonic"]
        o = it["op_str"]
        target = None
        # 解析立即数目标:call 0x401000 / jmp 0x401000 / jz 0x401000
        parts = o.split(",")
        if parts and parts[0].strip().startswith("0x"):
            try:
                target = int(parts[0].strip(), 16)
            except ValueError:
                target = None
        if target is None:
            continue
        if m == "call":
            calls.append({"from": it["address"], "to": target})
            refs.setdefault(target, []).append({"from": it["address"], "type": "call"})
        elif m.startswith("j"):
            jmps.append({"from": it["address"], "to": target})
            refs.setdefault(target, []).append({"from": it["address"], "type": "jmp"})
    return {
        "calls": calls,
        "jmps": jmps,
        "xref_targets": {hex(k): v for k, v in sorted(refs.items())},
        "call_targets": sorted({c["to"] for c in calls}),
        "jmp_targets": sorted({j["to"] for j in jmps}),
    }


def find_functions(entry_points: list, call_targets: list, jmp_targets: list,
                   image_base: int = 0, section_start: int = 0, section_end: int = 0) -> list:
    """启发式函数识别:入口点 + call 目标 + 跳转目标,落在代码节内视为函数。"""
    funcs = set()
    for ep in entry_points:
        funcs.add(ep)
    lo, hi = (section_start, section_end) if section_end else (0, 0xFFFFFFFF)
    for t in call_targets:
        if (not lo or (lo <= t <= hi)) and not (image_base and t < image_base + 0x1000):
            funcs.add(t)
    for t in jmp_targets:
        if (not lo or (lo <= t <= hi)) and t >= image_base:
            funcs.add(t)
    return sorted(funcs)


def disassemble_entry(data: bytes, entry_rva: int, image_base: int, arch: str,
                      max_insns: int = 2000, sections: list = None) -> dict:
    """从入口点反汇编(用于快速预览)。"""
    off = _rva_to_offset(entry_rva, data, sections)
    if off is None:
        return {"count": 0, "insns": [], "error": "entry not mapped"}
    return disassemble(data, base=image_base, arch=arch, start=off,
                       size=len(data) - off, max_insns=max_insns)
