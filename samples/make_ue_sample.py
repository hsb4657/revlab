"""REVLab UE 虚幻引擎演示样本构造器(字节级)
生成合法 PE32 x86,注入:
  - UE 版本字符串:UnrealEngine/5.3、UE5-、5.3.2(相邻排布使自动识别命中 UE5.3)
  - 反射系统字符串:ProcessEvent/GetDefaultObject/UClass/UFunction/FProperty/UObject
  - 三大件特征签名(GObjects_UE5/GNames_Pool/GWorld_UE5)及其 RIP-relative 目标数据
用于 UE 引擎阶段式工作流(engine_runner)本地验证,无需联网。
用法: python samples/make_ue_sample.py <out.exe>
"""
import struct
import sys
from pathlib import Path


def u32(x):
    return struct.pack("<I", x & 0xFFFFFFFF)


def u16(x):
    return struct.pack("<H", x & 0xFFFF)


def align(n, a):
    return ((n + a - 1) // a) * a


def build():
    IMAGE_BASE = 0x400000
    SEC_ALIGN = 0x1000
    FILE_ALIGN = 0x200
    headers_size = align(0x400, FILE_ALIGN)  # DOS+NT+节区头预留
    text_rva = 0x1000
    rdata_rva = text_rva + SEC_ALIGN
    data_rva = rdata_rva + SEC_ALIGN
    text_raw_ptr = headers_size

    # ---------------- .text:入口代码 + 三大件特征签名 ----------------
    text = bytearray()
    text += bytes([0x55, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3])  # push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret
    text += b"\x90" * 0x20

    def add_sig(prefix, tail):
        """追加一条 RIP-relative 签名: prefix(3B) + disp(4B,占位) + tail。"""
        start = len(text)
        text.extend(prefix)                      # pattern 索引 0..2
        disp_pos = len(text)                     # pattern 索引 3..6(imm)
        text.extend(b"\x00" * 4)
        text.extend(tail)                        # pattern 索引 7..
        return start, disp_pos

    s1, d1 = add_sig(b"\x48\x8B\x05", b"\x48\x8B\x0C\xC8\x48\x8D\x04\xD1\x48\x89")  # GObjects_UE5
    text += b"\x90" * 0x10
    s2, d2 = add_sig(b"\x48\x8D\x05", b"\x0F\xB7\x14\x48")                          # GNames_Pool
    text += b"\x90" * 0x10
    s3, d3 = add_sig(b"\x48\x8B\x1D", b"\x48\x8B\x5D\xD0")                          # GWorld_UE5
    text_raw_size = align(len(text), FILE_ALIGN)

    # ---------------- .rdata:版本 + 反射字符串 ----------------
    rdata = bytearray()

    def put(s):
        rdata.extend(s + b"\x00")

    # 版本字符串(UE5- 与 5.3.2 相邻,形成 UE5-5.3.2 供正则命中 UE5.3)
    put(b"UnrealEngine/5.3")
    put(b"UE5-5.3.2")
    put(b"5.3.2")
    # 反射系统字符串
    put(b"ProcessEvent")
    put(b"GetDefaultObject")
    put(b"UClass")
    put(b"UFunction")
    put(b"FProperty")
    put(b"UObject")
    put(b"REVLab UE sample")
    rdata_raw_ptr = text_raw_ptr + text_raw_size
    rdata_raw_size = align(len(rdata), FILE_ALIGN)

    # ---------------- .data:三大件目标数据 ----------------
    data_raw_ptr = rdata_raw_ptr + rdata_raw_size
    data = bytearray()
    data += b"\x00" * 0x10
    gobjects_off = data_raw_ptr + len(data)   # GObjects(TUObjectArray) 基址
    data += (b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00") * 0x10
    data += b"\x00" * 0x40
    gnames_off = data_raw_ptr + len(data)     # FNamePool 基址
    data += u32(0x403000) + u32(0) + u32(0) + u32(0)
    data += b"\x00" * 0x20
    gworld_off = data_raw_ptr + len(data)     # GWorld 全局指针
    data += u32(0x403000) + u32(0)
    data += b"\x00" * 0x40
    data_raw_size = align(len(data), FILE_ALIGN)

    # ---------------- 回填 RIP-relative disp(下一条指令 = match + 7 = 文件头 + disp_pos + 4) ----------------
    def patch(disp_pos, target_off):
        next_instr = text_raw_ptr + disp_pos + 4
        imm = target_off - next_instr
        text[disp_pos:disp_pos + 4] = u32(imm)

    patch(d1, gobjects_off)
    patch(d2, gnames_off)
    patch(d3, gworld_off)

    # ---------------- PE 头 ----------------
    size_of_image = align(data_rva + max(len(data), data_raw_size), SEC_ALIGN)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = u32(0x40)  # e_lfanew

    nt = bytearray()
    nt += b"PE\x00\x00"
    # FILE_HEADER
    nt += u16(0x14C)          # i386
    nt += u16(3)              # NumberOfSections
    nt += u32(0x60000000)     # TimeDateStamp
    nt += u32(0)              # PointerToSymbolTable
    nt += u32(0)              # NumberOfSymbols
    nt += u16(0xE0)           # SizeOfOptionalHeader
    nt += u16(0x0103)         # Characteristics: EXECUTABLE|32BIT
    # OPTIONAL_HEADER (PE32)
    opt = bytearray()
    opt += u16(0x10B)         # Magic PE32
    opt += bytes([6, 0])      # linker 6.0
    opt += u32(text_raw_size)      # SizeOfCode
    opt += u32(rdata_raw_size + data_raw_size)  # SizeOfInitializedData
    opt += u32(0)             # SizeOfUninitializedData
    opt += u32(text_rva)      # AddressOfEntryPoint
    opt += u32(text_rva)      # BaseOfCode
    opt += u32(rdata_rva)     # BaseOfData
    opt += u32(IMAGE_BASE)    # ImageBase
    opt += u32(SEC_ALIGN)     # SectionAlignment
    opt += u32(FILE_ALIGN)    # FileAlignment
    opt += u16(6)             # MajorOS
    opt += u16(0)             # MinorOS
    opt += u16(6)             # MajorImage
    opt += u16(0)             # MinorImage
    opt += u16(6)             # MajorSubsystem
    opt += u16(0)             # MinorSubsystem
    opt += u32(0)             # Win32VersionValue
    opt += u32(size_of_image) # SizeOfImage
    opt += u32(headers_size)  # SizeOfHeaders
    opt += u32(0)             # CheckSum
    opt += u16(2)             # Subsystem GUI
    opt += u16(0x8140)        # DllCharacteristics
    opt += u32(0x100000)      # SizeOfStackReserve
    opt += u32(0x1000)        # SizeOfStackCommit
    opt += u32(0x100000)      # SizeOfHeapReserve
    opt += u32(0x1000)        # SizeOfHeapCommit
    opt += u32(0)             # LoaderFlags
    opt += u32(16)            # NumberOfRvaAndSizes
    opt += u32(0) * 16 * 2    # 数据目录(16 个,全部置空)
    nt += opt

    def sec_hdr(name, vsize, vaddr, rsize, rptr, flags):
        h = bytearray(40)
        h[0:8] = name.encode().ljust(8, b"\x00")
        h[8:12] = u32(vsize)
        h[12:16] = u32(vaddr)
        h[16:20] = u32(rsize)
        h[20:24] = u32(rptr)
        h[36:40] = u32(flags)
        return h

    secs = bytearray()
    secs += sec_hdr(".text", len(text), text_rva, text_raw_size, text_raw_ptr, 0x60000020)
    secs += sec_hdr(".rdata", len(rdata), rdata_rva, rdata_raw_size, rdata_raw_ptr, 0x40000040)
    secs += sec_hdr(".data", len(data), data_rva, data_raw_size, data_raw_ptr, 0xC0000040)

    headers = bytearray(dos)
    headers += nt
    headers += secs
    headers += b"\x00" * (headers_size - len(headers))
    if len(headers) > headers_size:
        raise SystemExit("headers too large")

    out = bytearray(headers)
    out += text + b"\x00" * (text_raw_size - len(text))
    out += rdata + b"\x00" * (rdata_raw_size - len(rdata))
    out += data + b"\x00" * (data_raw_size - len(data))
    return bytes(out)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).parent / "ue_sample.exe")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    data = build()
    Path(out).write_bytes(data)
    # 验证
    import pefile
    pe = pefile.PE(data=data)
    print(f"[OK] 已生成 {out} ({len(data)} bytes)")
    print(f"     Machine={hex(pe.FILE_HEADER.Machine)} Sections={pe.FILE_HEADER.NumberOfSections}")
    print(f"     Entry={hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase)}")
    # 验证注入的特征字符串与签名(签名: prefix + 4B disp + tail)
    checks = {
        "UE5-5.3.2": b"UE5-5.3.2", "ProcessEvent": b"ProcessEvent",
        "GetDefaultObject": b"GetDefaultObject", "UClass": b"UClass",
        "UFunction": b"UFunction", "FProperty": b"FProperty", "UObject": b"UObject",
    }

    def sig_present(prefix, tail):
        idx = data.find(prefix)
        while idx >= 0:
            if data[idx + 7:idx + 7 + len(tail)] == tail:
                return idx
            idx = data.find(prefix, idx + 1)
        return -1

    for name, prefix, tail in [
        ("GObjects_UE5", b"\x48\x8B\x05", b"\x48\x8B\x0C\xC8\x48\x8D\x04\xD1\x48\x89"),
        ("GNames_Pool", b"\x48\x8D\x05", b"\x0F\xB7\x14\x48"),
        ("GWorld_UE5", b"\x48\x8B\x1D", b"\x48\x8B\x5D\xD0"),
    ]:
        m = sig_present(prefix, tail)
        print(f"     sig {name}: {'OK' if m >= 0 else 'MISSING'} (match={m})")
    for s in checks.values():
        print(f"     str {s.decode():20s}: {'OK' if s in data else 'MISSING'}")
