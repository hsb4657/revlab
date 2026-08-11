"""REVLab 自研合规测试样本构造器
生成一个含 .text/.rdata/.data 三节区、kernel32+ws2_32 导入表、字符串的 PE32。
用法: python samples/make_sample.py <out.exe>
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

    # ---------------- .rdata 布局 ----------------
    rdata = bytearray()
    # 1) IID table(先占位,后填)
    iid_off = len(rdata)
    rdata += b"\x00" * 60  # 3 * 20

    def put_str(s):
        rdata.extend(s.encode() + b"\x00")

    # 2) DLL 名
    name_k32 = len(rdata); put_str("kernel32.dll")
    name_ws2 = len(rdata); put_str("ws2_32.dll")

    # 3) Hint/Name 结构(hint=0 + 名称)
    def put_hintname(name):
        off = len(rdata)
        rdata.extend(u16(0)); rdata.extend(name.encode() + b"\x00")
        return off

    hn_msg = put_hintname("MessageBoxA")
    hn_exit = put_hintname("ExitProcess")
    hn_start = put_hintname("WSAStartup")
    hn_clean = put_hintname("WSACleanup")

    # 4) Thunk 数组与 IAT:每个 entry 是 hint/name 的 RVA,0 结尾
    def put_thunkarr(*hns):
        off = len(rdata)
        for h in hns:
            rdata.extend(u32(0x2000 + h))
        rdata.extend(u32(0))
        return off

    th_k32 = put_thunkarr(hn_msg, hn_exit)
    th_ws2 = put_thunkarr(hn_start, hn_clean)
    iat_k32 = put_thunkarr(hn_msg, hn_exit)
    iat_ws2 = put_thunkarr(hn_start, hn_clean)

    # 5) 字符串
    off_caption = len(rdata); put_str("REVLab")
    off_text = len(rdata); put_str("REVLab self-developed compliant test sample: fib(10)=55")

    # 填充 IID 表(RVA 需加 .rdata 基址 0x2000)
    def iid(oft, name, ft):
        return u32(0x2000 + oft) + u32(0) + u32(0) + u32(0x2000 + name) + u32(0x2000 + ft)

    rdata[0:20] = iid(th_k32, name_k32, iat_k32)
    rdata[20:40] = iid(th_ws2, name_ws2, iat_ws2)
    # 40..60 保持零(结束)

    # ---------------- .text 代码 ----------------
    iat_msg = 0x2000 + iat_k32
    iat_exit = 0x2000 + iat_k32 + 8
    cap = 0x2000 + off_caption
    txt = 0x2000 + off_text
    code = bytes([
        0x55, 0x89, 0xE5,                # push ebp; mov ebp,esp
        0x6A, 0x40,                      # push 0x40 (MB_ICONINFORMATION)
        0x68, *u32(cap),                 # push caption
        0x68, *u32(txt),                 # push text
        0x6A, 0x00,                      # push hWnd
        0xFF, 0x15, *u32(iat_msg),       # call [MessageBoxA]
        0x6A, 0x00,                      # push exitcode
        0xFF, 0x15, *u32(iat_exit),      # call [ExitProcess]
    ])

    # ---------------- 节区数据 ----------------
    text_raw = align(len(code), FILE_ALIGN)
    rdata_padded = align(len(rdata), FILE_ALIGN)

    headers_size = align(0x400, FILE_ALIGN)  # DOS+NT+section headers 预留
    text_rva = 0x1000
    rdata_rva = text_rva + SEC_ALIGN
    data_rva = rdata_rva + SEC_ALIGN

    size_of_image = data_rva + 0x200  # 粗算
    size_of_image = align(size_of_image, SEC_ALIGN)

    # ---------------- 头 ----------------
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = u32(0x40)  # e_lfanew
    nt = bytearray()
    nt += b"PE\x00\x00"
    # FILE_HEADER
    nt += u16(0x14C)          # i386
    nt += u16(2)              # NumberOfSections
    nt += u32(0x60000000)     # TimeDateStamp
    nt += u32(0)              # PointerToSymbolTable
    nt += u32(0)              # NumberOfSymbols
    nt += u16(0xE0)           # SizeOfOptionalHeader
    nt += u16(0x0103)         # Characteristics: EXECUTABLE|32BIT
    # OPTIONAL_HEADER (PE32)
    opt = bytearray()
    opt += u16(0x10B)         # Magic PE32
    opt += bytes([6, 0])      # linker 6.0
    opt += u32(len(code))     # SizeOfCode
    opt += u32(len(rdata))    # SizeOfInitializedData
    opt += u32(0)             # SizeOfUninitializedData
    opt += u32(0x1000)        # AddressOfEntryPoint
    opt += u32(0x1000)        # BaseOfCode
    opt += u32(0x2000)        # BaseOfData
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
    # 数据目录(16个,索引1=导入表)
    opt += u32(0) * 2         # [0] Export (rva+size)
    opt += u32(rdata_rva) + u32(60)   # [1] Import
    opt += u32(0) * 14 * 2
    nt += opt

    # 节区头
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
    secs += sec_hdr(".text", len(code), text_rva, text_raw, headers_size, 0x60000020)
    secs += sec_hdr(".rdata", len(rdata), rdata_rva, rdata_padded, headers_size + text_raw, 0x40000040)

    headers = bytearray(dos)
    headers += nt
    headers += secs
    # 头对齐:FILE_ALIGN 边界 → 填充到 headers_size
    headers += b"\x00" * (headers_size - len(headers))
    if len(headers) > headers_size:
        raise SystemExit("headers too large")

    out = bytearray(headers)
    out += code + b"\x00" * (text_raw - len(code))
    out += rdata + b"\x00" * (rdata_padded - len(rdata))
    return bytes(out)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).parent / "revlab_sample.exe")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    data = build()
    Path(out).write_bytes(data)
    # 验证
    import pefile
    pe = pefile.PE(data=data)
    print(f"[OK] 已生成 {out} ({len(data)} bytes)")
    print(f"     Machine={hex(pe.FILE_HEADER.Machine)} Sections={pe.FILE_HEADER.NumberOfSections}")
    print(f"     Entry={hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase)}")
    print(f"     Imports: {[e.dll.decode() for e in pe.DIRECTORY_ENTRY_IMPORT]}")
    print(f"     imphash={pe.get_imphash()}")
