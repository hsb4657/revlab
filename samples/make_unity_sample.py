"""REVLab Unity 演示样本构造器
在 samples/unity_sample/ 生成演示游戏目录:
  GameAssembly.dll                     (IL2CPP 主程序集,复制 revlab_sample.exe 改名,可被 pefile 解析)
  Data/il2cpp_data/Metadata/global-metadata.dat
                                      (IL2CPP v27 metadata:magic 0xFAB11BAF + 字符串表含关键游戏类名)
  Data/Managed/Assembly-CSharp.dll     (Mono 托管程序集占位,复制 revlab_sample.exe 改名)
  Data/globalgamemanagers              (版本串 2021.3.10f1)
  Data/resources.assets                (UnityFS 资源头)

用于 Unity 引擎阶段式工作流(engine_runner)本地验证,无需联网。
用法: python samples/make_unity_sample.py
"""
import struct
import sys
from pathlib import Path

MAGIC = 0xFAB11BAF
VERSION = 27

# 字符串表(经 il2cpp 模块 string_by_index 以字节偏移解析)
_STRINGS = [
    "", "Assembly-CSharp", "UnityEngine", "GameManager", "PlayerController",
    "Health", "GameObject", "TakeDamage", "Update", "Start", "Heal",
    "health", "playerName", "Assembly-CSharp.dll", "UnityPlayer",
]


def _string_offsets():
    """各字符串在字符串表中的字节偏移(供 name_index 使用)。"""
    offs = {}
    pos = 0
    for s in _STRINGS:
        offs[s] = pos
        pos += len(s.encode("utf-8")) + 1
    return offs


def u32(x):
    return struct.pack("<I", x & 0xFFFFFFFF)


def i32(x):
    return struct.pack("<i", x if x is not None else -1)


def align4(n):
    return (n + 3) & ~3


def build_string_table():
    data = bytearray()
    offsets = []
    for s in _STRINGS:
        offsets.append(len(data))
        data.extend(s.encode("utf-8") + b"\x00")
    while len(data) % 4:
        data.append(0)
    return bytes(data), offsets


def build_header(string_offset, string_count, image_offset, assembly_offset,
                 typedef_offset, typedef_count, method_offset, method_count,
                 field_offset, field_count):
    """IL2CPP v27 MetadataHeader(62 个 uint32 = 248 字节)。"""
    v = [
        MAGIC, VERSION,
        0, 0,                 # stringLiteralOffset/Count
        0, 0,                 # stringLiteralDataOffset/Count
        string_offset, string_count,
        0, 0,                 # events
        0, 0,                 # properties
        method_offset, method_count,
        0, 0,                 # parameterDefaultValues
        0, 0,                 # fieldDefaultValues
        0, 0,                 # fieldAndParameterDefaultValueData
        0, 0,                 # fieldMarshaledSizes
        0, 0,                 # parameters
        field_offset, field_count,
        0, 0,                 # genericParameters
        0, 0,                 # genericParameterConstraints
        0, 0,                 # genericContainers
        0, 0,                 # nestedTypes
        0, 0,                 # interfaces
        0, 0,                 # vtableMethods
        0, 0,                 # interfaceOffsets
        typedef_offset, typedef_count,
        image_offset, 1,
        assembly_offset, 1,
        0, 0,                 # fieldRefs
        0, 0,                 # referencedAssemblies
        0, 0,                 # attributesInfo
        0, 0,                 # attributeTypes
        0, 0,                 # unresolvedVirtualCallParameterTypes
        0, 0,                 # unresolvedVirtualCallParameterRanges
        0, 0,                 # windowsRuntimeTypeNames
        0, 0,                 # exportedTypeDefinitions
    ]
    assert len(v) == 62, len(v)
    return struct.pack("<62I", *v)


def build_image(offs):
    """Il2CppImageDefinition(il2cpp 模块 v27 解析,40 字节)。"""
    return struct.pack(
        "<10i",
        offs["Assembly-CSharp"],  # nameIndex
        0,    # assemblyIndex
        0,    # typeStart
        3,    # typeCount
        -1,   # exportedTypeStart
        0,    # exportedTypeCount
        -1,   # entryPointIndex
        0,    # token
        -1,   # customAttributeStart
        0,    # customAttributeCount
    )


def build_assembly(offs):
    """Il2CppAssemblyDefinition(60 字节,当前未被 il2cpp 模块解析,仅占位)。"""
    return struct.pack(
        "<i I i i i i i i i i I I I I I",
        0,     # imageIndex
        0,     # token
        -1,    # referencedAssemblyStart
        0,     # referencedAssemblyCount
        offs["Assembly-CSharp.dll"],  # nameIndex
        -1,    # cultureIndex
        -1,    # hashValueOffset
        0,     # hashValueSize
        -1,    # publicKeyOffset
        0,     # publicKeySize
        1, 0, 0, 0,  # major/minor/build/revision
        0,     # flags
    )


def build_typedefs(offs):
    """3 个 TypeDefinition(il2cpp 模块 v25+ 布局,76 字节/个)。
    布局(与 il2cpp 模块 _TD_V25 对齐):
      type_index@0 name_index@4 namespace_index@8 generic@12 flags@16
      field_start@20 method_start@24 event_start@28 property_start@32
      nested_start@36 interfaces_start@40 vtable_start@44 interface_offsets@48
      method_count@52 property_count@54 field_count@56 event_count@58
      nested_count@60 vtable_count@62 interfaces_count@64 interface_offsets_count@66
      bitfield@68 padding@70 token@72    (总 76 字节)
    """
    ns = offs["Assembly-CSharp"]
    rows = [
        # (type_index, name, method_start, method_count, field_start, field_count, token)
        (0, offs["GameManager"], 0, 2, 0, 1, 0x02000001),
        (1, offs["PlayerController"], 2, 1, 1, 1, 0x02000002),
        (2, offs["Health"], 3, 1, 2, 1, 0x02000003),
    ]
    out = bytearray()
    for type_idx, name, mstart, mcount, fstart, fcount, token in rows:
        td = bytearray(76)
        struct.pack_into("<i", td, 0, type_idx)
        struct.pack_into("<i", td, 4, name)
        struct.pack_into("<i", td, 8, ns)
        struct.pack_into("<i", td, 12, -1)      # genericContainerIndex
        struct.pack_into("<I", td, 16, 0)       # flags
        struct.pack_into("<i", td, 20, fstart)  # fieldStart
        struct.pack_into("<i", td, 24, mstart)  # methodStart
        struct.pack_into("<i", td, 28, -1)      # eventStart
        struct.pack_into("<i", td, 32, -1)      # propertyStart
        struct.pack_into("<i", td, 36, -1)      # nestedStart
        struct.pack_into("<i", td, 40, -1)      # interfacesStart
        struct.pack_into("<i", td, 44, -1)      # vtableStart
        struct.pack_into("<i", td, 48, -1)      # interfaceOffsetsStart
        struct.pack_into("<H", td, 52, mcount)  # methodCount
        struct.pack_into("<H", td, 54, 0)       # propertyCount
        struct.pack_into("<H", td, 56, fcount)  # fieldCount
        struct.pack_into("<H", td, 58, 0)       # eventCount
        struct.pack_into("<H", td, 60, 0)       # nestedCount
        struct.pack_into("<H", td, 62, 0)       # vtableCount
        struct.pack_into("<H", td, 64, 0)       # interfacesCount
        struct.pack_into("<H", td, 66, 0)       # interfaceOffsetsCount
        struct.pack_into("<H", td, 68, 0)       # bitfield
        struct.pack_into("<H", td, 70, 0)       # padding
        struct.pack_into("<I", td, 72, token)
        out += td
    assert len(out) == 3 * 76
    return bytes(out)


def build_methods(offs):
    """4 个 MethodDefinition(il2cpp 模块 v25 布局,32 字节/个)。
    布局:name_index@0 signature@4 return_type@8 parameter_start@12 generic@16
          token@20 flags@24 iflags@26 slot@28 parameter_count@30
    """
    rows = [
        (offs["TakeDamage"], 0),
        (offs["Update"], 0),
        (offs["Start"], 1),
        (offs["Heal"], 2),
    ]
    out = bytearray()
    for i, (nm, dt) in enumerate(rows):
        out += struct.pack(
            "<iiiii I HHHH",
            nm, dt, -1, -1, -1,   # nameIndex declaringType returnType parameterStart genericContainerIndex
            0x06000000 + i,        # token
            0x0001, 0, 0, 0,      # flags(public) iflags slot parameterCount
        )
    assert len(out) == 4 * 32
    return bytes(out)


def build_fields(offs):
    """3 个 FieldDefinition(12 字节/个):name_index@0 type_index@4 token@8。"""
    names = [offs["health"], offs["playerName"], offs["health"]]
    out = bytearray()
    for i, nm in enumerate(names):
        out += struct.pack("<iii", nm, -1, 0x04000000 + i)
    assert len(out) == 3 * 12
    return bytes(out)


def build_metadata() -> bytes:
    offs = _string_offsets()
    strings, _ = build_string_table()
    header_size = 62 * 4
    pos = header_size
    string_offset = pos
    pos = align4(string_offset + len(strings))

    image = build_image(offs)
    image_offset = pos
    pos += len(image)

    assembly = build_assembly(offs)
    assembly_offset = pos
    pos += len(assembly)

    typedefs = build_typedefs(offs)
    typedef_offset = pos
    pos += len(typedefs)

    methods = build_methods(offs)
    method_offset = pos
    pos += len(methods)

    fields = build_fields(offs)
    field_offset = pos
    pos += len(fields)

    header = build_header(
        string_offset=string_offset, string_count=len(_STRINGS),
        image_offset=image_offset, assembly_offset=assembly_offset,
        typedef_offset=typedef_offset, typedef_count=3,
        method_offset=method_offset, method_count=4,
        field_offset=field_offset, field_count=3,
    )
    assert len(header) == header_size
    body = header + strings + image + assembly + typedefs + methods + fields
    # 附加冗余字符串块,保证纯字符串扫描也能命中
    body += b"\x00Assembly-CSharp\x00GameManager\x00PlayerController\x00Health\x00TakeDamage\x00UnityEngine\x00"
    return body


def build():
    base = Path(__file__).resolve().parent
    sample_exe = base / "revlab_sample.exe"
    if not sample_exe.exists():
        raise SystemExit("缺少 samples/revlab_sample.exe,请先运行 python samples/make_sample.py")

    root = base / "unity_sample"
    metadata_dir = root / "Data" / "il2cpp_data" / "Metadata"
    managed_dir = root / "Data" / "Managed"
    for d in (metadata_dir, managed_dir):
        d.mkdir(parents=True, exist_ok=True)

    exe = sample_exe.read_bytes()
    (root / "GameAssembly.dll").write_bytes(exe)
    (managed_dir / "Assembly-CSharp.dll").write_bytes(exe)
    (metadata_dir / "global-metadata.dat").write_bytes(build_metadata())
    (root / "Data" / "globalgamemanagers").write_text("2021.3.10f1", encoding="utf-8")
    (root / "Data" / "resources.assets").write_bytes(b"UnityFS\x00\x00" + b"\x00" * 24)

    # 验证
    import pefile
    pe = pefile.PE(str(root / "GameAssembly.dll"))
    print(f"[OK] 已生成 {root}")
    print(f"     GameAssembly.dll Machine={hex(pe.FILE_HEADER.Machine)} Sections={pe.FILE_HEADER.NumberOfSections}")
    md = (metadata_dir / "global-metadata.dat").read_bytes()
    magic, ver = struct.unpack("<II", md[:8])
    print(f"     global-metadata.dat magic=0x{magic:08X} version={ver} size={len(md)}")
    for s in ("Assembly-CSharp", "GameManager", "PlayerController", "Health",
              "TakeDamage", "UnityEngine"):
        if s.encode() not in md:
            print(f"     [WARN] 字符串缺失: {s}")
    print(f"     globalgamemanagers: {(root/'Data'/'globalgamemanagers').read_text().strip()}")
    print(f"     resources.assets header: {(root/'Data'/'resources.assets').read_bytes()[:8]!r}")


if __name__ == "__main__":
    build()
    sys.exit(0)
