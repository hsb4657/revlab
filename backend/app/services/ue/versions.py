"""虚幻引擎版本知识库
基于公开逆向社区数据(UE4Dumper / UnrealDumper / 各大 UE 逆向项目)整理。
覆盖主要 4.x / 5.x 版本的核心结构布局、FName 索引方式、加密特征与源码分支名。
实际定位优先使用特征字节签名,本表用于交叉校验与偏移校正。
"""
from __future__ import annotations

from copy import deepcopy

# FName 索引方式: direct(早期 TNameEntryArray 直接索引) / pool(FNamePool 分块索引)
# chunk_size: TUObjectArray 每个 chunk 的对象数(经典 0x10000 = 64K)
UE_VERSIONS: dict = {
    "4.27": {
        "engine": "4.27.2", "family": "4.x", "fname": "direct", "gobjects_chunk": 0x10000,
        "gobjects_offset": 0, "gnames_type": "TNameEntryArray",
        "sources": {"branch": "4.27-release"},
        "note": "UE4.27 经典版,FName 直接索引 TNameEntryArray",
    },
    "5.0": {
        "engine": "5.0.3", "family": "5.x", "fname": "pool", "gobjects_chunk": 0x10000,
        "gobjects_offset": 0, "gnames_type": "FNamePool",
        "sources": {"branch": "5.0-release"},
        "note": "UE5.0,FNamePool 引入 block 分块",
    },
    "5.1": {
        "engine": "5.1.1", "family": "5.x", "fname": "pool", "gobjects_chunk": 0x10000,
        "gobjects_offset": 0, "gnames_type": "FNamePool",
        "sources": {"branch": "5.1-release"},
        "note": "UE5.1",
    },
    "5.2": {
        "engine": "5.2.1", "family": "5.x", "fname": "pool", "gobjects_chunk": 0x10000,
        "gobjects_offset": 0, "gnames_type": "FNamePool",
        "sources": {"branch": "5.2-release"},
        "note": "UE5.2,FName 加密引入 FName::IndexToName 加速表",
    },
    "5.3": {
        "engine": "5.3.2", "family": "5.x", "fname": "pool", "gobjects_chunk": 0x10000,
        "gobjects_offset": 0, "gnames_type": "FNamePool",
        "sources": {"branch": "5.3-release"},
        "note": "UE5.3,FName::FNameEntryId 统一索引",
    },
    "5.4": {
        "engine": "5.4.4", "family": "5.x", "fname": "pool", "gobjects_chunk": 0x10000,
        "gobjects_offset": 0, "gnames_type": "FNamePool",
        "sources": {"branch": "5.4-release"},
        "note": "UE5.4,ObjectArray 使用 FChunkedFixedUObjectArray 增强",
    },
    "5.5": {
        "engine": "5.5.0", "family": "5.x", "fname": "pool", "gobjects_chunk": 0x10000,
        "gobjects_offset": 0, "gnames_type": "FNamePool",
        "sources": {"branch": "5.5-release"},
        "note": "UE5.5",
    },
    "5.6": {
        "engine": "5.6.x", "family": "5.x", "fname": "pool", "gobjects_chunk": 0x10000,
        "gobjects_offset": 0, "gnames_type": "FNamePool",
        "sources": {"branch": "5.6-release"},
        "note": "UE5.6 candidate layout: FNamePool/FNameEntryId and chunked UObject array",
    },
    "5.7": {
        "engine": "5.7.x", "family": "5.x", "fname": "pool", "gobjects_chunk": 0x10000,
        "gobjects_offset": 0, "gnames_type": "FNamePool",
        "sources": {"branch": "5.7-release"},
        "note": "UE5.7 candidate layout: FNamePool/FNameEntryId and chunked UObject array",
    },
    "5.8": {
        "engine": "5.8.x", "family": "5.x", "fname": "pool", "gobjects_chunk": 0x10000,
        "gobjects_offset": 0, "gnames_type": "FNamePool",
        "sources": {"branch": "5.8-release"},
        "note": "UE5.8 candidate layout: FNamePool/FNameEntryId and chunked UObject array",
    },
}

# 各版本 FName 的字符串存储结构(FNamePool:Blocks[] / TNameEntryArray:Entries[])
# FName 索引在 dump 分析中的常见算法差异
FNAME_DETAILS: dict = {
    "direct": {
        "desc": "UE4 早期:TNameEntryArray,Index 直接为数组下标(Number 高位 1<<16)",
        "index_shift": 0, "number_mask": 0xFFFF,
    },
    "pool": {
        "desc": "UE4.23+/UE5:FNamePool，以 FNameEntryId 高位选择 block、低 16 位选择块内偏移；header/块数需按构建校验",
        "index_type": "FNameEntryId", "index_width": 32,
        "block_offset_bits": 16, "block_offset_mask": 0xFFFF,
        "block_bits_candidates": [13, 14], "block_size": 0x10000,
        "index_mask": 0xFFFF, "entry_stride_candidates": [2, 4],
        "header_candidates": [
            {"offset": 0, "wide_bit": 0, "length_shift": 1, "length_bits": 15},
            {"offset": 0, "wide_bit": 0, "length_shift": 6, "length_bits": 10},
        ],
        "runtime_validation_required": True,
    },
}

# Version-aware layouts are evidence hints, not hard-coded proof.  UE5.0-5.8
# share the modern pool/index family in the default profile, while optional
# fields make version-specific changes visible to the workflow and report.
UE5_FNAME_POOL_LAYOUTS: dict[str, dict] = {
    version: {
        "model": "FNamePool",
        # UE5 keeps a 32-bit id; source/builds may expose it as
        # ComparisonIndex or the FNameEntryId wrapper. Keep both labels so
        # callers can explain the candidate rather than silently choosing one.
        "index_type": "FNameEntryId",
        "index_aliases": ["ComparisonIndex", "DisplayIndex"],
        "index_width": 32,
        "block_offset_bits": 16,
        "block_offset_mask": 0xFFFF,
        "block_bits_candidates": [13, 14],
        "max_blocks_candidates": [0x2000, 0x4000],
        "stride": 2,
        "entry_stride_candidates": [2, 4],
        "entry_info_offset": 0,
        "wide_bit": 0,
        "length_shift": 6,
        "length_shift_candidates": [1, 6],
        "length_bits_candidates": [10, 15],
        "header_size": 2,
        "header_size_candidates": [2, 4],
        "index_formula_candidates": [
            "block = FNameEntryId.Value >> 16; offset = FNameEntryId.Value & 0xffff",
            "block = comparison_index >> 16; offset = comparison_index & 0xffff",
        ],
        "index_to_name_optional": version >= "5.2",
        "validation_state": "candidate",
        "runtime_validation_required": True,
    }
    for version in ("5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8")
}

UE5_GOBJECT_LAYOUTS: dict[str, dict] = {
    version: {
        "array_type": "FChunkedFixedUObjectArray",
        "container_type": "FUObjectArray",
        "chunk_size": 0x10000,
        "chunk_size_candidates": [0x10000, 0x4000],
        "fuobject_item_size": 0x18,
        "item_size_candidates": [0x18, 0x20],
        "pointer_size": 8,
        "obj_objects_offset_candidates": [0x10, 0x18, 0x20],
        "fields": {
            "Objects": 0x00,
            "PreAllocatedObjects": 0x08,
            "MaxElements": 0x10,
            "NumElements": 0x14,
            "MaxChunks": 0x18,
            "NumChunks": 0x1C,
        },
        "item_fields": {
            "Object": 0x00,
            "Flags": 0x08,
            "ClusterRootIndex": 0x0C,
            "SerialNumber": 0x10,
        },
        # Legacy aliases retained for existing API clients.
        "num_elements_offset": 0x14,
        "num_chunks_offset": 0x1C,
        "objects_offset": 0x00,
        "index_formula": "chunk = index >> 16; slot = index & 0xFFFF; item = chunks[chunk][slot]",
        "validation_state": "candidate",
        "runtime_validation_required": True,
    }
    for version in ("5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8")
}

UE5_REFLECTION_LAYOUTS: dict[str, dict] = {
    version: {
        "model": "FField/FProperty",
        "chains": ["UStruct::ChildProperties", "UStruct::Children"],
        "structures": ["UObject", "UClass", "UStruct", "UFunction", "FField", "FProperty"],
        "property_chain": "UStruct.ChildProperties -> FField.Next -> FProperty",
        "legacy_chain": "UStruct.Children -> UField.Next -> UProperty",
        "validation_state": "candidate",
        "runtime_validation_required": True,
    }
    for version in ("5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8")
}

for _version, _metadata in UE_VERSIONS.items():
    if _version in UE5_FNAME_POOL_LAYOUTS:
        _metadata["fname_layout"] = deepcopy(UE5_FNAME_POOL_LAYOUTS[_version])
        _metadata["gobjects_layout"] = deepcopy(UE5_GOBJECT_LAYOUTS[_version])
        _metadata["reflection_layout"] = deepcopy(UE5_REFLECTION_LAYOUTS[_version])
        _metadata["generation"] = "UE5"
        _metadata["version_status"] = "known_candidate"


def get_fname_layout(version: str) -> dict:
    """Return a copy of the version-aware FNamePool candidate layout."""
    key = normalize_version(version)
    if key in UE5_FNAME_POOL_LAYOUTS:
        return deepcopy(UE5_FNAME_POOL_LAYOUTS[key])
    return deepcopy(FNAME_DETAILS.get("direct" if str(version).startswith("4.") else "pool", {}))


def get_gobjects_layout(version: str) -> dict:
    """Return a copy of the version-aware UObject-array candidate layout."""
    key = normalize_version(version)
    if key in UE5_GOBJECT_LAYOUTS:
        return deepcopy(UE5_GOBJECT_LAYOUTS[key])
    return {
        "array_type": "TUObjectArray-compatible",
        "chunk_size": 0x10000,
        "fuobject_item_size": 0x18,
        "pointer_size": 8,
        "validation_state": "unconfirmed",
    }


def get_gobjects_layout_profiles(version: str) -> list[dict]:
    """Expose version-specific and generic GObjects layout candidates."""
    key = normalize_version(version)
    active = get_gobjects_layout(key or version)
    if key in UE5_GOBJECT_LAYOUTS:
        return [
            {
                "id": f"ue{key.replace('.', '_')}_gobjects",
                "name": f"UE {key} {active.get('array_type')}",
                "version": key,
                "layout": active,
                "score": 70,
                "confidence": 70,
                "validation_state": "candidate",
                "evidence": [
                    {
                        "kind": "version_registry",
                        "detail": f"UE {key} maps to the registered UObject-array layout candidate.",
                    }
                ],
            },
            {
                "id": "ue5_generic_gobjects",
                "name": "UE5 generic FChunkedFixedUObjectArray",
                "version": "5.0-5.8",
                "layout": deepcopy(active),
                "score": 45,
                "confidence": 45,
                "validation_state": "candidate",
                "evidence": [
                    {
                        "kind": "family_registry",
                        "detail": "Generic UE5 fallback; validate NumElements, chunks, and FUObjectItem stride at runtime.",
                    }
                ],
            },
        ]
    return [
        {
            "id": "generic_gobjects",
            "name": "Generic UObject array",
            "version": version or "unknown",
            "layout": active,
            "score": 0,
            "confidence": 0,
            "validation_state": "unconfirmed",
            "evidence": [],
        }
    ]


def get_version_layout(version: str) -> dict:
    """Combine FNamePool and GObjects candidates for API/report consumers."""
    key = normalize_version(version)
    return {
        "version": key or version,
        "generation": "UE5" if key.startswith("5.") else "UE4" if key.startswith("4.") else "unknown",
        "fname": get_fname_layout(key or version),
        "gobjects": get_gobjects_layout(key or version),
        "reflection": deepcopy(UE5_REFLECTION_LAYOUTS.get(key, {})),
        "validation_state": "candidate" if key in UE5_FNAME_POOL_LAYOUTS else "unconfirmed",
        "runtime_validation_required": True,
    }

# 常用源码关键文件(按版本拉取用于结构分析)
SOURCE_FILES: list = [
    "Engine/Source/Runtime/CoreUObject/Public/UObject/UObjectArray.h",
    "Engine/Source/Runtime/CoreUObject/Public/UObject/UObjectBase.h",
    "Engine/Source/Runtime/Core/Public/UObject/NameTypes.h",
    "Engine/Source/Runtime/CoreUObject/Public/UObject/Object.h",
    "Engine/Source/Runtime/Engine/Classes/Engine/World.h",
]

# 加密/混淆检测特征(UE 相关)
UE_ENCRYPTION_SIGS: list = [
    ("FNameEncryption", "UnrealEngine 5.2+ FName 加密(FName 字符串混淆)"),
    ("GNameFastHash", "FName IndexToName 加速哈希表"),
    ("AES", "AES 加密特征(SizedAES128)"),
    ("VMProtect", "VMProtect 虚拟机壳"),
    ("Themida", "Themida 保护壳"),
    ("TLS", "TLS 回调加密"),
    ("PackedSections", "高熵节区(代码/资源加密)"),
]

# 内置 GitHub 镜像仓库(UE 源码公开镜像,按需拉取单个文件)
GITHUB_MIRRORS: list = [
    {"owner": "LarJarosz", "repo": "UnrealEngine", "note": "LarJarosz 公开镜像"},
    {"owner": "Unreal-Framework", "repo": "UnrealEngine", "note": "Unreal-Framework 镜像"},
    {"owner": "EpicGames", "repo": "UnrealEngine", "note": "官方(需授权,仅作占位)"},
]


def all_versions() -> list:
    return sorted(UE_VERSIONS.keys(), key=lambda v: tuple(int(x) for x in v.split(".")))


def get_version(version: str) -> dict | None:
    if not version:
        return None
    value = str(version).strip()
    if value in UE_VERSIONS:
        return UE_VERSIONS[value]
    key = normalize_version(value)
    return UE_VERSIONS.get(key)


def normalize_version(version: str) -> str:
    """Normalize ``UE5.8.1``/``5.8-preview`` to the ``5.8`` profile key."""
    import re
    match = re.search(r"(?:UE)?\s*([45])\.(\d+)", str(version or ""), re.IGNORECASE)
    return f"{match.group(1)}.{match.group(2)}" if match else ""


def version_candidates(version: str = "", family: str = "") -> list[str]:
    """Return known minor profiles compatible with a requested version/family."""
    key = normalize_version(version)
    if key in UE_VERSIONS:
        return [key]
    fam = family or ("5.x" if key.startswith("5.") else "4.x" if key.startswith("4.") else "")
    return [item for item in all_versions() if UE_VERSIONS[item].get("family") == fam]


def search_versions(keyword: str) -> list:
    kw = keyword.lower()
    return [v for v in UE_VERSIONS
            if kw in v or kw in UE_VERSIONS[v]["engine"] or kw in UE_VERSIONS[v]["note"].lower()]
