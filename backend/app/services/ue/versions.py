"""虚幻引擎版本知识库
基于公开逆向社区数据(UE4Dumper / UnrealDumper / 各大 UE 逆向项目)整理。
覆盖主要 4.x / 5.x 版本的核心结构布局、FName 索引方式、加密特征与源码分支名。
实际定位优先使用特征字节签名,本表用于交叉校验与偏移校正。
"""
from __future__ import annotations

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
}

# 各版本 FName 的字符串存储结构(FNamePool:Blocks[] / TNameEntryArray:Entries[])
# FName 索引在 dump 分析中的常见算法差异
FNAME_DETAILS: dict = {
    "direct": {
        "desc": "UE4 早期:TNameEntryArray,Index 直接为数组下标(Number 高位 1<<16)",
        "index_shift": 0, "number_mask": 0xFFFF,
    },
    "pool": {
        "desc": "UE4.23+/UE5:FNamePool,Index 高 6 bit 为 Block 号,低 18 bit 为块内偏移",
        "block_bits": 6, "block_size": 0xFFFF, "index_mask": 0x3FFFF,
    },
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
    return UE_VERSIONS.get(version)


def search_versions(keyword: str) -> list:
    kw = keyword.lower()
    return [v for v in UE_VERSIONS
            if kw in v or kw in UE_VERSIONS[v]["engine"] or kw in UE_VERSIONS[v]["note"].lower()]
