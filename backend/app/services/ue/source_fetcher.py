"""UE 源码按需获取(轻量版)
- 不克隆/不下载整个 UnrealEngine 仓库(源码巨大)。
- 通过 GitHub API 快速定位镜像仓库中匹配版本的**分支**,再 raw 拉取少量关键头文件
  (UObjectArray.h / NameTypes.h 等,每个仅数 KB),本地缓存复用。
- 支持用户配置自定义镜像仓库或本地已存在的 UE 源码目录。
"""
from __future__ import annotations
import os
import re
from pathlib import Path

import httpx

from ...core.config import DATA_DIR, config
from .versions import GITHUB_MIRRORS, SOURCE_FILES

SRC_CACHE = DATA_DIR / "ue_src"

# 源码头文件 → 结构分析关键词
FILE_ANALYSIS = {
    "UObjectArray.h": ["chunk", "MaxChunkIndex", "FChunkedFixedUObjectArray", "GetObjectPtr", "ObjObjects", "NumElements"],
    "UObjectBase.h": ["ObjectFlags", "InternalIndex", "ClassPrivate", "OuterPrivate", "NamePrivate"],
    "NameTypes.h": ["FNamePool", "FNameEntry", "Blocks", "FNameEntryId", "IndexToName", "EName", "MaxByIndex"],
    "Object.h": ["UObject", "GetClass", "GetName", "GetFName"],
    "World.h": ["UWorld", "GWorld", "PersistentLevel", "CurrentLevel"],
}


class SourceFetchError(Exception):
    pass


def _client() -> httpx.Client:
    return httpx.Client(timeout=30,
                        proxies=os.environ.get("ALL_PROXY") or os.environ.get("HTTPS_PROXY") or None)


def list_mirror_branches(mirror: dict, proxy: bool = True) -> list:
    """列出镜像仓库的分支(名称列表,快)。"""
    owner, repo = mirror["owner"], mirror["repo"]
    url = f"https://api.github.com/repos/{owner}/{repo}/branches?per_page=100"
    try:
        with _client() as c:
            r = c.get(url, headers={"User-Agent": "REVLab"})
            if r.status_code != 200:
                return []
            return [b["name"] for b in r.json()]
    except Exception:
        return []


def _match_branch(branches: list, version: str) -> str | None:
    """匹配与版本对应的分支名。优先级:精确 → 前缀 → 模糊(仅字符匹配,不做数值比较)。"""
    ver = version.lower()
    # 精确
    for b in branches:
        if b.lower() == ver or b.lower() == f"{ver}-release":
            return b
    # 前缀(分支含版本号)
    for b in branches:
        bl = b.lower()
        if bl.startswith(ver) or ver in bl:
            return b
    # 模糊:提取数字段比较
    vn = re.sub(r"[^0-9.]", "", ver)
    for b in branches:
        bn = re.sub(r"[^0-9.]", "", b.lower())
        if bn == vn:
            return b
        if bn.startswith(vn) or vn.startswith(bn):
            return b
    return None


def find_version_branch(version: str) -> dict:
    """在所有镜像仓库中查找匹配版本的分支。返回 {mirror, branch}。"""
    for m in GITHUB_MIRRORS:
        if m.get("owner") == "EpicGames":  # 官方需授权,跳过
            continue
        try:
            branches = list_mirror_branches(m)
        except Exception:
            continue
        hit = _match_branch(branches, version)
        if hit:
            return {"mirror": f"{m['owner']}/{m['repo']}", "branch": hit, "note": m["note"]}
    raise SourceFetchError(f"未找到 UE {version} 的公开镜像分支")


def fetch_file(mirror: str, branch: str, path: str, cache: bool = True) -> str:
    """raw 拉取单个源码文件,返回内容。缓存到本地。"""
    cache_dir = SRC_CACHE / f"{mirror.replace('/', '_')}@{branch}"
    if cache:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cp = cache_dir / path.replace("/", "_")
        if cp.exists():
            return cp.read_text(encoding="utf-8", errors="ignore")
    url = f"https://raw.githubusercontent.com/{mirror}/{branch}/{path}"
    try:
        with _client() as c:
            r = c.get(url, headers={"User-Agent": "REVLab"})
            if r.status_code != 200:
                raise SourceFetchError(f"拉取失败 {url} (HTTP {r.status_code})")
            text = r.text
    except httpx.HTTPError as e:
        raise SourceFetchError(f"拉取失败 {url}: {e}")
    if cache:
        cp.write_text(text, encoding="utf-8")
    return text


def fetch_version_sources(version: str, files: list | None = None, cache: bool = True) -> dict:
    """为指定版本拉取关键源码文件。返回 {version, mirror, branch, files:[{path, size, cached}]}。"""
    loc = find_version_branch(version)
    result = {"version": version, "mirror": loc["mirror"], "branch": loc["branch"],
              "note": loc["note"], "files": []}
    for f in (files or SOURCE_FILES):
        try:
            text = fetch_file(loc["mirror"], loc["branch"], f, cache=cache)
            result["files"].append({"path": f, "size": len(text),
                                    "cached": (SRC_CACHE / f"{loc['mirror'].replace('/', '_')}@{loc['branch']}" / f.replace("/", "_")).exists()})
        except SourceFetchError as e:
            result["files"].append({"path": f, "size": 0, "cached": False, "error": str(e)})
    return result


def cached_sources() -> list:
    """列出本地已缓存的源码文件。"""
    if not SRC_CACHE.exists():
        return []
    out = []
    for d in SRC_CACHE.iterdir():
        if d.is_dir():
            for f in d.iterdir():
                out.append({"cache": d.name, "file": f.name, "size": f.stat().st_size})
    return out


def analyze_source_file(content: str, filename: str) -> dict:
    """从源码内容提取结构布局线索(正则轻量解析)。"""
    hints = {}
    # FNamePool block 偏移
    m = re.search(r"FNameEntry\s*\*\s*(\w+)\[.*?(\d+)", content, re.S)
    # TUObjectArray chunk
    if "chunk" in content.lower():
        cm = re.search(r"(?:chunk|NumElements|MaxChunkIndex)\s*[=:]\s*(\d+)", content)
        if cm:
            hints["chunk_count"] = int(cm.group(1))
    # FChunkedFixedUObjectArray 内联偏移(常见: ChunkSize=0x10000)
    m2 = re.search(r"(?:enum|constexpr|static\s+const).{0,40}?\b(?:MAX_|Num|ChunkSize).{0,20}(\d+)", content, re.S)
    if m2:
        hints["const"] = m2.group(1)
    # NameIndex / bIsNumber
    if "NameIndex" in content:
        hints["name_index_style"] = "modern (FNameEntryId)"
    if "ComparisonIndex" in content:
        hints["name_index_style"] = "legacy (ComparisonIndex)"
    matched = [k for k in FILE_ANALYSIS.get(filename, []) if k in content]
    return {"file": filename, "matched_keywords": matched, "hints": hints}


def analyze_all_cached(version: str) -> list:
    """分析已缓存源码文件,输出结构线索。"""
    out = []
    loc = None
    for d in SRC_CACHE.iterdir():
        if version in d.name:
            for f in sorted(d.iterdir()):
                content = f.read_text(encoding="utf-8", errors="ignore")
                out.append(analyze_source_file(content, f.name))
    return out
