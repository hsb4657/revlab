"""文件指纹:MD5/SHA1/SHA256/SHA512/imphash/ssdeep"""
import hashlib
import math


def _ssdeep_sim(a: str, b: str) -> int:
    """轻量 ssdeep 相似度近似(0-100)。完整实现依赖 libfuzzy。"""
    if not a or not b or a == b:
        return 100 if a == b else 0
    seta, setb = set(a.split(":")[1].split(":")[-1] if ":" in a else a), set(b.split(":")[1].split(":")[-1] if ":" in b else b)
    if not seta or not setb:
        return 0
    j = len(seta & setb) / len(seta | setb)
    return int(j * 100)


def compute_hashes(data: bytes, pe=None) -> dict:
    h = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "size": len(data),
        "imphash": "",
        "ssdeep": "",
        "ssdeep_sim": None,
    }
    if pe is not None:
        try:
            h["imphash"] = pe.get_imphash() or ""
        except Exception:
            pass
    return h


def imphash_from_imports(imports: list) -> str:
    """依据导入表(小写 dll+func 排序)计算 imphash,与 pefile 兼容。"""
    parts = []
    for imp in imports:
        for fn in imp.get("functions", []):
            parts.append(f"{imp['dll'].lower()}.{fn.get('name','').lower()}")
    parts.sort()
    import hashlib
    return hashlib.md5(",".join(parts).encode("utf-8")).hexdigest()


def entropy(data: bytes) -> float:
    """Shannon 熵(0-8)。高熵(>6.5)通常表示加密/压缩。"""
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    e = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return round(e, 4)
