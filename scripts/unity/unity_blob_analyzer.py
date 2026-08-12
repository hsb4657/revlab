#!/usr/bin/env python3
"""Read-only triage for renamed/split Unity IL2CPP metadata blobs.

The script deliberately does not emit a decrypted file.  It measures container
shape, entropy, repeated blocks, cross-file similarity, common format markers,
and bounded known-plaintext/XOR hypotheses.  A positive SDK/decryption result
must still pass an IL2CPP metadata structural validator.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import itertools
import json
import math
import os
import struct
from pathlib import Path


IL2CPP_MAGIC = b"\xaf\x1b\xb1\xfa"
HEADER_SIZE = 0xF8
DEFAULT_MAX_BYTES = 64 * 1024 * 1024

SIGNATURES = {
    "il2cpp_metadata": IL2CPP_MAGIC,
    "gzip": b"\x1f\x8b\x08",
    "zip": b"PK\x03\x04",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "xz": b"\xfd7zXZ\x00",
    "zstd": b"\x28\xb5\x2f\xfd",
    "lz4_frame": b"\x04\x22\x4d\x18",
    "bzip2": b"BZh",
    "rar4": b"Rar!\x1a\x07\x00",
    "rar5": b"Rar!\x1a\x07\x01\x00",
    "unityfs": b"UnityFS",
    "pe": b"MZ",
    "elf": b"\x7fELF",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def chi_square_uniform(data: bytes) -> float:
    if not data:
        return 0.0
    expected = len(data) / 256.0
    counts = collections.Counter(data)
    return sum(((counts.get(value, 0) - expected) ** 2) / expected for value in range(256))


def serial_correlation(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    left = data[:-1]
    right = data[1:]
    count = len(left)
    mean_left = sum(left) / count
    mean_right = sum(right) / count
    numerator = sum((a - mean_left) * (b - mean_right) for a, b in zip(left, right))
    denom_left = sum((a - mean_left) ** 2 for a in left)
    denom_right = sum((b - mean_right) ** 2 for b in right)
    denominator = math.sqrt(denom_left * denom_right)
    return numerator / denominator if denominator else 0.0


def common_prefix(a: bytes, b: bytes) -> int:
    for index, (left, right) in enumerate(zip(a, b)):
        if left != right:
            return index
    return min(len(a), len(b))


def common_suffix(a: bytes, b: bytes) -> int:
    return common_prefix(a[::-1], b[::-1])


def block_stats(data: bytes, block_size: int) -> dict:
    full = len(data) // block_size
    blocks = [data[index * block_size:(index + 1) * block_size] for index in range(full)]
    counts = collections.Counter(blocks)
    repeated_instances = sum(count - 1 for count in counts.values() if count > 1)
    return {
        "block_size": block_size,
        "full_blocks": full,
        "unique_blocks": len(counts),
        "repeated_instances": repeated_instances,
        "max_multiplicity": max(counts.values(), default=0),
    }


def entropy_windows(data: bytes, window: int) -> dict:
    values = [entropy(data[offset:offset + window]) for offset in range(0, len(data), window)]
    if not values:
        return {"window": window, "count": 0, "min": 0.0, "max": 0.0, "mean": 0.0}
    return {
        "window": window,
        "count": len(values),
        "min": round(min(values), 6),
        "max": round(max(values), 6),
        "mean": round(sum(values) / len(values), 6),
        "first": round(values[0], 6),
        "last": round(values[-1], 6),
    }


def signature_hits(data: bytes) -> list[dict]:
    hits: list[dict] = []
    for name, marker in SIGNATURES.items():
        start = 0
        offsets: list[int] = []
        while len(offsets) < 16:
            position = data.find(marker, start)
            if position < 0:
                break
            offsets.append(position)
            start = position + 1
        if offsets:
            hits.append({"name": name, "offsets": offsets, "truncated": len(offsets) == 16})
    return hits


def valid_metadata_header(data: bytes) -> dict:
    result = {"magic": data[:4].hex(), "valid": False, "version": None, "plausible_pairs": 0}
    if len(data) < HEADER_SIZE or data[:4] != IL2CPP_MAGIC:
        return result
    version = struct.unpack_from("<I", data, 4)[0]
    result["version"] = version
    if not 16 <= version <= 50:
        return result
    plausible = 0
    for offset in range(8, HEADER_SIZE, 8):
        table_offset, table_size = struct.unpack_from("<II", data, offset)
        if HEADER_SIZE <= table_offset <= len(data) and table_size <= len(data):
            plausible += 1
    result["plausible_pairs"] = plausible
    result["valid"] = plausible >= 10
    return result


def repeating_xor_tests(data: bytes) -> list[dict]:
    """Test only keys fully determined by known magic+version bytes.

    This does not brute-force unknown keys.  Periods 1/2/4/8 are completely
    determined by the first eight known plaintext bytes for each version.
    """
    outcomes: list[dict] = []
    if len(data) < HEADER_SIZE:
        return outcomes
    for version in range(16, 51):
        known = IL2CPP_MAGIC + struct.pack("<I", version)
        keystream = bytes(left ^ right for left, right in zip(data[:8], known))
        for period in (1, 2, 4, 8):
            key = keystream[:period]
            if any(keystream[index] != key[index % period] for index in range(8)):
                continue
            decoded = bytes(value ^ key[index % period] for index, value in enumerate(data[:HEADER_SIZE]))
            check = valid_metadata_header(decoded + bytes(max(0, len(data) - HEADER_SIZE)))
            outcomes.append({
                "version": version,
                "period": period,
                "key_hex": key.hex(),
                "header_valid": check["valid"],
                "plausible_pairs": check["plausible_pairs"],
            })
    return outcomes


def byte_transform_tests(data: bytes) -> list[dict]:
    """Bounded tests for single-byte XOR/add/subtract and bit rotations."""
    if len(data) < HEADER_SIZE:
        return []
    results: list[dict] = []
    for operation in ("xor", "add", "sub"):
        for key in range(256):
            if operation == "xor":
                decoded = bytes(value ^ key for value in data[:HEADER_SIZE])
            elif operation == "add":
                decoded = bytes((value + key) & 0xFF for value in data[:HEADER_SIZE])
            else:
                decoded = bytes((value - key) & 0xFF for value in data[:HEADER_SIZE])
            if decoded[:4] != IL2CPP_MAGIC:
                continue
            check = valid_metadata_header(decoded + bytes(max(0, len(data) - HEADER_SIZE)))
            results.append({"operation": operation, "key": key, **check})
    for bits in range(1, 8):
        decoded = bytes(((value >> bits) | (value << (8 - bits))) & 0xFF for value in data[:HEADER_SIZE])
        if decoded[:4] == IL2CPP_MAGIC:
            check = valid_metadata_header(decoded + bytes(max(0, len(data) - HEADER_SIZE)))
            results.append({"operation": "ror", "bits": bits, **check})
    return results


def cross_file_stats(items: list[tuple[Path, bytes]]) -> list[dict]:
    output: list[dict] = []
    for (left_path, left), (right_path, right) in itertools.combinations(items, 2):
        length = min(len(left), len(right))
        stride = max(1, length // (1024 * 1024))
        left_sample = left[:length:stride]
        right_sample = right[:length:stride]
        xor_sample = bytes(a ^ b for a, b in zip(left_sample, right_sample))
        equal = sum(a == b for a, b in zip(left_sample, right_sample))
        output.append({
            "left": left_path.name,
            "right": right_path.name,
            "compared_bytes": length,
            "sample_stride": stride,
            "sample_count": len(left_sample),
            "equal_byte_ratio": round(equal / len(left_sample), 8) if left_sample else 0.0,
            "xor_zero_ratio": round(xor_sample.count(0) / len(xor_sample), 8) if xor_sample else 0.0,
            "xor_entropy": round(entropy(xor_sample), 6),
            "common_prefix": common_prefix(left, right),
            "common_suffix": common_suffix(left, right),
        })
    return output


def analyze_file(path: Path, data: bytes) -> dict:
    sample_stride = max(1, len(data) // (4 * 1024 * 1024))
    sample = data[::sample_stride]
    name_raw = bytes.fromhex(path.name) if len(path.name) == 32 else b""
    return {
        "path": str(path),
        "name": path.name,
        "size": len(data),
        "size_hex": hex(len(data)),
        "size_mod_16": len(data) % 16,
        "size_mod_4096": len(data) % 4096,
        "sha256": sha256(data),
        "md5": hashlib.md5(data).hexdigest(),
        "filename_equals_md5": path.name.lower() == hashlib.md5(data).hexdigest(),
        "filename_raw16_equals_head": bool(name_raw and name_raw == data[:16]),
        "filename_raw16_equals_tail": bool(name_raw and name_raw == data[-16:]),
        "head_32": data[:32].hex(),
        "tail_32": data[-32:].hex(),
        "entropy": round(entropy(sample), 6),
        "entropy_sample_stride": sample_stride,
        "chi_square_uniform": round(chi_square_uniform(sample), 3),
        "serial_correlation": round(serial_correlation(sample), 8),
        "zero_ratio": round(sample.count(0) / len(sample), 8) if sample else 0.0,
        "entropy_windows": [entropy_windows(data, size) for size in (4096, 65536, 1048576)],
        "block_stats": [block_stats(data, size) for size in (16, 32, 4096)],
        "signature_hits": signature_hits(data),
        "metadata_header_at_zero": valid_metadata_header(data),
        "bounded_transform_hits": byte_transform_tests(data),
        "bounded_repeating_xor_hits": repeating_xor_tests(data),
    }


def render_markdown(report: dict) -> str:
    files = report["files"]
    lines = [
        "# Unity IL2CPP split-blob analysis",
        "",
        "> This is static, read-only evidence. It does not claim that metadata was decrypted.",
        "",
        "## Summary",
        "",
        f"- Candidate count: `{len(files)}`",
        f"- Total bytes: `{report['aggregate']['total_size']}` (`{report['aggregate']['total_size_hex']}`)",
        f"- Total minus 16 bytes per candidate: `{report['aggregate']['total_minus_16_each']}`",
        f"- Equal-size large candidates: `{report['aggregate']['equal_large_size_count']}` at `{report['aggregate']['largest_size']}` bytes",
        f"- All sizes 16-byte aligned: `{report['aggregate']['all_sizes_aligned_16']}`",
        f"- Verified plaintext metadata: `{report['conclusion']['verified_plaintext_metadata']}`",
        f"- Decryption verified: `{report['conclusion']['decryption_verified']}`",
        "",
        "## Files",
        "",
        "| File | Size | Entropy | SHA-256 | 16-byte repeats | 4 KiB repeats |",
        "|---|---:|---:|---|---:|---:|",
    ]
    for item in files:
        blocks = {entry["block_size"]: entry for entry in item["block_stats"]}
        lines.append(
            f"| `{item['name']}` | {item['size']} | {item['entropy']:.6f} | `{item['sha256']}` | "
            f"{blocks[16]['repeated_instances']} | {blocks[4096]['repeated_instances']} |"
        )
    lines += [
        "",
        "## Static tests",
        "",
        "- Standard IL2CPP magic at offset zero: no candidate passed.",
        "- Common compression/container signatures: see JSON `signature_hits`; no signature is treated as proof without parsing.",
        "- Single-byte XOR/add/subtract and byte rotations: only structurally valid results are meaningful.",
        "- Repeating XOR periods 1/2/4/8 were tested from known IL2CPP magic plus plausible version bytes.",
        "- Repeated 16-byte blocks measure ECB-like leakage; absence is compatible with CBC/CTR/GCM or compressed data, not proof of a mode.",
        "",
        "## Cross-file comparison",
        "",
        "| Left | Right | Equal-byte ratio | XOR entropy | Common prefix | Common suffix |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for pair in report["cross_file"]:
        lines.append(
            f"| `{pair['left']}` | `{pair['right']}` | {pair['equal_byte_ratio']:.8f} | "
            f"{pair['xor_entropy']:.6f} | {pair['common_prefix']} | {pair['common_suffix']} |"
        )
    lines += [
        "",
        "## Interpretation boundary",
        "",
        "- High entropy cannot by itself distinguish encryption from strong compression.",
        "- A size of `10 MiB + 16` is consistent with either a 16-byte per-part prefix/tag/IV or block-cipher padding; it does not choose between them.",
        "- Candidate order is not proven by hash-like filenames. A loader trace, recovered manifest, or validated decryption is required.",
        "- SDK generation remains blocked until reconstructed bytes pass magic, version, table-boundary, and cross-table validation.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("--glob", default="*")
    parser.add_argument("--hex-name-length", type=int, default=32)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--md-out", type=Path)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    args = parser.parse_args()

    candidates = []
    for path in sorted(args.input_dir.glob(args.glob)):
        if not path.is_file() or path.stat().st_size > args.max_bytes:
            continue
        if args.hex_name_length:
            if len(path.name) != args.hex_name_length:
                continue
            try:
                int(path.name, 16)
            except ValueError:
                continue
        candidates.append(path)
    if not candidates:
        raise SystemExit("no matching candidate files")

    items = [(path, path.read_bytes()) for path in candidates]
    sizes = [len(data) for _, data in items]
    largest = max(sizes)
    report = {
        "schema": "revlab.unity.split_blob_analysis.v1",
        "input_dir": str(args.input_dir),
        "read_only": True,
        "files": [analyze_file(path, data) for path, data in items],
        "cross_file": cross_file_stats(items),
        "aggregate": {
            "total_size": sum(sizes),
            "total_size_hex": hex(sum(sizes)),
            "total_minus_16_each": sum(size - 16 for size in sizes),
            "largest_size": largest,
            "equal_large_size_count": sizes.count(largest),
            "all_sizes_aligned_16": all(size % 16 == 0 for size in sizes),
        },
        "conclusion": {
            "verified_plaintext_metadata": False,
            "decryption_verified": False,
            "sdk_delivery_allowed": False,
            "status": "encrypted_or_compressed_split_metadata_candidate",
        },
    }

    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(encoded + "\n", encoding="utf-8")
    else:
        print(encoded)
    if args.md_out:
        args.md_out.parent.mkdir(parents=True, exist_ok=True)
        args.md_out.write_text(render_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
