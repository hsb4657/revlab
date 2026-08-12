"""Strict recovery recipes for split/encrypted IL2CPP metadata containers.

Recipes are intentionally fingerprinted and fail closed.  A container is not
accepted merely because it has high entropy or 32-hex filenames: the descriptor
layout, every part, the reconstructed table map and known metadata strings must
all validate before the output can be passed to an SDK exporter.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


STANDARD_METADATA_MAGIC = 0xFAB11BAF
DESCRIPTOR_MAGIC = 0xAF1BB1FA
DESCRIPTOR_VERSION = 1
GUNFIRE_SPLIT_AES_ECB_V1 = "gunfire_split_aes_ecb_v1"
_GUNFIRE_MASTER_KEY = bytes.fromhex("2b7e151628aed2a6abf7258809cf5f4c")
_DESCRIPTOR_RELATIVE_PATH = Path("Resources") / "Firmware.dll-resources.dat"
_REQUIRED_STRING_ANCHORS = (
    b"mscorlib.dll",
    b"<Module>",
    b"System.Object",
    b"Assembly-CSharp",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError(f"invalid AES key length: {len(key)}")
    if len(ciphertext) % 16:
        raise ValueError(f"AES-ECB input is not block aligned: {len(ciphertext)}")
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _u32(data: bytes | bytearray, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError(f"u32 read outside buffer at 0x{offset:x}")
    return struct.unpack_from("<I", data, offset)[0]


def _checked_slice(data: bytes | bytearray, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(
            f"{label} outside buffer: offset=0x{offset:x}, size=0x{size:x}, "
            f"buffer=0x{len(data):x}"
        )
    return bytes(data[offset:offset + size])


def _find_il2cpp_data_root(target_path: str | Path) -> Path | None:
    target = Path(target_path).expanduser()
    if target.is_file():
        target = target.parent
    if target.name.lower() == "il2cpp_data" and target.is_dir():
        return target.resolve()
    if not target.is_dir():
        return None
    candidates = sorted(
        (item for item in target.rglob("il2cpp_data") if item.is_dir()),
        key=lambda item: (len(item.parts), str(item).lower()),
    )
    for candidate in candidates:
        if (candidate / _DESCRIPTOR_RELATIVE_PATH).is_file():
            return candidate.resolve()
    return None


def _parse_descriptor(plaintext: bytes) -> dict:
    if len(plaintext) < 0x3C:
        raise ValueError("descriptor is smaller than its fixed header")
    fields = {
        "magic": _u32(plaintext, 0x00),
        "version": _u32(plaintext, 0x04),
        "flags": _u32(plaintext, 0x08),
        "fixed_header_size": _u32(plaintext, 0x0C),
        "logical_metadata_size": _u32(plaintext, 0x10),
        "allocated_metadata_size": _u32(plaintext, 0x14),
        "part_count": _u32(plaintext, 0x18),
        "name_table_offset": _u32(plaintext, 0x1C),
        "name_table_size": _u32(plaintext, 0x20),
        "key_table_offset": _u32(plaintext, 0x24),
        "key_table_size": _u32(plaintext, 0x28),
        "part_table_offset": _u32(plaintext, 0x2C),
        "part_table_size": _u32(plaintext, 0x30),
        "metadata_header_offset": _u32(plaintext, 0x34),
        "metadata_header_size": _u32(plaintext, 0x38),
    }
    if fields["magic"] != DESCRIPTOR_MAGIC:
        raise ValueError(f"unexpected descriptor magic: 0x{fields['magic']:08x}")
    if fields["version"] != DESCRIPTOR_VERSION:
        raise ValueError(f"unsupported descriptor version: {fields['version']}")
    if fields["fixed_header_size"] != 0x3C:
        raise ValueError("descriptor fixed header size is not 0x3c")
    if fields["part_count"] == 0 or fields["part_count"] > 1024:
        raise ValueError(f"implausible part count: {fields['part_count']}")
    if fields["part_table_size"] != fields["part_count"] * 0x14:
        raise ValueError("part table size does not match 20-byte records")
    if fields["allocated_metadata_size"] % 16:
        raise ValueError("allocated metadata size is not block aligned")
    if not (
        fields["logical_metadata_size"]
        <= fields["allocated_metadata_size"]
        < fields["logical_metadata_size"] + 16
    ):
        raise ValueError("logical/allocation metadata size relation is invalid")

    for prefix in ("name_table", "key_table", "part_table", "metadata_header"):
        _checked_slice(
            plaintext,
            fields[f"{prefix}_offset"],
            fields[f"{prefix}_size"],
            prefix,
        )

    records = []
    for index in range(fields["part_count"]):
        record_offset = fields["part_table_offset"] + index * 0x14
        encrypted_size, name_offset, name_size, key_offset, key_size = struct.unpack_from(
            "<IIIII", plaintext, record_offset
        )
        name_bytes = _checked_slice(
            plaintext,
            fields["name_table_offset"] + name_offset,
            name_size,
            f"part[{index}] name",
        )
        key = _checked_slice(
            plaintext,
            fields["key_table_offset"] + key_offset,
            key_size,
            f"part[{index}] key",
        )
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError(f"part[{index}] name is not ASCII") from error
        if not name or Path(name).name != name or "/" in name or "\\" in name:
            raise ValueError(f"unsafe part filename: {name!r}")
        if encrypted_size == 0 or encrypted_size % 16:
            raise ValueError(f"part[{index}] encrypted size is not block aligned")
        if key_size != 16:
            raise ValueError(f"part[{index}] key size is not AES-128")
        records.append({
            "index": index,
            "encrypted_size": encrypted_size,
            "name": name,
            "key": key,
        })

    if sum(item["encrypted_size"] for item in records) != fields["allocated_metadata_size"]:
        raise ValueError("sum of part sizes does not match allocated metadata size")
    fields["metadata_header"] = _checked_slice(
        plaintext,
        fields["metadata_header_offset"],
        fields["metadata_header_size"],
        "metadata header",
    )
    fields["records"] = records
    return fields


def _descriptor(root: Path) -> tuple[Path, bytes, bytes, dict]:
    descriptor_path = root / _DESCRIPTOR_RELATIVE_PATH
    ciphertext = descriptor_path.read_bytes()
    plaintext = _decrypt_ecb(ciphertext, _GUNFIRE_MASTER_KEY)
    return descriptor_path, ciphertext, plaintext, _parse_descriptor(plaintext)


def detect_recipe(target_path: str | Path) -> dict:
    """Detect a supported split container without accepting weak heuristics."""
    root = _find_il2cpp_data_root(target_path)
    if root is None:
        return {
            "supported": False,
            "recipe": "",
            "status": "descriptor_missing",
            "il2cpp_data_root": "",
            "reason": "Firmware.dll-resources.dat was not found under an il2cpp_data directory",
        }
    descriptor_path = root / _DESCRIPTOR_RELATIVE_PATH
    try:
        _, ciphertext, plaintext, descriptor = _descriptor(root)
        part_evidence = []
        for record in descriptor["records"]:
            part_path = root / record["name"]
            expected = record["encrypted_size"] + 16
            actual = part_path.stat().st_size if part_path.is_file() else -1
            if actual != expected:
                raise ValueError(
                    f"{record['name']} size mismatch: expected 0x{expected:x}, got 0x{actual:x}"
                )
            part_evidence.append({
                "index": record["index"],
                "name": record["name"],
                "path": str(part_path),
                "expected_file_size": expected,
                "actual_file_size": actual,
            })
    except (OSError, ValueError) as exc:
        return {
            "supported": False,
            "recipe": "",
            "status": "unsupported_custom_metadata",
            "il2cpp_data_root": str(root),
            "descriptor_path": str(descriptor_path),
            "reason": str(exc),
        }
    return {
        "supported": True,
        "recipe": GUNFIRE_SPLIT_AES_ECB_V1,
        "status": "supported_encrypted_container",
        "il2cpp_data_root": str(root),
        "descriptor_path": str(descriptor_path),
        "descriptor_sha256": _sha256(ciphertext),
        "descriptor_plaintext_sha256": _sha256(plaintext),
        "part_count": descriptor["part_count"],
        "logical_metadata_size": descriptor["logical_metadata_size"],
        "allocated_metadata_size": descriptor["allocated_metadata_size"],
        "metadata_header_size": descriptor["metadata_header_size"],
        "parts": part_evidence,
    }


def _validate_metadata(metadata: bytes, header_size: int) -> dict:
    if len(metadata) < header_size or header_size < 8 or header_size % 8:
        raise ValueError("invalid metadata header size")
    magic, version = struct.unpack_from("<II", metadata, 0)
    if magic != STANDARD_METADATA_MAGIC:
        raise ValueError(f"invalid normalized metadata magic: 0x{magic:08x}")
    if version < 16 or version > 40:
        raise ValueError(f"implausible metadata version: {version}")

    regions = []
    for field_offset in range(8, header_size, 8):
        offset, size = struct.unpack_from("<II", metadata, field_offset)
        if offset > len(metadata) or size > len(metadata) or offset + size > len(metadata):
            raise ValueError(
                f"metadata region at header+0x{field_offset:x} is outside file: "
                f"offset=0x{offset:x}, size=0x{size:x}, file=0x{len(metadata):x}"
            )
        if size and offset < header_size:
            raise ValueError(f"metadata region at header+0x{field_offset:x} overlaps the header")
        if size:
            regions.append({
                "header_field_offset": field_offset,
                "offset": offset,
                "size": size,
                "end": offset + size,
            })

    ordered = sorted(regions, key=lambda item: (item["offset"], item["end"]))
    overlaps = []
    previous = None
    for region in ordered:
        if previous and region["offset"] < previous["end"]:
            overlaps.append({
                "left_header_field_offset": previous["header_field_offset"],
                "right_header_field_offset": region["header_field_offset"],
                "overlap_start": region["offset"],
                "overlap_end": min(previous["end"], region["end"]),
            })
        if previous is None or region["end"] > previous["end"]:
            previous = region
    return {
        "magic": f"0x{magic:08x}",
        "version": version,
        "file_size": len(metadata),
        "header_size": header_size,
        "region_count": len(regions),
        "regions": regions,
        "overlap_count": len(overlaps),
        "overlaps": overlaps,
        "max_region_end": max((item["end"] for item in regions), default=header_size),
    }


def _normalize_gunfire_tables(metadata: bytes, header_size: int) -> tuple[bytes, dict]:
    normalized = bytearray(metadata)
    swaps = []
    for left, right in ((0x08, 0x30), (0x50, 0x78)):
        left_offset = _u32(normalized, left)
        right_offset = _u32(normalized, right)
        struct.pack_into("<I", normalized, left, right_offset)
        struct.pack_into("<I", normalized, right, left_offset)
        swaps.append({
            "left_header_offset": left,
            "right_header_offset": right,
            "left_original": left_offset,
            "right_original": right_offset,
        })

    xor_regions = []
    # Resolve these regions from the normalized header instead of relying on
    # build-specific absolute offsets: stringLiteralData is pair 1 and string
    # data is pair 2 in the standard metadata header.
    for field_offset, label in ((0x10, "string_literal_data"), (0x18, "string_data")):
        offset = _u32(normalized, field_offset)
        size = _u32(normalized, field_offset + 4)
        _checked_slice(normalized, offset, size, label)
        normalized[offset:offset + size] = bytes(value ^ 0x41 for value in normalized[offset:offset + size])
        xor_regions.append({"label": label, "offset": offset, "size": size, "xor": "0x41"})

    result = bytes(normalized)
    validation = _validate_metadata(result, header_size)
    anchors = {needle.decode("ascii"): result.find(needle) for needle in _REQUIRED_STRING_ANCHORS}
    validation["string_anchors"] = anchors
    validation["normalization"] = {"offset_swaps": swaps, "xor_regions": xor_regions}
    if validation["overlap_count"]:
        raise ValueError(f"normalized metadata contains {validation['overlap_count']} overlapping regions")
    if validation["max_region_end"] != len(result):
        raise ValueError("normalized metadata table map does not end at the file boundary")
    if any(value < 0 for value in anchors.values()):
        raise ValueError(f"normalized metadata is missing string anchors: {anchors}")
    return result, validation


def recover(target_path: str | Path, output_dir: str | Path, recipe: str = GUNFIRE_SPLIT_AES_ECB_V1) -> dict:
    detection = detect_recipe(target_path)
    if not detection.get("supported") or detection.get("recipe") != recipe:
        raise ValueError(detection.get("reason") or "no supported split metadata recipe matched")
    root = Path(detection["il2cpp_data_root"])
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    descriptor_path, ciphertext, plaintext, descriptor = _descriptor(root)

    manifest = {
        "format": "revlab.unity.split-metadata-recovery.v1",
        "recipe": recipe,
        "source_root": str(root),
        "descriptor": {
            "path": str(descriptor_path),
            "size": len(ciphertext),
            "sha256": _sha256(ciphertext),
            "plaintext_sha256": _sha256(plaintext),
            "magic": f"0x{descriptor['magic']:08x}",
            "version": descriptor["version"],
            "part_count": descriptor["part_count"],
            "logical_metadata_size": descriptor["logical_metadata_size"],
            "allocated_metadata_size": descriptor["allocated_metadata_size"],
            "metadata_header_size": descriptor["metadata_header_size"],
        },
        "parts": [],
    }

    plaintext_parts = []
    for record in descriptor["records"]:
        part_path = root / record["name"]
        part_ciphertext = part_path.read_bytes()
        expected_file_size = record["encrypted_size"] + 16
        if len(part_ciphertext) != expected_file_size:
            raise ValueError(
                f"{record['name']} size mismatch: expected 0x{expected_file_size:x}, "
                f"got 0x{len(part_ciphertext):x}"
            )
        part_plaintext = _decrypt_ecb(part_ciphertext[:record["encrypted_size"]], record["key"])
        plaintext_parts.append(part_plaintext)
        manifest["parts"].append({
            "index": record["index"],
            "name": record["name"],
            "path": str(part_path),
            "file_size": len(part_ciphertext),
            "encrypted_size": record["encrypted_size"],
            "trailer_size": len(part_ciphertext) - record["encrypted_size"],
            "ciphertext_sha256": _sha256(part_ciphertext),
            "decrypted_sha256": _sha256(part_plaintext),
            "key_sha256": _sha256(record["key"]),
        })

    allocation = b"".join(plaintext_parts)
    if len(allocation) != descriptor["allocated_metadata_size"]:
        raise ValueError("reconstructed allocation size mismatch")
    metadata = bytearray(allocation[:descriptor["logical_metadata_size"]])
    header = bytearray(descriptor["metadata_header"])
    if len(header) > len(metadata):
        raise ValueError("metadata header is larger than reconstructed metadata")
    custom_magic, version = struct.unpack_from("<II", header, 0)
    struct.pack_into("<I", header, 0, STANDARD_METADATA_MAGIC)
    metadata[:len(header)] = header
    metadata_bytes, validation = _normalize_gunfire_tables(bytes(metadata), len(header))

    output_path = output / "global-metadata.dat"
    output_path.write_bytes(metadata_bytes)
    manifest["output"] = {
        "path": str(output_path),
        "size": len(metadata_bytes),
        "sha256": _sha256(metadata_bytes),
        "original_custom_magic": f"0x{custom_magic:08x}",
        "normalized_magic": f"0x{STANDARD_METADATA_MAGIC:08x}",
        "version": version,
    }
    manifest["validation"] = validation
    manifest_path = output / "recovery_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    return manifest

