"""Structured UE layout and FName candidate analysis.

This module deliberately separates a *candidate* layout from a verified one.
The supplied offset packs are useful starting points, but a static executable
cannot prove that a particular object instance uses an offset.  Callers can
pass runtime observations later to promote individual candidates to
``confirmed``.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

from .versions import get_version_layout


VALIDATION_CONFIRMED = "confirmed"
VALIDATION_CANDIDATE = "candidate"
VALIDATION_UNCONFIRMED = "unconfirmed"


def _offset(value: int) -> dict[str, Any]:
    return {"value": value, "hex": hex(value)}


def _profile(
    name: str,
    *,
    stride: int,
    fuobject_item_size: int,
    fname_number: int,
    fname_entry: dict[str, int],
    structures: dict[str, dict[str, int]],
    note: str,
) -> dict[str, Any]:
    """Build a serializable profile from the supplied offset pack."""
    return {
        "id": name,
        "name": name,
        "source": "user-supplied layout profile",
        "note": note,
        "fname": {
            "stride": stride,
            "number": _offset(fname_number),
            "entry": {field: _offset(value) for field, value in fname_entry.items()},
        },
        "fuobject_item": {"size": _offset(fuobject_item_size)},
        "structures": {
            structure: {field: _offset(value) for field, value in fields.items()}
            for structure, fields in structures.items()
        },
    }


# The values below mirror the six profiles supplied with the task.  Values are
# held as integers internally in the source pack and emitted with both decimal
# and hexadecimal representations so the UI can show either form without
# losing machine-readable offsets.
UE_LAYOUT_PROFILES: dict[str, dict[str, Any]] = {
    "DeltaForceClient": _profile(
        "DeltaForceClient",
        stride=2,
        fuobject_item_size=0x18,
        fname_number=4,
        fname_entry={"Info": 0, "WideBit": 0, "LenBit": 6, "HeaderSize": 2},
        structures={
            "UObject": {"Index": 0x24, "Class": 0x8, "Name": 0x1C, "Outer": 0x10},
            "UField": {"Next": 0x28},
            "UStruct": {
                "SuperStruct": 0x48,
                "Children": 0x48,
                "ChildProperties": 0x70,
                "PropertiesSize": 0x40,
            },
            "UEnum": {"Names": 0x40},
            "UFunction": {"FunctionFlags": 0xC0, "Func": 0xF0},
            "FField": {"Class": 0x20, "Next": 0x18, "Name": 0x28},
            "FProperty": {
                "ArrayDim": 0x3C,
                "ElementSize": 0x40,
                "PropertyFlags": 0x4C,
                "Offset": 0x54,
                "Size": 0x90,
            },
            "UProperty": {"ArrayDim": 0, "ElementSize": 0, "PropertyFlags": 0, "Offset": 0, "Size": 0},
        },
        note="Game-specific candidate; ChildProperties is the primary modern property chain.",
    ),
    "Default": _profile(
        "Default",
        stride=2,
        fuobject_item_size=0x18,
        fname_number=4,
        fname_entry={"Info": 0, "WideBit": 0, "LenBit": 6, "HeaderSize": 2},
        structures={
            "UObject": {"Index": 0xC, "Class": 0x10, "Name": 0x18, "Outer": 0x20},
            "UField": {"Next": 0x28},
            "UStruct": {
                "SuperStruct": 0x40,
                "Children": 0x48,
                "ChildProperties": 0x50,
                "PropertiesSize": 0x58,
            },
            "UEnum": {"Names": 0x40},
            "UFunction": {"FunctionFlags": 0xB0, "Func": 0xD8},
            "FField": {"Class": 0x8, "Next": 0x20, "Name": 0x28},
            "FProperty": {
                "ArrayDim": 0x38,
                "ElementSize": 0x3C,
                "PropertyFlags": 0x40,
                "Offset": 0x4C,
                "Size": 0x78,
            },
            "UProperty": {"ArrayDim": 0, "ElementSize": 0, "PropertyFlags": 0, "Offset": 0, "Size": 0},
        },
        note="Generic modern UE candidate profile.",
    ),
    "DeadByDaylight": _profile(
        "DeadByDaylight",
        stride=4,
        fuobject_item_size=0x18,
        fname_number=8,
        fname_entry={"Info": 4, "WideBit": 0, "LenBit": 1, "HeaderSize": 6},
        structures={
            "UObject": {"Index": 0xC, "Class": 0x10, "Name": 0x18, "Outer": 0x28},
            "UField": {"Next": 0x30},
            "UStruct": {
                "SuperStruct": 0x48,
                "Children": 0x50,
                "ChildProperties": 0x58,
                "PropertiesSize": 0x60,
            },
            "UEnum": {"Names": 0x48},
            "UFunction": {"FunctionFlags": 0xB8, "Func": 0xE0},
            "FField": {"Class": 0x8, "Next": 0x20, "Name": 0x28},
            "FProperty": {
                "ArrayDim": 0x38,
                "ElementSize": 0x3C,
                "PropertyFlags": 0x40,
                "Offset": 0x4C,
                "Size": 0x80,
            },
            "UProperty": {"ArrayDim": 0, "ElementSize": 0, "PropertyFlags": 0, "Offset": 0, "Size": 0},
        },
        note="Game-specific candidate with a 4-byte FName entry stride.",
    ),
    "Scavengers": _profile(
        "Scavengers",
        stride=2,
        fuobject_item_size=0x18,
        fname_number=4,
        fname_entry={"Info": 0, "WideBit": 0, "LenBit": 6, "HeaderSize": 2},
        structures={
            "UObject": {"Index": 0xC, "Class": 0x10, "Name": 0x18, "Outer": 0x20},
            "UField": {"Next": 0x28},
            "UStruct": {
                "SuperStruct": 0x40,
                "Children": 0x48,
                "ChildProperties": 0x50,
                "PropertiesSize": 0x58,
            },
            "UEnum": {"Names": 0x40},
            "UFunction": {"FunctionFlags": 0xB0, "Func": 0xE0},
            "FField": {"Class": 0x8, "Next": 0x20, "Name": 0x28},
            "FProperty": {
                "ArrayDim": 0x38,
                "ElementSize": 0x3C,
                "PropertyFlags": 0x40,
                "Offset": 0x4C,
                "Size": 0x78,
            },
            "UProperty": {"ArrayDim": 0, "ElementSize": 0, "PropertyFlags": 0, "Offset": 0, "Size": 0},
        },
        note="Game-specific candidate; Func is FunctionFlags + 0x30.",
    ),
    "Brickadia": _profile(
        "Brickadia",
        stride=2,
        fuobject_item_size=0x20,
        fname_number=4,
        fname_entry={"Info": 0, "WideBit": 0, "LenBit": 6, "HeaderSize": 2},
        structures={
            "UObject": {"Index": 0xC, "Class": 0x10, "Name": 0x18, "Outer": 0x20},
            "UField": {"Next": 0x28},
            "UStruct": {
                "SuperStruct": 0x40,
                "Children": 0x48,
                "ChildProperties": 0x50,
                "PropertiesSize": 0x58,
            },
            "UEnum": {"Names": 0x40},
            "UFunction": {"FunctionFlags": 0xB0, "Func": 0xD8},
            "FField": {"Class": 0x8, "Next": 0x20, "Name": 0x28},
            "FProperty": {
                "ArrayDim": 0x38,
                "ElementSize": 0x3C,
                "PropertyFlags": 0x40,
                "Offset": 0x4C,
                "Size": 0x78,
            },
            "UProperty": {"ArrayDim": 0, "ElementSize": 0, "PropertyFlags": 0, "Offset": 0, "Size": 0},
        },
        note="Game-specific candidate with a 0x20 FUObjectItem.",
    ),
    "Core": _profile(
        "Core",
        stride=4,
        fuobject_item_size=0x18,
        fname_number=8,
        fname_entry={"Info": 4, "WideBit": 0, "LenBit": 1, "HeaderSize": 6},
        structures={
            "UObject": {"Index": 0xC, "Class": 0x10, "Name": 0x18, "Outer": 0x28},
            "UField": {"Next": 0x30},
            "UStruct": {
                "SuperStruct": 0x48,
                "Children": 0x50,
                "ChildProperties": 0x58,
                "PropertiesSize": 0x60,
            },
            "UEnum": {"Names": 0x48},
            "UFunction": {"FunctionFlags": 0xB8, "Func": 0xE0},
            "FField": {"Class": 0x8, "Next": 0x20, "Name": 0x28},
            "FProperty": {
                "ArrayDim": 0x38,
                "ElementSize": 0x3C,
                "PropertyFlags": 0x40,
                "Offset": 0x4C,
                "Size": 0x80,
            },
            "UProperty": {"ArrayDim": 0, "ElementSize": 0, "PropertyFlags": 0, "Offset": 0, "Size": 0},
        },
        note="Game-specific candidate with 4-byte FName entry stride.",
    ),
}


def list_layout_profiles() -> list[dict[str, Any]]:
    """Return independent copies so API clients cannot mutate the registry."""
    return [deepcopy(UE_LAYOUT_PROFILES[name]) for name in UE_LAYOUT_PROFILES]


def version_baseline_profile(engine_version: str = "", engine_family: str = "") -> dict[str, Any]:
    """Return the conservative reflection baseline for an engine generation.

    Game-specific profiles are never selected from incidental strings in the
    executable.  They require explicit runtime observations.  Modern UE4 and
    UE5 builds therefore start from the generic Default profile and retain a
    candidate validation state until a live object walk proves the offsets.
    """
    version = str(engine_version or "").strip()
    family = str(engine_family or "").strip().upper()
    profile_name = "Default"
    profile = deepcopy(UE_LAYOUT_PROFILES[profile_name])
    generation = "UE5" if version.startswith("5.") or family == "UE5" else (
        "UE4" if version.startswith("4.") or family == "UE4" else "unknown"
    )
    profile.update({
        "engine_generation": generation,
        "engine_version": version,
        "confidence": 55 if generation != "unknown" else 35,
        "validation_state": VALIDATION_CANDIDATE,
        "selection_state": "version_baseline_candidate",
        "selection_reason": (
            f"{generation} generic reflection baseline; runtime UObject/FField traversal is required"
            if generation != "unknown"
            else "Unknown engine minor version; using the generic modern baseline pending runtime validation"
        ),
    })
    return profile


def get_layout_profile(name: str) -> dict[str, Any] | None:
    profile = UE_LAYOUT_PROFILES.get(name)
    return deepcopy(profile) if profile else None


def _contains_marker(data: bytes, profile_name: str) -> bool:
    lowered = data.lower()
    return profile_name.encode("ascii").lower() in lowered


def rank_layout_profiles(
    data: bytes,
    *,
    engine_version: str = "",
    engine_family: str = "",
    fname_model: str = "",
    runtime_observations: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Rank all known packs without treating a rank as proof.

    A static profile-name string, a supplied runtime profile identity, and a
    matching FName model are evidence.  Offsets remain candidates until the
    memory validator observes expected pointer/string invariants.
    """
    runtime_observations = runtime_observations or {}
    runtime_profile = str(runtime_observations.get("profile") or "")
    version_layout = get_version_layout(engine_version) if engine_version else {}
    ranked: list[dict[str, Any]] = []
    for profile in list_layout_profiles():
        score = 15
        evidence = [
            {
                "kind": "profile_registry",
                "detail": "Offset pack is registered as a candidate.",
                "weight": 15,
            }
        ]
        profile_stride = profile["fname"]["stride"]
        if fname_model == "pool":
            score += 10
            evidence.append(
                {
                    "kind": "fname_model",
                    "detail": "FNamePool model is compatible with this profile.",
                    "weight": 10,
                }
            )
        if engine_family in {"4.x", "5.x"}:
            score += 5
            evidence.append(
                {
                    "kind": "engine_family",
                    "detail": f"Detected UE engine family: {engine_family}.",
                    "weight": 5,
                }
            )
        if engine_version.startswith("5.") and version_layout.get("gobjects"):
            score += 8
            evidence.append(
                {
                    "kind": "version_layout",
                    "detail": f"UE {engine_version} uses the version-aware FNamePool/UObject-array candidate layout.",
                    "weight": 8,
                }
            )
        if _contains_marker(data, profile["name"]):
            score += 35
            evidence.append(
                {
                    "kind": "binary_string",
                    "detail": f"Profile name {profile['name']} appears in the sample.",
                    "weight": 35,
                }
            )
        state = VALIDATION_CANDIDATE
        if runtime_profile and runtime_profile == profile["name"]:
            score += 35
            state = VALIDATION_CONFIRMED
            evidence.append(
                {
                    "kind": "runtime_profile",
                    "detail": "Runtime validator selected this profile.",
                    "weight": 35,
                }
            )
        profile["score"] = min(score, 100)
        profile["confidence"] = min(score, 100)
        profile["validation_state"] = state
        profile["evidence"] = evidence
        profile["engine_version"] = engine_version
        profile["fname_stride"] = profile_stride
        profile["version_layout"] = deepcopy(version_layout) if version_layout else None
        ranked.append(profile)
    return sorted(ranked, key=lambda item: (-item["score"], item["name"]))


def _global_state(global_candidate: dict[str, Any] | None, label: str) -> dict[str, Any]:
    """Normalize a global address result into an explicit validation record."""
    if not global_candidate or global_candidate.get("target_va") is None:
        is_name_global = label.lower().startswith("gnames") or label.lower().startswith("gname")
        return {
            "name": label,
            "target_va": None,
            "status": VALIDATION_UNCONFIRMED,
            "validation_state": VALIDATION_UNCONFIRMED,
            "confidence": 0,
            "score": 0,
            "evidence_status": "not_found",
            "evidence": [],
            "reason": f"No static {label} signature candidate was found.",
            "plaintext_candidate": {
                "kind": "name" if is_name_global else "pointer",
                "status": VALIDATION_UNCONFIRMED,
                "validation_state": VALIDATION_UNCONFIRMED,
                "address": None,
                "decoded_names": [],
                "reason": (
                    "A live FNamePool/TNameEntryArray read is required before any plaintext name can be claimed."
                    if is_name_global
                    else "No static global candidate; a runtime module/object scan is required."
                ),
            },
            "required_runtime_evidence": [
                "A readable target address in the loaded module.",
                "Structure invariants matching the selected engine/layout profile.",
                "At least two decoded known names for FNamePool candidates.",
            ],
        }
    evidence = list(global_candidate.get("evidence") or [])
    if not evidence:
        evidence.append(
            {
                "kind": "static_signature",
                "detail": global_candidate.get("name", "UE signature"),
                "match_offset": global_candidate.get("match_offset"),
            }
        )
    is_name_global = label.lower().startswith("gnames") or label.lower().startswith("gname")
    record = {
        **global_candidate,
        "status": global_candidate.get("status") or VALIDATION_CANDIDATE,
        "validation_state": global_candidate.get("validation_state") or VALIDATION_CANDIDATE,
        "confidence": int(global_candidate.get("confidence") or 55),
        "score": int(global_candidate.get("score") or global_candidate.get("confidence") or 55),
        "evidence_status": (
            "runtime_validated"
            if (global_candidate.get("validation_state") or global_candidate.get("status")) == VALIDATION_CONFIRMED
            else "static_candidate"
        ),
        "evidence": evidence,
        "required_runtime_evidence": global_candidate.get("required_runtime_evidence")
        or [
            "Validate the pointed-to memory after the module is loaded.",
            "Validate expected structure fields and pointer ranges.",
        ],
    }
    record["plaintext_candidate"] = {
        "kind": "name" if is_name_global else "pointer",
        "status": record["validation_state"],
        "validation_state": record["validation_state"],
        "address": global_candidate.get("target_va"),
        "decoded_names": [],
        "reason": (
            "Static RIP-relative target only; plaintext names require a runtime/memory read."
            if is_name_global
            else "Static global pointer candidate; pointed-to object bytes were not read."
        ),
    }
    return record


def describe_global_candidate(global_candidate: dict[str, Any] | None, label: str) -> dict[str, Any]:
    """Expose a normalized global address record to the analyzer and API."""
    return _global_state(global_candidate, label)


def _xor_immediate_candidates(blob: bytes, base_offset: int = 0) -> list[dict[str, Any]]:
    """Find conservative x86 immediate-XOR candidates in a bounded window."""
    out: list[dict[str, Any]] = []
    for index, opcode in enumerate(blob):
        key = None
        width = 1
        encoding = ""
        if opcode in (0x34, 0x35) and index + 1 < len(blob):
            # xor AL/EAX, imm8/imm32.  The EAX form is retained as a key hint;
            # it is not interpreted as proof of a name decoder.
            key = int.from_bytes(blob[index + 1:index + (5 if opcode == 0x35 else 2)], "little")
            width = 4 if opcode == 0x35 else 1
            encoding = "xor_accumulator_immediate"
        elif opcode in (0x80, 0x81, 0x83) and index + 2 < len(blob):
            modrm = blob[index + 1]
            # /6 is the XOR operation for the group-1 immediate encodings.
            if ((modrm >> 3) & 0x7) == 0x6:
                width = 4 if opcode == 0x81 else 1
                end = index + 2 + width
                if end <= len(blob):
                    key = int.from_bytes(blob[index + 2:end], "little")
                    encoding = "xor_group_immediate"
        if key is None:
            continue
        out.append(
            {
                "offset": base_offset + index,
                "opcode": f"{opcode:02x}",
                "key": key,
                "key_hex": hex(key),
                "width": width,
                "encoding": encoding,
                "validation_state": VALIDATION_CANDIDATE,
                "confidence": 35,
            }
        )
        if len(out) >= 32:
            break
    return out


def analyze_get_name_xor(
    data: bytes,
    *,
    runtime_observations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect GetName/FName XOR evidence without claiming a decoded key.

    This is intentionally a static triage helper.  It records symbol/string
    markers, nearby immediate-XOR instructions, and printable text windows;
    a runtime observation may promote a specific key and plaintext sample.
    """
    runtime_observations = runtime_observations or {}
    marker_names = (b"GetName", b"GetFName", b"FName::ToString", b"DecryptFName")
    markers: list[dict[str, Any]] = []
    for marker in marker_names:
        start = 0
        while len(markers) < 32:
            index = data.find(marker, start)
            if index < 0:
                break
            markers.append({"name": marker.decode("ascii", "ignore"), "offset": index})
            start = index + 1
    xor_candidates: list[dict[str, Any]] = []
    windows: list[tuple[int, int]] = []
    for marker in markers:
        begin = max(0, marker["offset"] - 512)
        end = min(len(data), marker["offset"] + 512)
        windows.append((begin, end))
        xor_candidates.extend(_xor_immediate_candidates(data[begin:end], begin))
    # If symbols are stripped, inspect a bounded prefix as weak evidence.  Do
    # not scan an entire multi-hundred-MB dump in Python.
    if not markers and len(data):
        xor_candidates.extend(_xor_immediate_candidates(data[: min(len(data), 8 * 1024 * 1024)]))
    dedup: dict[tuple[int, int], dict[str, Any]] = {}
    for candidate in xor_candidates:
        dedup[(candidate["offset"], candidate["key"])] = candidate
    xor_candidates = list(dedup.values())[:32]

    plaintext_candidates: list[dict[str, Any]] = []
    for begin, end in windows:
        window = data[begin:end]
        for match in re.finditer(rb"[ -~]{4,96}", window):
            text = match.group(0).decode("ascii", "ignore").strip()
            if not text or text in {"GetName", "GetFName"}:
                continue
            plaintext_candidates.append(
                {
                    "text": text,
                    "offset": begin + match.start(),
                    "status": VALIDATION_CANDIDATE,
                    "validation_state": VALIDATION_CANDIDATE,
                    "reason": "Printable bytes near a GetName/FName marker; not runtime-decoded.",
                }
            )
            if len(plaintext_candidates) >= 32:
                break
        if len(plaintext_candidates) >= 32:
            break

    runtime = runtime_observations.get("get_name_xor")
    runtime_validated = isinstance(runtime, dict) and bool(runtime.get("validated"))
    if runtime_validated:
        key = runtime.get("key")
        plaintext = runtime.get("plaintext")
        if key is not None:
            xor_candidates.insert(
                0,
                {
                    "offset": runtime.get("offset"),
                    "key": key,
                    "key_hex": hex(key) if isinstance(key, int) else str(key),
                    "encoding": runtime.get("encoding", "runtime_observation"),
                    "validation_state": VALIDATION_CONFIRMED,
                    "confidence": 100,
                    "evidence": ["external_runtime_observations"],
                },
            )
        if plaintext:
            plaintext_candidates.insert(
                0,
                {
                    "text": str(plaintext),
                    "offset": runtime.get("plaintext_offset"),
                    "status": VALIDATION_CONFIRMED,
                    "validation_state": VALIDATION_CONFIRMED,
                    "reason": "External runtime observation supplied a decoded name.",
                },
            )

    if runtime_validated and xor_candidates:
        state = VALIDATION_CONFIRMED
    elif markers and xor_candidates:
        state = VALIDATION_CANDIDATE
    elif markers:
        state = VALIDATION_CANDIDATE
    else:
        state = VALIDATION_UNCONFIRMED
    evidence = []
    if markers:
        evidence.append({"kind": "get_name_marker", "count": len(markers), "markers": markers[:8]})
    if xor_candidates:
        evidence.append({"kind": "xor_instruction", "count": len(xor_candidates), "near_markers": bool(windows)})
    return {
        "status": state,
        "validation_state": state,
        "function_markers": markers,
        "xor_candidates": xor_candidates,
        "key_candidates": [candidate.get("key_hex") for candidate in xor_candidates],
        "plaintext_candidates": plaintext_candidates,
        "evidence": evidence,
        "runtime_validation_required": not runtime_validated,
        "validation_plan": [
            "Locate the GetName/GetFName function in the loaded module.",
            "Trace the XOR candidate through its input and output buffers.",
            "Decode two known names and compare them with the FNamePool entry layout.",
            "Only then promote the key/plaintext record to confirmed.",
        ],
    }


def analyze_fname_algorithm(
    data: bytes,
    *,
    engine_version: str = "",
    engine_family: str = "",
    fname_model: str = "",
    gnames: dict[str, Any] | None = None,
    runtime_observations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return FName/GNames formulas, candidates, and explicit evidence state."""
    runtime_observations = runtime_observations or {}
    gnames_record = _global_state(gnames, "GNames/FNamePool")
    has_pool_marker = any(marker in data for marker in (b"FNamePool", b"FNameEntryId", b"IndexToName"))
    has_direct_marker = b"TNameEntryArray" in data
    has_index_to_name = b"IndexToName" in data

    inferred_model = fname_model
    if not inferred_model:
        inferred_model = "pool" if has_pool_marker or gnames_record["target_va"] is not None else "unknown"

    pool_score = 30
    pool_evidence: list[dict[str, Any]] = []
    if inferred_model == "pool":
        pool_score += 25
        pool_evidence.append({"kind": "version_or_signature", "detail": "FNamePool is indicated by version or signature evidence."})
    if has_pool_marker:
        pool_score += 15
        pool_evidence.append({"kind": "binary_string", "detail": "FNamePool/FNameEntryId marker found."})
    if gnames_record["target_va"] is not None:
        pool_score += 15
        pool_evidence.append({"kind": "global_candidate", "detail": "Static GNames/FNamePool address candidate found."})
    if has_index_to_name:
        pool_score += 8
        pool_evidence.append({"kind": "binary_string", "detail": "IndexToName marker found; encrypted/redirected name path remains possible."})

    direct_score = 15
    direct_evidence: list[dict[str, Any]] = []
    if inferred_model == "direct":
        direct_score += 30
        direct_evidence.append({"kind": "version_or_signature", "detail": "Direct TNameEntryArray model is indicated."})
    if has_direct_marker:
        direct_score += 25
        direct_evidence.append({"kind": "binary_string", "detail": "TNameEntryArray marker found."})

    candidates = [
        {
            "id": "fname_pool_blocked",
            "name": "FNamePool blocked index",
            "model": "pool",
            "formula": {
                "block": "comparison_index >> 16",
                "offset_units": "comparison_index & 0xFFFF",
                "entry_address": "blocks[block] + offset_units * stride",
                "header": "uint16 at entry + Info",
                "is_wide": "(header >> WideBit) & 1",
                "length": "header >> LenBit",
            },
            "parameters": {"block_offset_bits": 16, "block_offset_mask": 0xFFFF, "default_stride": 2},
            "confidence": min(pool_score, 100),
            "validation_state": VALIDATION_CANDIDATE if gnames_record["target_va"] is not None else VALIDATION_UNCONFIRMED,
            "evidence": pool_evidence,
        },
        {
            "id": "fname_direct_array",
            "name": "TNameEntryArray direct index",
            "model": "direct",
            "formula": {
                "entry_address": "entries[comparison_index]",
                "number": "FName + Number offset",
            },
            "parameters": {"number_mask": 0xFFFF},
            "confidence": min(direct_score, 100),
            "validation_state": VALIDATION_CANDIDATE if has_direct_marker else VALIDATION_UNCONFIRMED,
            "evidence": direct_evidence,
        },
    ]
    candidates.sort(key=lambda item: (-item["confidence"], item["id"]))

    profiles = rank_layout_profiles(
        data,
        engine_version=engine_version,
        engine_family=engine_family,
        fname_model=inferred_model,
        runtime_observations=runtime_observations,
    )
    entry_layout_candidates = []
    for profile in profiles:
        entry_layout_candidates.append(
            {
                "profile": profile["name"],
                "stride": profile["fname"]["stride"],
                "number": profile["fname"]["number"],
                "entry": profile["fname"]["entry"],
                "confidence": profile["confidence"],
                "validation_state": profile["validation_state"],
                "evidence": profile["evidence"],
            }
        )

    selected = candidates[0]
    state = selected["validation_state"]
    if gnames_record["validation_state"] == VALIDATION_UNCONFIRMED:
        state = VALIDATION_UNCONFIRMED
    get_name_xor = analyze_get_name_xor(
        data,
        runtime_observations=runtime_observations,
    )
    return {
        "model": inferred_model,
        "engine_version": engine_version,
        "engine_family": engine_family,
        "version_layout": get_version_layout(engine_version) if engine_version else None,
        "gnames": gnames_record,
        "gnames_status": gnames_record["status"],
        "algorithm": selected,
        "algorithm_candidates": candidates,
        "get_name_xor": get_name_xor,
        "entry_layout_candidates": entry_layout_candidates,
        "selected_profile": {
            "name": profiles[0]["name"],
            "confidence": profiles[0]["confidence"],
            "validation_state": profiles[0]["validation_state"],
        },
        "validation_state": state,
        "encryption_signals": {
            "index_to_name": has_index_to_name,
            "requires_runtime_decode": bool(has_index_to_name or gnames_record["target_va"] is None),
        },
        "validation_plan": [
            "Read the candidate Blocks pointer array from the loaded module.",
            "Decode at least two known FName entries and verify printable names.",
            "Confirm header length and wide-string bit against decoded bytes.",
            "Correlate GetName/GetFName XOR candidates with the decoded plaintext names.",
            "Promote the selected entry layout only after the pointer and text checks pass.",
        ],
    }


def _marker_results(data: bytes) -> dict[str, bool]:
    markers = {
        "UObject": b"UObject",
        "UClass": b"UClass",
        "UField": b"UField",
        "UStruct": b"UStruct",
        "UEnum": b"UEnum",
        "UFunction": b"UFunction",
        "FField": b"FField",
        "FProperty": b"FProperty",
        "UProperty": b"UProperty",
        "ProcessEvent": b"ProcessEvent",
        "GetDefaultObject": b"GetDefaultObject",
    }
    return {name: needle in data for name, needle in markers.items()}


def analyze_reflection_layouts(
    data: bytes,
    *,
    engine_version: str = "",
    engine_family: str = "",
    fname_model: str = "",
    gnames: dict[str, Any] | None = None,
    runtime_observations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build structure/field offset candidates for the UE reflection system."""
    markers = _marker_results(data)
    profiles = rank_layout_profiles(
        data,
        engine_version=engine_version,
        engine_family=engine_family,
        fname_model=fname_model,
        runtime_observations=runtime_observations,
    )
    gnames_record = _global_state(gnames, "GNames/FNamePool")
    structures: dict[str, Any] = {}
    flat_fields: list[dict[str, Any]] = []
    names = [
        "UObject",
        "UField",
        "UStruct",
        "UEnum",
        "UFunction",
        "FField",
        "FProperty",
        "UProperty",
    ]
    for structure_name in names:
        fields: dict[str, list[dict[str, Any]]] = {}
        field_names = sorted(
            {
                field
                for profile in profiles
                for field in profile["structures"].get(structure_name, {})
            }
        )
        for field_name in field_names:
            candidates = []
            for profile in profiles:
                entry = profile["structures"].get(structure_name, {}).get(field_name)
                if entry is None:
                    continue
                candidate = {
                    "profile": profile["name"],
                    "offset": entry,
                    "confidence": profile["confidence"],
                    "validation_state": profile["validation_state"],
                    "evidence": profile["evidence"],
                }
                candidates.append(candidate)
                flat_fields.append({"structure": structure_name, "field": field_name, **candidate})
            fields[field_name] = candidates
        structures[structure_name] = {
            "marker_present": markers.get(structure_name, False),
            "validation_state": VALIDATION_CANDIDATE if markers.get(structure_name, False) else VALIDATION_UNCONFIRMED,
            "fields": fields,
        }

    baseline = version_baseline_profile(engine_version, engine_family)
    observed_profile = str((runtime_observations or {}).get("validated_profile") or "").strip()
    selected = baseline
    selection_state = baseline["selection_state"]
    if observed_profile in UE_LAYOUT_PROFILES:
        selected = deepcopy(UE_LAYOUT_PROFILES[observed_profile])
        selected.update({
            "confidence": 100,
            "validation_state": VALIDATION_CONFIRMED,
            "selection_state": "runtime_confirmed",
            "selection_reason": "Selected from explicit runtime validated_profile evidence.",
        })
        selection_state = "runtime_confirmed"
    detected = any(markers.values())
    return {
        "detected": detected,
        "markers": markers,
        "version_layout": get_version_layout(engine_version) if engine_version else None,
        "profile_candidates": profiles,
        "version_baseline_profile": baseline,
        "version_baseline_profile_name": baseline["name"],
        "profile_selection_state": selection_state,
        "selected_profile": {
            "name": selected["name"],
            "confidence": selected["confidence"],
            "validation_state": selected["validation_state"],
            "selection_state": selected.get("selection_state", selection_state),
            "selection_reason": selected.get("selection_reason", ""),
            "fname": selected.get("fname", {}),
            "fuobject_item": selected.get("fuobject_item", {}),
            "structures": selected.get("structures", {}),
            "note": "Candidate only until a runtime structure traversal validates pointer and name invariants."
            if selected["validation_state"] != VALIDATION_CONFIRMED
            else "Confirmed by explicit runtime profile evidence.",
        }
        if selected
        else None,
        "alternative_profiles": [
            profile for profile in profiles if profile.get("name") != selected.get("name")
        ],
        "structures": structures,
        "field_offset_candidates": flat_fields,
        "gnames_dependency": {
            "status": gnames_record["status"],
            "note": "FName-bearing fields remain unconfirmed while GNames/FNamePool is unconfirmed."
            if gnames_record["status"] == VALIDATION_UNCONFIRMED
            else "Use FName decoding to validate class/name fields.",
        },
        "validation_state": VALIDATION_CANDIDATE if detected else VALIDATION_UNCONFIRMED,
        "validation_plan": [
            "Validate UObject Class and Outer as in-module or heap pointers.",
            "Use decoded FNames to validate UObject Name and FField Name.",
            "Traverse UStruct ChildProperties/Children until a terminating null pointer.",
            "Validate FProperty ArrayDim, ElementSize, and Offset against plausible ranges.",
            "Record the validated profile and field-level evidence in runtime observations.",
        ],
    }
