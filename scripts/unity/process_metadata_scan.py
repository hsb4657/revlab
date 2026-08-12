"""Read-only IL2CPP metadata scanner for a running Windows process.

The scanner never writes to the target process.  It accepts a PID or starts a
Unity executable, searches committed readable memory for the IL2CPP metadata
magic, validates the complete v24 header/table layout, and writes only fully
bounded candidates to the requested output directory.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time


IL2CPP_MAGIC = b"\xaf\x1b\xb1\xfa"
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
READABLE_PROTECTIONS = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
MAX_METADATA_SIZE = 1024 * 1024 * 1024
READ_CHUNK = 4 * 1024 * 1024


if os.name != "nt":
    raise SystemExit("process_metadata_scan.py requires Windows")


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL


# Metadata v24.2-v24.5 header.  Counts are byte lengths for record tables.
V24_FIELDS = (
    "stringLiteral",
    "stringLiteralData",
    "string",
    "events",
    "properties",
    "methods",
    "parameterDefaultValues",
    "fieldDefaultValues",
    "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes",
    "parameters",
    "fields",
    "genericParameters",
    "genericParameterConstraints",
    "genericContainers",
    "nestedTypes",
    "interfaces",
    "vtableMethods",
    "interfaceOffsets",
    "typeDefinitions",
    "images",
    "assemblies",
    "metadataUsageLists",
    "metadataUsagePairs",
    "fieldRefs",
    "referencedAssemblies",
    "attributesInfo",
    "attributeTypes",
    "unresolvedVirtualCallParameterTypes",
    "unresolvedVirtualCallParameterRanges",
    "windowsRuntimeTypeNames",
    "exportedTypeDefinitions",
)
V24_HEADER_SIZE = 8 + len(V24_FIELDS) * 8


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_memory(handle: int, address: int, size: int) -> bytes:
    if size <= 0:
        return b""
    output = bytearray()
    cursor = address
    remaining = size
    while remaining:
        requested = min(remaining, READ_CHUNK)
        buffer = ctypes.create_string_buffer(requested)
        read = ctypes.c_size_t()
        ok = kernel32.ReadProcessMemory(
            handle,
            ctypes.c_void_p(cursor),
            buffer,
            requested,
            ctypes.byref(read),
        )
        if not ok or read.value == 0:
            raise OSError(ctypes.get_last_error(), f"ReadProcessMemory failed at 0x{cursor:x}")
        output.extend(buffer.raw[: read.value])
        cursor += read.value
        remaining -= read.value
        if read.value != requested:
            raise OSError(f"partial process-memory read at 0x{cursor:x}")
    return bytes(output)


def _header_v24(data: bytes) -> dict | None:
    if len(data) < V24_HEADER_SIZE or data[:4] != IL2CPP_MAGIC:
        return None
    version = struct.unpack_from("<i", data, 4)[0]
    if version != 24:
        return None
    tables = {}
    ends = []
    nonempty = 0
    prior_offset = V24_HEADER_SIZE
    monotonic = 0
    for index, name in enumerate(V24_FIELDS):
        offset, size = struct.unpack_from("<II", data, 8 + index * 8)
        tables[name] = {"offset": offset, "size": size, "end": offset + size}
        if size == 0:
            continue
        nonempty += 1
        if offset < V24_HEADER_SIZE or offset > MAX_METADATA_SIZE:
            return None
        if size > MAX_METADATA_SIZE or offset + size > MAX_METADATA_SIZE:
            return None
        if offset >= prior_offset:
            monotonic += 1
        prior_offset = offset
        ends.append(offset + size)
    if nonempty < 18 or not ends:
        return None
    file_size = max(ends)
    if file_size < 1024 * 1024 or monotonic < nonempty - 3:
        return None

    divisibility = {
        "stringLiteral": (8,),
        "events": (24, 28),
        "properties": (20, 24),
        "methods": (32, 36, 56),
        "parameterDefaultValues": (12,),
        "fieldDefaultValues": (12,),
        "parameters": (12, 16),
        "fields": (12, 16),
        "genericContainers": (16,),
        "interfaceOffsets": (8,),
        "typeDefinitions": (88, 92, 96, 104, 120),
        "images": (32, 40),
        "assemblies": (64, 68),
        "metadataUsageLists": (8,),
        "metadataUsagePairs": (8,),
        "fieldRefs": (8,),
    }
    checks = {}
    failed = []
    for name, record_sizes in divisibility.items():
        size = tables[name]["size"]
        valid = size == 0 or any(size % record_size == 0 for record_size in record_sizes)
        checks[name] = {"record_sizes": record_sizes, "valid": valid}
        if not valid:
            failed.append(name)
    # Unity has minor v24 layout variants.  A candidate must still satisfy
    # nearly all stable record-table widths before it can be dumped.
    if len(failed) > 2:
        return None
    return {
        "version": version,
        "header_size": V24_HEADER_SIZE,
        "file_size": file_size,
        "nonempty_tables": nonempty,
        "monotonic_tables": monotonic,
        "tables": tables,
        "record_size_checks": checks,
        "record_size_failures": failed,
    }


def _validate_payload(payload: bytes, header: dict) -> dict:
    if len(payload) != header["file_size"]:
        return {"valid": False, "reason": "payload length does not match table boundary"}
    tables = header["tables"]
    string_table = tables["string"]
    strings = payload[string_table["offset"] : string_table["end"]]
    anchors = [
        anchor.decode("ascii")
        for anchor in (b"mscorlib.dll", b"System.Object", b"Assembly-CSharp")
        if anchor in strings
    ]
    printable = sum(1 for value in strings[: min(len(strings), 4 * 1024 * 1024)]
                    if value == 0 or 0x20 <= value < 0x7F)
    sample_size = min(len(strings), 4 * 1024 * 1024)
    printable_ratio = printable / sample_size if sample_size else 0.0
    token_tables = ("typeDefinitions", "methods", "fields", "images")
    token_hits = 0
    for name in token_tables:
        table = tables[name]
        sample = payload[table["offset"] : min(table["end"], table["offset"] + 8 * 1024 * 1024)]
        token_hits += sample.count(b"\x02\x00\x00\x02")
        token_hits += sample.count(b"\x01\x00\x00\x06")
    valid = printable_ratio >= 0.72 and bool(anchors) and token_hits > 10
    return {
        "valid": valid,
        "reason": "validated" if valid else "cross-table/string evidence failed",
        "string_anchors": anchors,
        "string_printable_ratio": round(printable_ratio, 6),
        "metadata_token_hits": token_hits,
    }


def _regions(handle: int):
    cursor = 0
    maximum = (1 << 47) - 1
    while cursor < maximum:
        info = MEMORY_BASIC_INFORMATION()
        size = kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(cursor),
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not size:
            break
        base = int(info.BaseAddress or 0)
        region_size = int(info.RegionSize)
        if region_size <= 0:
            break
        yield info
        next_cursor = base + region_size
        if next_cursor <= cursor:
            break
        cursor = next_cursor


def scan_process(pid: int, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), f"OpenProcess({pid}) failed")
    result = {
        "schema": "revlab.unity.runtime-metadata-capture/v1",
        "pid": pid,
        "read_only": True,
        "candidates": [],
        "regions_scanned": 0,
        "bytes_scanned": 0,
    }
    seen = set()
    try:
        for info in _regions(handle):
            protect = int(info.Protect)
            base = int(info.BaseAddress or 0)
            region_size = int(info.RegionSize)
            if (info.State != MEM_COMMIT or protect & (PAGE_GUARD | PAGE_NOACCESS)
                    or (protect & 0xFF) not in READABLE_PROTECTIONS):
                continue
            result["regions_scanned"] += 1
            result["bytes_scanned"] += region_size
            overlap = b""
            cursor = 0
            while cursor < region_size:
                requested = min(READ_CHUNK, region_size - cursor)
                try:
                    block = _read_memory(handle, base + cursor, requested)
                except OSError:
                    break
                data = overlap + block
                search_from = 0
                while True:
                    hit = data.find(IL2CPP_MAGIC, search_from)
                    if hit < 0:
                        break
                    address = base + cursor - len(overlap) + hit
                    search_from = hit + 1
                    if address in seen:
                        continue
                    seen.add(address)
                    try:
                        header_data = _read_memory(handle, address, V24_HEADER_SIZE)
                        header = _header_v24(header_data)
                        if not header:
                            continue
                        payload = _read_memory(handle, address, header["file_size"])
                        validation = _validate_payload(payload, header)
                    except OSError:
                        continue
                    record = {
                        "address": f"0x{address:x}",
                        "allocation_base": f"0x{int(info.AllocationBase or 0):x}",
                        "region_base": f"0x{base:x}",
                        "region_size": region_size,
                        "memory_type": int(info.Type),
                        "protection": protect,
                        "header": header,
                        "validation": validation,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                    if validation["valid"]:
                        path = output_dir / f"global-metadata_0x{address:x}.dat"
                        path.write_bytes(payload)
                        record["path"] = str(path)
                    result["candidates"].append(record)
                overlap = data[-(len(IL2CPP_MAGIC) - 1) :]
                cursor += requested
    finally:
        kernel32.CloseHandle(handle)
    verified = [item for item in result["candidates"] if item["validation"]["valid"]]
    result["verified_count"] = len(verified)
    result["verified"] = bool(verified)
    result["verified_paths"] = [item.get("path", "") for item in verified]
    return result


def _start_target(executable: Path, arguments: list[str], log_path: Path) -> subprocess.Popen:
    command = [str(executable), *arguments]
    if "-logFile" not in arguments:
        command.extend(["-logFile", str(log_path)])
    return subprocess.Popen(
        command,
        cwd=str(executable.parent),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pid", type=int)
    source.add_argument("--exe", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--poll", type=float, default=2.0)
    parser.add_argument("--keep-running", action="store_true")
    parser.add_argument("target_args", nargs="*")
    args = parser.parse_args()

    process = None
    pid = args.pid
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.exe:
        executable = args.exe.resolve()
        if not executable.is_file():
            parser.error(f"executable not found: {executable}")
        target_args = args.target_args or ["-batchmode", "-nographics"]
        process = _start_target(executable, target_args, args.output_dir / "unity_runtime.log")
        pid = process.pid

    assert pid is not None
    deadline = time.monotonic() + args.timeout
    attempts = []
    final = None
    try:
        while time.monotonic() < deadline:
            if process and process.poll() is not None:
                break
            try:
                current = scan_process(pid, args.output_dir)
                attempts.append({
                    "at": time.time(),
                    "verified_count": current["verified_count"],
                    "candidate_count": len(current["candidates"]),
                    "regions_scanned": current["regions_scanned"],
                    "bytes_scanned": current["bytes_scanned"],
                })
                if current["verified"]:
                    final = current
                    break
            except OSError as error:
                attempts.append({"at": time.time(), "error": str(error)})
            time.sleep(args.poll)
    finally:
        if process and not args.keep_running and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()

    if final is None:
        final = {"schema": "revlab.unity.runtime-metadata-capture/v1", "pid": pid,
                 "read_only": True, "verified": False, "verified_count": 0,
                 "candidates": [], "verified_paths": []}
    final["attempts"] = attempts
    if args.exe:
        final["executable"] = str(args.exe.resolve())
        final["executable_sha256"] = _sha256(args.exe.resolve())
        final["exit_code"] = process.poll() if process else None
    manifest = args.output_dir / "runtime_metadata_capture.json"
    manifest.write_text(json.dumps(final, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "verified": final["verified"],
        "verified_count": final["verified_count"],
        "verified_paths": final["verified_paths"],
        "manifest": str(manifest),
        "pid": pid,
    }, ensure_ascii=False))
    return 0 if final["verified"] else 2


if __name__ == "__main__":
    sys.exit(main())
