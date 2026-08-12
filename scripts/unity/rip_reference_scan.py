#!/usr/bin/env python3
"""Find x64 RIP-relative references to a VA range in executable PE sections."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("target", type=lambda value: int(value, 0))
    parser.add_argument("--size", type=lambda value: int(value, 0), default=0x100)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    pe = pefile.PE(str(args.pe), fast_load=True)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    hits = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()
        section_va = image_base + int(section.VirtualAddress)
        for instruction in disassembler.disasm(data, section_va):
            for operand in instruction.operands:
                if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
                    continue
                resolved = instruction.address + instruction.size + operand.mem.disp
                if args.target <= resolved < args.target + args.size:
                    hits.append({
                        "instruction_va": instruction.address,
                        "instruction_rva": instruction.address - image_base,
                        "mnemonic": instruction.mnemonic,
                        "operands": instruction.op_str,
                        "target_va": resolved,
                        "target_offset": resolved - args.target,
                        "section": section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                    })
    report = {
        "schema": "revlab.unity.rip_reference_scan.v1",
        "pe": str(args.pe),
        "image_base": image_base,
        "target": args.target,
        "size": args.size,
        "hits": hits,
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(encoded + "\n", encoding="utf-8")
    else:
        print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
