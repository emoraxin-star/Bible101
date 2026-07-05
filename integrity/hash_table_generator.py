#!/usr/bin/env python3
"""
hash_table_generator.py — Precomputes CRC32C hashes for .text section integrity.

Reads a compiled PE binary and its optional map file, then generates
a C header with:
  1. g_IntegrityHashes[] — CRC32C of each 4KB .text block
  2. g_IntegrityHashCount
  3. Critical function offset/size entries (from map file)

Usage:
    python hash_table_generator.py --pe <path> [--map <path>] [--output <path>]

Dependencies: None (uses only stdlib)
"""

import argparse
import os
import re
import struct
import sys

CRC32C_TABLE: list[int] = []

def _build_crc32c_table() -> None:
    poly = 0x82F63B78
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        CRC32C_TABLE.append(crc)

def crc32c(data: bytes) -> int:
    if not CRC32C_TABLE:
        _build_crc32c_table()
    crc = 0xFFFFFFFF
    for byte in data:
        crc = CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def read_pe_text_section(path: str) -> tuple[bytes, int, int]:
    with open(path, "rb") as f:
        dos = f.read(64)
        if dos[:2] != b"MZ":
            raise ValueError("Not a valid PE file (missing MZ signature)")

        e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
        f.seek(e_lfanew)
        nt = f.read(24)
        if nt[:4] != b"PE\x00\x00":
            raise ValueError("Missing PE signature")

        file_header = f.read(20)
        num_sections = struct.unpack_from("<H", file_header, 2)[0]
        optional_header_size = struct.unpack_from("<H", file_header, 16)[0]
        f.seek(e_lfanew + 24 + optional_header_size)

        for _ in range(num_sections):
            section = f.read(40)
            name = section[:8].rstrip(b"\x00").decode("ascii", errors="replace")
            if name == ".text":
                virtual_size = struct.unpack_from("<I", section, 8)[0]
                virtual_addr = struct.unpack_from("<I", section, 12)[0]
                raw_size = struct.unpack_from("<I", section, 16)[0]
                raw_addr = struct.unpack_from("<I", section, 20)[0]

                f.seek(raw_addr)
                text_data = f.read(raw_size)
                print(f"[+] .text section: VAddr=0x{virtual_addr:08X}, "
                      f"VSize=0x{virtual_size:X}, RawSize=0x{raw_size:X}",
                      file=sys.stderr)
                return text_data, raw_size, virtual_addr

        raise ValueError("No .text section found")


def parse_map_file(path: str) -> list[dict]:
    functions = []
    if not path or not os.path.exists(path):
        return functions

    func_pattern = re.compile(
        r'^\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(\S+)'
    )

    with open(path, "r") as f:
        for line in f:
            m = func_pattern.match(line)
            if m:
                addr = int(m.group(1), 16)
                size = int(m.group(2), 16)
                name = m.group(3)
                functions.append({
                    "name": name,
                    "address": addr,
                    "size": size,
                })

    return functions


def generate_header(
    text_data: bytes,
    section_rva: int,
    functions: list[dict],
    output_path: str,
) -> None:
    block_size = 0x1000
    lines: list[str] = []

    lines.append("#pragma once")
    lines.append("#include <stdint.h>")
    lines.append("")

    num_complete = len(text_data) // block_size
    lines.append(f"#define INTEGRITY_NUM_BLOCKS {num_complete}")
    lines.append(f"#define INTEGRITY_BLOCK_SIZE  0x{block_size:X}")
    lines.append("")

    lines.append("//")
    lines.append("// Auto-generated CRC32C hashes for .text section integrity")
    lines.append(f"// Source PE: {os.path.basename(output_path) if output_path else '<stdin>'}")
    lines.append("//")
    lines.append("")

    lines.append("uint32_t g_IntegrityHashes[] = {")
    for i in range(num_complete):
        block = text_data[i * block_size : (i + 1) * block_size]
        h = crc32c(block)
        sep = "," if i < num_complete - 1 else " "
        lines.append(f"    0x{h:08X}{sep}  // Block {i}: offset 0x{i * block_size:X}")
    lines.append("};")
    lines.append("")

    lines.append(f"SIZE_T g_IntegrityHashCount = {num_complete};")
    lines.append("")

    critical_names = [
        "PatternScanner", "HookInstaller", "SyscallBuilder",
        "AuthValidator", "Decompressor", "NetworkSend",
        "OverlayRender", "ConfigParser", "ReplayEngine",
        "ChallengeResponder",
    ]

    selected = []
    for f in functions:
        for cn in critical_names:
            if cn.lower() in f["name"].lower() or f["name"].lower() in cn.lower():
                selected.append(f)
                break

    lines.append("//")
    lines.append("// Critical function checksums (from map file)")
    lines.append("//")
    lines.append("")

    for f in selected:
        func_size = f["size"]
        func_offset = f["address"] - section_rva
        if func_offset >= 0 and func_offset + func_size <= len(text_data):
            func_data = text_data[func_offset : func_offset + func_size]
            h = crc32c(func_data)
            lines.append(f"// {f['name']}: offset=0x{f['address']:X}, "
                         f"size=0x{func_size:X}, hash=0x{h:08X}")

    lines.append("")
    lines.append("INTEGRITY_CRITICAL_FUNC g_CriticalFunctions[] = {")

    for f in selected:
        func_size = f["size"]
        func_offset = f["address"] - section_rva
        if func_offset >= 0 and func_offset + func_size <= len(text_data):
            func_data = text_data[func_offset : func_offset + func_size]
            h = crc32c(func_data)
            name_clean = f["name"].replace('"', '\\"')
            lines.append(f'    {{ "{name_clean}", (PVOID)0x{f["address"]:X}, '
                         f'0x{func_size:X}, 0x{h:08X} }},')

    lines.append("};")
    lines.append("")
    lines.append(f"const SIZE_T g_CriticalFunctionCount = {len(selected)};")

    output = "\n".join(lines) + "\n"
    with open(output_path, "w") as f:
        f.write(output)

    print(f"[+] Generated {output_path}: {num_complete} blocks, "
          f"{len(selected)} critical functions", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate integrity hash table C header from PE binary")
    parser.add_argument("--pe", required=True,
                        help="Path to the compiled PE (.dll or .exe)")
    parser.add_argument("--map", default=None,
                        help="Optional path to map file for critical function offsets")
    parser.add_argument("--output", default="integrity_hashes.h",
                        help="Output C header path (default: integrity_hashes.h)")
    args = parser.parse_args()

    if not os.path.exists(args.pe):
        print(f"[-] PE file not found: {args.pe}", file=sys.stderr)
        sys.exit(1)

    text_data, raw_size, section_rva = read_pe_text_section(args.pe)
    functions = parse_map_file(args.map)

    generate_header(text_data, section_rva, functions, args.output)


if __name__ == "__main__":
    main()
