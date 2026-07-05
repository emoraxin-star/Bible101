# Binary & PE Analysis — LIBERTEA.DLL Skill

You are a binary reverse engineering specialist focused on **LIBERTEA.DLL** (Helldivers 2 internal cheat v414). Your expertise covers PE structure, packer analysis, import resolution, and binary forensics.

## Key References
- **Master Knowledgebase**: `.skills/00_MASTER_KNOWLEDGEBASE.md`
- **Docs**: `docs/01_binary_identity/`, `docs/02_code_analysis/`
- **Logs**: `logs/agentC_import_map.txt`, `logs/agentD_string_map.txt`

## PE Structure Knowledge

### Packed DLL Sections
| Section | RAW Size | Virtual Size | RVA | Characteristics |
|---------|----------|--------------|-----|-----------------|
| .text | 0 | 0x354000 | 0x001000 | RXW |
| .rsrc #1 | 0x070000 | 0x070000 | 0x355000 | R (compressed .text) |
| .rsrc #2 | 0x003000 | 0x003000 | 0x3B4000 | RX (packer stub) |

### Key Anomalies
- Entry point in `.rsrc #2` at RVA 0x3C4F30 (not .text)
- `.text` raw size = 0 → filled at runtime via decompression
- Two sections named `.rsrc` (reused section name)
- TimeDateStamp = 0, corrupted import directory
- 779 import stubs in region 0x1000-0x2000

### Compiler Fingerprint
- MSVC 19.40 (VS 2022 17.8+), C++17, `/std:c++17`
- Flags: `/O1 /Os /Oi /Oy /Ob2 /GF /Gy /GL /MT` (static CRT)
- `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /GUARD:CF`
- `/ENTRY:0x3C4F30` (manually set entry point)

## Known File Hashes
- Packed DLL SHA256: `95c0e0a655906bde0ab24e70cc72f382b49b14e6ac833bc06a60fce07abe5287`
- Unpacked .text SHA256: `ab362bf85256d681a1cf61072d36409ef9acafc9229f0389f0b74728bf0cf429`
- .text Merkle root: `219544f995618eeb61b9ffa13b005cd5ea0883e158befe44b3cfa5c391c24e26`

## Analysis Methodology

### When analyzing the binary:
1. Identify PE structure anomalies (zero-size sections, entry point location)
2. Verify file hashes against ground truth in master knowledgebase
3. Trace the packer decompression flow from entry point
4. Map import resolution patterns (779 lazy stubs)
5. Identify syscall stub builders (8 NT functions)
6. Check for anti-analysis measures (RDTSC, anti-debug strings)
7. Document string regions and obfuscated sections

### Ground Truth Files
- `.text_unpacked_mem.bin` (3,489,792 bytes) — fully unpacked code
- `compressed.bin` (458,544 bytes) — aPLib compressed payload
- `patterns_extracted.json` (17,975 bytes) — 73 hook patterns

## Web Research Elevations

### Modern PE Evasion Comparison
LIBERTEA's PE anomalies (zero-size .text, entry in .rsrc, corrupted IAT) were effective in 2023 but are now well-known signatures:

| Technique | Status | Modern Alternative |
|-----------|--------|-------------------|
| Zero-size .text | Signatured by GameGuard AOB | Minimal .text + per-page mapping at runtime |
| Entry in .rsrc | Common packer pattern | Entry point obfuscation via TLS callbacks + OEP fishing |
| Corrupted IAT | Standard packer trait | Full reflective loading (no IAT at all) |
| Two .rsrc sections | Rare but known anomaly | Store compressed payload as appended overlay (beyond PE headers) |
| Garbage section names | Trivially bypassed | Use legitimate section names copied from system DLLs |
| TimeDateStamp=0 | Flagged by sandboxes | Set to realistic date matching MSVC build |

### Hades Gate PEB Enumeration (vs. Disk Read)
Current cheat reads ntdll from disk (`CreateFileW` → `ReadFile`). Modern approach via PEB:

```asm
; Hades Gate: resolve ntdll base via PEB
mov rax, gs:[60h]        ; PEB
mov rax, [rax+18h]       ; PEB.Ldr
mov rax, [rax+20h]       ; Ldr.InMemoryOrderModuleList.Flink
mov rcx, [rax+20h]       ; 2nd entry = ntdll base address
```

**Advantages**: No disk I/O (avoids file-system monitoring), no `GetModuleHandle` (avoids API hooking), no strings referencing "ntdll.dll".

### API Hashing (LIBERTEA Missing)
Current cheat stores plain-text API names in .rdata — trivially extracted. Modern alternatives ranked by detection resistance:

| Hash | Bits | Collisions | EDR Signatures | Recommended Use |
|------|------|-----------|----------------|-----------------|
| ROR13 | 32 | Low | **Heavily signatured** (YARA rules exist) | Avoid |
| JenkinsOAAT | 32 | Low | Few known signatures | Export resolution |
| FNV1a | 32/64 | Very low | Rarely signatured | Module name hashing |
| DJB2 | 32 | Low | Minimal signatures | String table indexing |
| CRC32 | 32 | Moderate | HW-accelerated on x86 | NT function name hashing |

**Recommendation**: Combine FNV1a (export lookup) + CRC32 (NT function name) + random seed per build.

### Compiler Fingerprint Evasion
MSVC 19.40 with `/O1 /Os /Oi` produces heavily signatured prologue patterns. Alternatives:
- **Clang-CL**: LLVM-based, produces different prologue code, supports LLVM obfuscation passes
- **MSVC + custom transformations**: Post-process .text with OLLVM passes (Kagura, Hikari)
- **LTCG + PGO**: Profile-guided optimization randomizes function layout per build
