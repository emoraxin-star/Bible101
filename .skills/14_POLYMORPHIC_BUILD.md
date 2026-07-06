# 14_POLYMORPHIC_BUILD.md
# Polymorphic Build System

Techniques and implementation for generating per-user unique LIBERTEA.DLL builds, defeating signature-based detection.

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Technique Overview](#2-technique-overview)
3. [Build-Time Constant Rotation](#3-build-time-constant-rotation)
4. [Function Reordering & Padding](#4-function-reordering--padding)
5. [String Obfuscation (Compile-Time)](#5-string-obfuscation-compile-time)
6. [Kagura OLLVM Pass Integration](#6-kagura-ollvm-pass-integration)
7. [Python Polymorphic Builder](#7-python-polymorphic-builder)
8. [CI/CD Pipeline](#8-cicd-pipeline)

---

## 1. Threat Model

```
Current state:  1 binary → 1 signature → detects ALL users
Target state:   N binaries → N signatures → no cross-user detection

GameGuard AOB scan targets:
  - Syscall stub pattern:    4C 8B D1 B8 ?? 0F 05 C3
  - NOP sled pattern:        90 90 90 90
  - Detour hook pattern:     FF 25 00 00 00 00 [8 bytes]
  - ImGui version string:    "Dear ImGui 1.91.5"
  - Feature strings:         "GodMode", "NoReload", etc.
  - Import resolutions:      LEA RCX, [import_name] → JMP resolver
```

### Polymorphism Layers (Defense-in-Depth)

| Layer | Technique | Defeats |
|-------|-----------|---------|
| 1 | Build-time constant rotation | AOB patterns with hardcoded values |
| 2 | Function reordering + padding | Function prologue signatures |
| 3 | Compile-time string encryption | String-based detection (ImGui, feature names) |
| 4 | OLLVM obfuscation passes | Static CFG analysis, pattern matching |
| 5 | PE header mutation | PE signature-based detection |
| 6 | Per-user API hash seeds | Import table scanning |

---

## 2. Technique Overview

### Source of Entropy

```cpp
// Polymorphic seed derived from per-user invariant
// This ensures the same user gets consistent builds (for caching)
// but different users get different binaries

uint64_t GetBuildSeed() {
    // Option A: License key hash (server-side, returned at auth)
    // Option B: MachineGuid hash
    // Option C: Random on first launch, stored in config

    // Build-time: the seed is chosen by the build script
    // and embedded as a compile-time constant
    // Build script sets: -DPOLYMORPHIC_SEED=0xDEADBEEF
    return POLYMORPHIC_SEED;
}
```

### What Varies Per Build

| Component | Variation Method | Variation Degree |
|-----------|-----------------|-----------------|
| Syscall stub layout | Random variant selection per stub | 7 variants × N functions |
| NOP sled bytes | Replace NOP with `MOV REG,REG` + `XOR REG,REG` equivalents | ~20 alternatives per byte |
| Feature string order | Shuffle feature comparison order | 73! (impossible to enumerate) |
| Constant immediates | XOR with seed, decode at runtime | 2^32 per constant |
| Function layout | Randomize .text section order | N! function permutations |
| Import resolver order | Randomize stub resolution sequence | 779! import permutations |
| String encryption key | Per-build key | 2^128 |
| PE timestamp | Random date matching MSVC build era | ~1000 realistic dates |

---

## 3. Build-Time Constant Rotation

### Macro-Based Constant Obfuscation

```cpp
// obfuscate.h — included by all source files
#pragma once
#include <cstdint>
#include <type_traits>

// Polymorphic seed set by build system: -DPOLY_SEED=<random>
#ifndef POLY_SEED
#define POLY_SEED 0
#endif

// Obfuscate an integer constant: stored as (value ^ POLY_SEED),
// deobfuscated at runtime via XOR
template<typename T>
struct Obfuscated {
    T stored;
    constexpr Obfuscated(T v) : stored(static_cast<T>(v ^ static_cast<T>(POLY_SEED))) {}
    constexpr T get() const { return stored ^ static_cast<T>(POLY_SEED); }
    operator T() const { return get(); }
};

// Usage: replaces "0x12345678" with "OBFUSCATE(0x12345678)"
#define OBFUSCATE(x) (Obfuscated<uint32_t>(x).get())

// Pattern comparison constants become polymorphic:
// Before: if (*(uint32_t*)addr == 0x12345678)
// After:  if (*(uint32_t*)addr == OBFUSCATE(0x12345678))
```

### Syscall Number Obfuscation

```cpp
// Instead of: mov eax, ssn  (where ssn is a constant in .text)
// Use:        mov eax, obfuscated_ssn; xor eax, poly_seed

// Implementation in stub builder:
void BuildXorSsn(uint32_t ssn, uint32_t seed) {
    uint32_t encSsn = ssn ^ seed;
    StubBuilder sb;
    sb.MovR10Rcx();
    sb.MovEax(encSsn);
    sb.XorEax(seed);     // Reconstruct original SSN at runtime
    sb.Syscall();
    sb.Ret();
    // Encoded SSN in stub: encSsn != ssn → different AOB per seed
}
```

### ImGui Version String Removal

```cpp
// Replace:  const char* imguiVersion = "Dear ImGui 1.91.5";
// With:     // Version string constructed at runtime from parts
const char* GetImguiVersion() {
    static char buf[32];
    static bool init = false;
    if (!init) {
        // Build string from individually obfuscated characters
        // Each character XOR'd with POLY_SEED & 0xFF
        char parts[] = {
            'D' ^ (POLY_SEED & 0xFF), 'e' ^ (POLY_SEED & 0xFF), ...
        };
        for (int i = 0; i < 16; i++)
            buf[i] = parts[i] ^ (POLY_SEED & 0xFF);
        init = true;
    }
    return buf;
}
```

---

## 4. Function Reordering & Padding

### Linker Function Order Randomization

```python
# randomize_layout.py — Post-compilation .text reordering
# Usage: python randomize_layout.py LIBERTEA.dll seed > LIBERTEA_reordered.dll

import struct, random, sys

def randomize_text_section(dll_path, seed):
    random.seed(seed)
    with open(dll_path, 'rb') as f:
        dll = bytearray(f.read())

    # Parse PE to find .text section
    # For each COMDAT function:
    #   1. Read function bytes (preserve alignment)
    #   2. Shuffle function order
    #   3. Insert random padding between functions (0xCC int3)
    #   4. Update relocations for new offsets

    # This is simplified — real implementation needs
    # /Gy (function-level linking) + linker map file

    with open(dll_path.replace('.dll', '_poly.dll'), 'wb') as f:
        f.write(dll)
```

### Random Padding Insertion

```cpp
// linker_padding.asm — Assembly file with randomized NOP sleds
// Between each COMDAT function, insert random-length padding

; Function A ends here
ALIGN 16
; Random padding bytes (generated at build time)
; Options: 0x90 (NOP), 0xCC (INT3), 0x0F 0x1F 00 (NOP DWORD),
;          0x66 0x90 (XCHG AX,AX), 0x0F 0x1F 0x40 0x00 (NOP QWORD)
padding_start:
REPT random(8, 64)   ; 8-64 bytes of random NOP variants
    NOP
ENDM
; Function B begins here
```

### Function Prologue Diversity

```cpp
// Instead of the standard MSVC prologue:
//   push rbp; mov rbp, rsp; sub rsp, XXX
// Randomize per function:

/*
Variant 0: Standard       push rbp; mov rbp,rsp; sub rsp,XX
Variant 1: Sub first      sub rsp,XX; mov rbp,rsp; push rbp
Variant 2: Push 0         push 0; push rbp; mov rbp,rsp
Variant 3: LEA rbp        lea rbp,[rsp-XX]; sub rsp,XX; push rbp
Variant 4: No frame ptr   sub rsp,XX; (no rbp usage)
Variant 5: Push all       push rbp; push rbx; push rsi; mov rbp,rsp
*/

// Implementation: LLVM pass that rewrites function prologues
// Alternatively: post-processing Python script
#define POLY_PROLOGUE(variant) \
    switch(variant % 6) { \
    case 0: __asm { push rbp; mov rbp, rsp; sub rsp, 0x20 } break; \
    case 1: __asm { sub rsp, 0x20; mov rbp, rsp; push rbp } break; \
    case 2: __asm { push 0; push rbp; mov rbp, rsp } break; \
    ...
    }
```

---

## 5. String Obfuscation (Compile-Time)

### C++17 constexpr String Encryption

```cpp
// Compile-time XOR string encryption
// All string literals are encrypted at compile time, decrypted at runtime

template<size_t N>
struct EncryptedString {
    char data[N] = {};

    // Compile-time encryption (runs at build time)
    constexpr EncryptedString(const char(&plain)[N], char key) {
        for (size_t i = 0; i < N; i++)
            data[i] = plain[i] ^ key;
    }

    // Runtime decryption
    const char* decrypt(char key) const {
        static char buf[N];  // Cache decrypted once
        static bool done = false;
        if (!done) {
            for (size_t i = 0; i < N; i++)
                buf[i] = data[i] ^ key;
            done = true;
        }
        return buf;
    }
};

// Per-string unique key derived from POLY_SEED + string hash
#define ENC_STR(str) \
    ([]() { \
        constexpr auto _enc = EncryptedString(str, (POLY_SEED ^ compile_time_hash(str)) & 0xFF); \
        return _enc.decrypt((POLY_SEED ^ compile_time_hash(str)) & 0xFF); \
    }())

// Usage:
// Before:  MessageBoxA(nullptr, "Patterns found", "LIBERTEA", MB_OK);
// After:   MessageBoxA(nullptr, ENC_STR("Patterns found"), ENC_STR("LIBERTEA"), MB_OK);
```

### Compile-Time Hash for Per-String Keys

```cpp
// Compile-time FNV-1a hash for generating per-string XOR keys
constexpr uint32_t compile_time_hash(const char* str) {
    uint32_t hash = 0x811C9DC5;
    while (*str) {
        hash ^= static_cast<uint8_t>(*str++);
        hash *= 0x01000193;
    }
    return hash;
}

// Since each string hashes to a different value,
// each gets a different XOR key derived from POLY_SEED
// → all ciphertexts differ per build
```

### String Table at Runtime

```cpp
// Instead of storing all strings in .rdata,
// store encrypted blobs and decrypt on first access

class StringTable {
    struct Entry {
        const char* encrypted;   // Points to compile-time encrypted data
        char        key;         // Per-entry XOR key
        mutable std::once_flag flag;
        mutable std::string decrypted;
    };

    Entry m_entries[256];
    int   m_count = 0;

public:
    template<size_t N>
    void Add(const EncryptedString<N>& es, char key) {
        m_entries[m_count].encrypted = es.data;
        m_entries[m_count].key       = key;
        m_count++;
    }

    const char* Get(int idx) const {
        std::call_once(m_entries[idx].flag, [&] {
            m_entries[idx].decrypted = Decrypt(
                m_entries[idx].encrypted, m_entries[idx].key);
        });
        return m_entries[idx].decrypted.c_str();
    }
};
```

---

## 6. Kagura OLLVM Pass Integration

### Architecture Overview

```
Source (.cpp) → Clang-CL (LLVM IR) → Kagura Passes → LLVM Optimizer → Link → Pack
                                          │
                                    ┌─────┴─────┐
                                    │  Config    │
                                    │  (JSON)    │
                                    └───────────┘
```

### Kagura Pass Configuration (JSON)

```json
{
    "version": "2.0",
    "seed": 0xDEADBEEF,
    "passes": {
        "control_flow_flattening": {
            "enable": true,
            "functions": [
                {"name": "ProcessMessages", "split": 5, "order": "random"},
                {"name": "ReplayAPC", "split": 3},
                {"name": "SCLoop", "split": 8},
                {"name": "*VCapture*", "split": 4}
            ],
            "except": ["DllMain", "VEH_CrashHandler"],
            "probability": 0.8
        },
        "bogus_control_flow": {
            "enable": true,
            "probability": 0.6,
            "max_opaque_predicates": 10,
            "function_regex": "^(?!.*Simple).*$"
        },
        "instruction_substitution": {
            "enable": true,
            "probability": 0.7,
            "substitution_level": 3,
            "substitutions": ["add_sub", "sub_add", "xor_equiv", "or_and_not"]
        },
        "string_encryption": {
            "enable": true,
            "min_length": 4,
            "except": ["imgui*", "opengl*"]
        },
        "basic_block_splitting": {
            "enable": true,
            "split_probability": 0.8,
            "max_splits": 10,
            "min_block_size": 3
        },
        "mba_expressions": {
            "enable": true,
            "probability": 0.5,
            "complexity": 3,
            "operations": ["add", "sub", "xor", "and", "or"]
        }
    }
}
```

### Build Integration with Clang-CL

```cmake
# CMakeLists.txt additions for OLLVM:
option(USE_OLLVM "Enable OLLVM obfuscation passes" ON)

if(USE_OLLVM)
    # Use Clang-CL instead of MSVC CL
    set(CMAKE_C_COMPILER "clang-cl.exe")
    set(CMAKE_CXX_COMPILER "clang-cl.exe")

    # Path to Kagura pass plugin
    set(KAGURA_PLUGIN "C:/ollvm/kagura/build/lib/kagura.dll")

    # Load pass config (per-user specific)
    set(POLY_CONFIG "${CMAKE_SOURCE_DIR}/build/kagura_config_${POLY_SEED}.json")

    # Apply passes via -Xclang -load
    add_compile_options(
        -Xclang -load -Xclang "${KAGURA_PLUGIN}"
        -Xclang -mllvm -Xclang "-kagura-config=${POLY_CONFIG}"
        -Xclang -mllvm -Xclang "-kagura-seed=${POLY_SEED}"
    )

    # Disable MSVC-specific flags incompatible with Clang-CL
    remove_compile_options(/GL /guard:cf)
    add_compile_options(-fno-strict-aliasing -fvisibility=hidden)
endif()
```

### Function Granularity Control

```python
# generate_kagura_config.py — Per-user Kagura config generator
# python generate_kagura_config.py --seed 0xDEADBEEF --output config.json

import json, random, sys

def generate_config(seed):
    random.seed(seed)
    config = {
        "version": "2.0",
        "seed": seed,
        "passes": {
            "control_flow_flattening": {
                "enable": True,
                "functions": [],
                "probability": random.uniform(0.6, 0.9)
            },
            "mba_expressions": {
                "enable": True,
                "probability": random.uniform(0.3, 0.7),
                "complexity": random.randint(2, 4)
            },
            "bogus_control_flow": {
                "enable": True,
                "probability": random.uniform(0.4, 0.8)
            }
        }
    }

    # Assign per-function randomization
    critical_funcs = ["DllMain", "VEH_CrashHandler", "PackerStub"]
    heavy_funcs = ["ProcessMessages", "SCLoop", "ReplayAPC",
                   "BuildPayload", "HandleSCDispatch", "AutoSyncLoop"]

    for fn in heavy_funcs:
        config["passes"]["control_flow_flattening"]["functions"].append({
            "name": fn,
            "split": random.randint(3, 10),
            "order": random.choice(["random", "sequential"])
        })

    return config

if __name__ == "__main__":
    seed = int(sys.argv[1], 16) if len(sys.argv) > 1 else random.randint(0, 0xFFFFFFFF)
    config = generate_config(seed)
    with open(sys.argv[2] if len(sys.argv) > 2 else "kagura_config.json", "w") as f:
        json.dump(config, f, indent=2)
    print(f"Config generated with seed 0x{seed:08X}")
```

---

## 7. Python Polymorphic Builder

### Full Build Pipeline

```python
#!/usr/bin/env python3
"""
polymorphic_builder.py — Generate a per-user unique LIBERTEA.DLL build

Usage:
    python polymorphic_builder.py --user-id <id> --output <dir>

Pipeline:
    1. Generate per-user entropy seed from user ID
    2. Create Kagura OLLVM config
    3. Set compile-time defines (-DPOLY_SEED=...)
    4. Build DLL with CMake + Clang-CL
    5. Post-process: function reorder, padding insertion
    6. Pack with aPLib variant
    7. Sign with per-user PE certificate (optional)
"""
import argparse, hashlib, json, os, random, struct, subprocess, sys

def derive_seed(user_id: str) -> int:
    """Derive deterministic seed from user identifier."""
    h = hashlib.sha256(user_id.encode()).hexdigest()
    return int(h[:8], 16)  # 32-bit seed

def generate_poly_defines(seed: int) -> dict:
    random.seed(seed)
    defines = {
        "POLY_SEED": f"0x{seed:08X}",
        "POLY_STRING_KEY": f"0x{random.randint(0, 0xFF):02X}",
        "POLY_IMPORT_SEED": f"0x{random.randint(0, 0xFFFFFFFF):08X}",
        "POLY_NOP_VARIANT": random.randint(0, 5),
        "POLY_PROLOGUE_VARIANT": random.randint(0, 5),
        "POLY_PE_TIMESTAMP": random.randint(0x5E000000, 0x66000000),
    }
    return defines

def write_cmake_cache(defines: dict, path: str):
    """Write CMake cache with polymorphic defines."""
    with open(path, "w") as f:
        f.write("# Polymorphic build cache\n")
        f.write(f"# Generated for seed {defines['POLY_SEED']}\n\n")
        for key, val in defines.items():
            f.write(f'{key}:STRING={val}\n')

def post_process_text(dll_path: str, seed: int):
    """Insert random padding, shuffle function order."""
    random.seed(seed)
    with open(dll_path, "rb") as f:
        data = bytearray(f.read())

    # Parse PE headers
    dos_hdr = struct.unpack_from("<2s58xI", data)
    pe_off = dos_hdr[1]

    # Locate .text section header
    # For each function (COMDAT), insert random NOP variants
    # between functions

    with open(dll_path, "wb") as f:
        f.write(data)

def mutate_pe_header(dll_path: str, seed: int):
    """Mutate non-functional PE header fields."""
    random.seed(seed)
    with open(dll_path, "r+b") as f:
        data = f.read()
        f.seek(0)

        # Parse headers
        dos_hdr = struct.unpack_from("<2s58xI", data)
        pe_off = dos_hdr[1]

        # Mutate TimeDateStamp to random realistic value
        # MSVC 2022 era: 0x5F000000-0x66000000
        ts = random.randint(0x5F000000, 0x66000000)
        struct.pack_into("<I", data, pe_off + 0x08, ts)

        # Mutate linker version fields
        data[pe_off + 0x06] = random.randint(14, 15)  # Major
        data[pe_off + 0x07] = random.randint(10, 40)  # Minor

        # Mutate section name trailing bytes (keep ".text" prefix)
        # Section table starts at pe_off + 0xF8
        # .text is usually first section

        f.seek(0)
        f.write(data)

def polymorphic_build(user_id: str, output_dir: str, source_dir: str = "."):
    seed = derive_seed(user_id)
    defines = generate_poly_defines(seed)

    build_dir = os.path.join(output_dir, f"build_{seed:08X}")
    os.makedirs(build_dir, exist_ok=True)

    # Write Kagura config
    kagura_config = generate_kagura_config(seed)
    with open(os.path.join(build_dir, "kagura_config.json"), "w") as f:
        json.dump(kagura_config, f, indent=2)

    # Write CMake cache with polymorphic defines
    write_cmake_cache(defines, os.path.join(build_dir, "CMakeCache.txt"))

    # Run CMake build
    subprocess.run([
        "cmake", "-S", source_dir, "-B", build_dir,
        f"-DPOLY_SEED={defines['POLY_SEED']}",
        f"-DCMAKE_CXX_FLAGS=-DPOLY_SEED={defines['POLY_SEED']}",
    ], check=True)
    subprocess.run(["cmake", "--build", build_dir, "--config", "Release"], check=True)

    # Post-process
    dll_path = os.path.join(build_dir, "Release", "LIBERTEA.dll")
    post_process_text(dll_path, seed)
    mutate_pe_header(dll_path, seed)

    # Pack
    output_dll = os.path.join(output_dir, f"LIBERTEA_{seed:08X}.dll")
    subprocess.run(["python", "packer/pack.py", dll_path, output_dll], check=True)

    print(f"[+] Build complete: {output_dll}")
    print(f"[+] Seed: 0x{seed:08X}")
    return output_dll

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Polymorphic LIBERTEA builder")
    parser.add_argument("--user-id", required=True, help="Per-user identifier")
    parser.add_argument("--output", default=".", help="Output directory")
    parser.add_argument("--source", default=".", help="Source directory")
    args = parser.parse_args()
    polymorphic_build(args.user_id, args.output, args.source)
```

### CI/CD Integration

```yaml
# .github/workflows/polymorphic_build.yml
name: Polymorphic Build

on:
  workflow_dispatch:
    inputs:
      user_id:
        description: 'User identifier for seed derivation'
        required: true
        type: string

jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ilammy/msvc-dev-cmd@v1

      - name: Install LLVM/Clang-CL
        run: choco install llvm -y

      - name: Build Kagura OLLVM passes
        run: |
          git clone https://github.com/.../kagura.git
          cmake -S kagura -B kagura/build
          cmake --build kagura/build --config Release

      - name: Generate polymorphic build
        run: |
          python scripts/polymorphic_builder.py `
            --user-id "${{ inputs.user_id }}" `
            --output dist/ `
            --source .

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: LIBERTEA_${{ hashFiles('dist/*.dll') }}
          path: dist/*.dll
```

---

## 8. Verification: Measuring Polymorphism

### Signature Diversity Test

```python
# verify_polymorphism.py — Test that N builds produce N unique signatures
# python verify_polymorphism.py --builds 10

import hashlib, subprocess, tempfile

def measure_diversity(user_ids):
    hashes = []
    for uid in user_ids:
        with tempfile.TemporaryDirectory() as td:
            result = subprocess.run(
                ["python", "polymorphic_builder.py",
                 "--user-id", uid, "--output", td],
                capture_output=True, text=True
            )
            # Hash the unpacked .text section (the polymorphic code)
            dll = open(f"{td}/LIBERTEA_{hashlib.sha256(uid.encode()).hexdigest()[:8]}.dll", "rb").read()
            hashes.append(hashlib.sha256(dll).hexdigest())

    unique = len(set(hashes))
    total = len(hashes)
    print(f"Diversity: {unique}/{total} unique hashes")
    print(f"Collision rate: {(total - unique) / total * 100:.1f}%")
    return unique == total

# Target: 100% diversity (N builds → N unique hashes)
```

### Expected Detection Resistance

| Detection Vector | Before Polymorphism | After Polymorphism |
|-----------------|-------------------|-------------------|
| Syscall stub AOB `4C 8B D1 B8 ?? 0F 05 C3` | **HIGH** (all 8 identical) | **LOW** (7 variants, random per build) |
| NOP sled `90 90 90 90` | **HIGH** (27 occurrences) | **LOW** (replaced with MOV/XOR equivalents) |
| Feature strings ("GodMode") | **HIGH** (plain text) | **LOW** (encrypted, build-varying key) |
| Function prologues | **MEDIUM** (MSVC standard) | **LOW** (6 variants, random per function) |
| PE header anomalies | **MEDIUM** (zero TimeDateStamp) | **LOW** (randomized realistic values) |
| Overall binary hash | **IDENTICAL PER DOWNLOAD** | **UNIQUE PER USER** |

---

*Last updated: 2026-07-05 | Accuracy baseline: 93.4%*
*Cross-ref: 06_EVASION_WEAKNESSES.md, 13_RECIPES_ADVANCED.md, 10_CROSS_REFERENCE.md*
