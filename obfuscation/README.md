# OLLVM Obfuscation Pipeline — LIBERTEA.DLL v414

## Overview

The current cheat uses standard MSVC `/O2` output with zero obfuscation — fully readable in IDA/Ghidra after unpacking. This pipeline adds LLVM-based obfuscation passes to produce build-time polymorphic binaries.

**Strategy:** Replace MSVC `cl.exe` with `clang-cl.exe` (Clang-CL), a drop-in replacement that accepts MSVC-style flags and emits COFF objects compatible with MSVC `link.exe`. OLLVM-style passes are loaded as LLVM plugins.

## Architecture

```
Source (.c/.cpp)
    |
    v
clang-cl.exe -fpass-plugin=obfuscation.dll  (replaces cl.exe)
    |
    v
MSVC link.exe (unchanged)
    |
    v
Obfuscated .dll/.exe
```

## Prerequisites

### 1. Install LLVM 18+ with Clang-CL

**Option A — Official binary (recommended):**
```
Download from https://github.com/llvm/llvm-project/releases (LLVM 18.1.x+)
Run installer, select "Add LLVM to PATH"
```

**Option B — Chocolatey:**
```
choco install llvm
```

**Option C — Build from source:**
```
git clone --branch release/18.x https://github.com/llvm/llvm-project.git
cd llvm-project
cmake -S llvm -B build -G "Visual Studio 17 2022" -DLLVM_ENABLE_PROJECTS="clang" -DLLVM_TARGETS_TO_BUILD=X86
cmake --build build --config Release
```

### 2. Verify Clang-CL works
```batch
clang-cl --version
clang-cl /?   (MSVC-compatible flags)
```

### 3. Build the obfuscation passes

Using the provided build script:
```batch
cd obfuscation\passes
clang-cl /EHsc /std:c++20 /I<LLVM_INCLUDE_DIR> /LD *.cpp /Fe:obfuscation.dll
```

Or with CMake:
```cmake
cmake_minimum_required(VERSION 3.26)
project(ObfuscationPasses)

find_package(LLVM REQUIRED CONFIG)
include_directories(${LLVM_INCLUDE_DIRS})

add_library(obfuscation SHARED
    passes/string_encrypt.cpp
    passes/cfg_flatten.cpp
    passes/bogus_cfg.cpp
    passes/function_split.cpp
)
target_link_libraries(obfuscation ${LLVM_LIBS})
```

## Usage

### Compile with obfuscation enabled
```batch
build_obfuscated.bat
```

Or manually:
```batch
set CC=clang-cl.exe
set CFLAGS=/O2 /GS- /fpass-plugin=obfuscation.dll
set CFLAGS=%CFLAGS% -mllvm -enable-cfg-flatten
set CFLAGS=%CFLAGS% -mllvm -enable-string-encrypt
set CFLAGS=%CFLAGS% -mllvm -enable-bogus-cfg
set CFLAGS=%CFLAGS% -mllvm -enable-function-split

%CC% %CFLAGS% /c source.cpp
link /DLL /OUT:target.dll source.obj
```

### Run passes as post-process
```batch
pass_runner.exe --input target.dll --output target_obf.dll ^
    --passes cfg_flatten,bogus_cfg,string_encrypt ^
    --funcs "sub_*,?sendPacket@"
```

## Pass Descriptions

| Pass | Flag | Effect |
|------|------|--------|
| String Encryption | `-enable-string-encrypt` | XOR-encrypts .rdata strings; decrypts at each use site |
| CFG Flattening | `-enable-cfg-flatten` | Converts selected functions to switch-dispatch loop |
| Bogus CFG | `-enable-bogus-cfg` | Inserts dead blocks with MBA-based opaque predicates |
| Function Split | `-enable-function-split` | Splits large functions, randomizes sub-function layout |

## Opaque Predicates (MBA)

See `example_mba.h` for reusable macros:
- `OPAQUE_TRUE(expr)` — block always taken
- `OPAQUE_FALSE(expr)` — block never taken
- `OPAQUE_SWITCH(seed, range)` — deterministic dispatch value

## Anti-Analysis Properties

1. **Polymorphism:** Each build produces different encryption keys, different block layouts, different opaque predicate structure
2. **MBA complexity:** Mixed Boolean-Arithmetic expressions resist SMT solvers (e.g., `(x ^ y) + 2*(x & y) == x + y`)
3. **Call graph obfuscation:** Function splitting + trampolines break static call graph recovery
4. **String resistance:** Constant strings are encrypted until the moment of use; cross-references are hidden

## Limitations

- Debugging obfuscated code is extremely difficult (by design)
- OLLVM passes may increase binary size 2-5x depending on function count
- Some antivirus engines may flag LLVM-compiled code (mitigate by signing)
- Not all LLVM passes compose well with exception handling (`/EHa`)
