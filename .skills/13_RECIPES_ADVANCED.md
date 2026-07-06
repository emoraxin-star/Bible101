# 13_RECIPES_ADVANCED.md
# Advanced Implementation Recipes

Step-by-step recipes for game state interaction, anti-debug, build system, SIMD scanning, and syscall diversity.

---

## Table of Contents

1. [GAP-D: Game State Interaction](#1-game-state-interaction-recipes)
2. [GAP-E: Anti-Debug Implementation](#2-anti-debug-implementation)
3. [GAP-F: Build System Specification](#3-build-system-specification)
4. [GAP-H: SIMD Pattern Scanner](#4-simd-pattern-scanner)
5. [GAP-I: Syscall Stub Diversity](#5-syscall-stub-diversity)

---

## 1. Game State Interaction Recipes

### 1.1 Reading War Time

War time is embedded in mission data at offset `+0x38`. The value is seconds since war start.

```cpp
// warTime = *(uint32_t*)(missionData + 0x38)
uint32_t ReadWarTime() {
    uintptr_t ptrAddr = gameBase + GS::rv_gp4;     // ServerInfo global
    uintptr_t serverInfo = 0;
    SIZE_T rd = 0;
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)ptrAddr,
                      &serverInfo, 8, &rd);
    if (!serverInfo) return 0;

    // ServerInfo+ringIndex → slot → missionData → warTime
    uint32_t ringIndex = 0;
    ReadProcessMemory(GetCurrentProcess(),
        (LPCVOID)(serverInfo + GS::OFF_RING_INDEX), &ringIndex, 4, &rd);

    uintptr_t ringBase = 0;
    ReadProcessMemory(GetCurrentProcess(),
        (LPCVOID)(serverInfo + GS::OFF_RING_BASE), &ringBase, 8, &rd);
    if (!ringBase) return 0;

    uint32_t slotIdx = ringIndex & GS::RING_SLOT_MASK;
    uintptr_t slot = ringBase + slotIdx * GS::RING_SLOT_SIZE;

    uintptr_t missionData = 0;
    ReadProcessMemory(GetCurrentProcess(),
        (LPCVOID)(slot + 0xC10), &missionData, 8, &rd);  // serialObj
    if (!missionData) return 0;

    uint32_t warTime = 0;
    ReadProcessMemory(GetCurrentProcess(),
        (LPCVOID)(missionData + 0x38), &warTime, 4, &rd);
    return warTime;
}

// War time update for replay:
uint32_t AdvanceWarTime(uint32_t capturedWarTime, uint64_t captureTick) {
    uint64_t now = GetTickCount64();
    uint32_t elapsed = (uint32_t)((now - captureTick) / 1000);
    return capturedWarTime + elapsed;
}
```

### 1.2 Traversing ServerInfo

```cpp
// Full ServerInfo traversal:
struct ServerInfoAccess {
    uintptr_t base;          // ServerInfo base address
    uint32_t  ringIndex;     // Current write index
    uintptr_t ringBase;      // Ring buffer base
    uint32_t  flag;          // Flags
    char      url[64];       // Base API URL
    int32_t   queueDelta;    // Queue processing delta
    uint8_t*  requestBuffer; // Request queue

    static ServerInfoAccess Read(uintptr_t gameBase) {
        ServerInfoAccess sia = {};
        uintptr_t ptrAddr = gameBase + GS::rv_gp4;
        SIZE_T rd = 0;

        ReadProcessMemory(GetCurrentProcess(), (LPCVOID)ptrAddr,
                          &sia.base, 8, &rd);
        if (!sia.base) return sia;

        ReadProcessMemory(GetCurrentProcess(),
            (LPCVOID)(sia.base + GS::OFF_RING_INDEX), &sia.ringIndex, 4, &rd);
        ReadProcessMemory(GetCurrentProcess(),
            (LPCVOID)(sia.base + GS::OFF_RING_BASE), &sia.ringBase, 8, &rd);
        ReadProcessMemory(GetCurrentProcess(),
            (LPCVOID)(sia.base + GetSIFlagOff()), &sia.flag, 4, &rd);
        ReadProcessMemory(GetCurrentProcess(),
            (LPCVOID)(sia.base + GetSIUrlOff()), &sia.url, 64, &rd);
        ReadProcessMemory(GetCurrentProcess(),
            (LPCVOID)(sia.base + GetSIQueueOff()), &sia.queueDelta, 4, &rd);
        return sia;
    }
};
```

### 1.3 Reading Peer List (Lobby Sync)

```cpp
// Poll PeerManager for lobby player IDs:
struct PeerInfo {
    uint64_t ids[4];         // Up to 4 peer IDs
    int      count;           // Number of peers found
};

PeerInfo ReadPeerList(uintptr_t gameBase) {
    PeerInfo pi = {};
    uintptr_t ptrAddr = gameBase + GS::rv_gp7;        // PeerManager global
    uintptr_t peerMgr = 0;
    SIZE_T rd = 0;

    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)ptrAddr,
                      &peerMgr, 8, &rd);
    if (!peerMgr) return pi;

    uint32_t peerCount = 0;
    ReadProcessMemory(GetCurrentProcess(),
        (LPCVOID)(peerMgr + GetPeerMgrCountOff()), &peerCount, 4, &rd);
    if (peerCount > 4) peerCount = 4;

    uint32_t scanMax = (peerCount < 4) ? peerCount + 1 : 4;
    for (uint32_t i = 0; i < scanMax && pi.count < 4; i++) {
        uintptr_t slotAddr = peerMgr + GetPeerMgrSlotOff() + (uintptr_t)i * 0x20;
        uint64_t pid = 0;
        ReadProcessMemory(GetCurrentProcess(), (LPCVOID)slotAddr,
                          &pid, 8, &rd);
        if (pid != 0) {
            bool dup = false;
            for (int d = 0; d < pi.count; d++)
                if (pi.ids[d] == pid) { dup = true; break; }
            if (!dup) pi.ids[pi.count++] = pid;
        }
    }
    return pi;
}

// AutoSync loop (runs on T1):
void SCAutoSyncLoop() {
    uintptr_t gameBase = (uintptr_t)GetModuleHandleA("game.dll");
    while (!s_scAutoSyncStop.load()) {
        PeerInfo pi = ReadPeerList(gameBase);
        if (pi.count > 0) {
            std::lock_guard<std::mutex> lk(s_scIdsMutex);
            // Update shared peer ID array for ScLoop to use
            memcpy(s_scIds, pi.ids, sizeof(uint64_t) * pi.count);
            s_scIdCount = pi.count;
        }
        for (int i = 0; i < 20 && !s_scAutoSyncStop.load(); i++)
            Sleep(100);  // Total: ~2s per poll
    }
}
```

### 1.4 Reading PlayerSession

```cpp
// Access current PlayerSession for mission data:
struct SessionAccess {
    uintptr_t session;          // SessionData base
    uintptr_t liveEntity;       // Player entity pointer (+0x10)
    uintptr_t playerSession;    // PlayerSession (if directly accessible)
    char      missionId[64];    // Current mission UUID
    uint32_t  difficulty;       // Current difficulty

    static SessionAccess Read(uintptr_t gameBase) {
        SessionAccess sa = {};
        uintptr_t ptrAddr = gameBase + GS::rv_gp3;     // SessionData global
        uintptr_t pSD = 0;
        SIZE_T rd = 0;
        ReadProcessMemory(GetCurrentProcess(), (LPCVOID)ptrAddr,
                          &pSD, 8, &rd);
        if (!pSD) return sa;

        ReadProcessMemory(GetCurrentProcess(),
            (LPCVOID)pSD, &sa.session, 8, &rd);
        if (!sa.session) return sa;

        ReadProcessMemory(GetCurrentProcess(),
            (LPCVOID)(sa.session + 0x10), &sa.liveEntity, 8, &rd);

        // If we have a direct PlayerSession pointer:
        // PlayerSession+0x70 = missionId[64]
        // PlayerSession+0x30 = difficulty (approximate)
        return sa;
    }
};
```

---

## 2. Anti-Debug Implementation

### 2.1 Self-Integrity Checking (CRC32C)

```cpp
#include <intrin.h>  // _mm_crc32_u64

class IntegrityChecker {
    // Region descriptor for hashing
    struct Region {
        const char* name;
        uint8_t*    base;
        size_t      size;
        uint32_t    expectedCrc;  // Computed at build time
    };

    Region m_regions[16];
    int    m_regionCount = 0;

public:
    void AddRegion(const char* name, uint8_t* base, size_t size) {
        if (m_regionCount >= 16) return;
        Region& r = m_regions[m_regionCount++];
        r.name = name;
        r.base = base;
        r.size = size;
        r.expectedCrc = ComputeCrc32c(base, size);
    }

    // Layer 1: CRC32C of .text section (fast, coarse)
    static uint32_t ComputeCrc32c(uint8_t* data, size_t len) {
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < len; i++)
            crc = _mm_crc32_u8(crc, data[i]);
        return crc ^ 0xFFFFFFFF;
    }

    // Layer 2: Per-block hash (finer granularity, detects small patches)
    struct BlockHash {
        uint32_t  offset;  // Block start offset from region base
        uint32_t  size;    // Block size
        uint32_t  crc;     // Expected CRC32C
    };

    // Layer 3: IAT integrity (verifies import stubs point to system DLLs)
    bool VerifyImportStubs() {
        // Walk the import resolution table at RVA 0x1000-0x2000
        // Verify each resolved address belongs to a system DLL
        // via QueryVirtualMemoryInformation
        return true;
    }

    // Layer 4: Stack integrity (detect hooked return addresses)
    bool CheckStackIntegrity() {
        // Walk stack frames via RtlCaptureStackBackTrace
        // Verify each return address is within known modules
        return true;
    }

    // Layer 5: Server-side challenge
    // Periodically send a random challenge nonce to C2 server
    // Server responds with expected hash of .text section
    // If mismatch → detected tampering

    bool VerifyAll() {
        for (int i = 0; i < m_regionCount; i++) {
            Region& r = m_regions[i];
            uint32_t crc = ComputeCrc32c(r.base, r.size);
            if (crc != r.expectedCrc) {
                // Integrity violation — take action
                LogIntegrityFailure(r.name);
                return false;
            }
        }
        return true;
    }

    // Background integrity thread
    static DWORD WINAPI IntegrityThread(LPVOID ctx) {
        IntegrityChecker* self = (IntegrityChecker*)ctx;
        while (true) {
            Sleep(30000);  // Check every 30s
            if (!self->VerifyAll()) {
                // CRC mismatch — trigger crash or self-unload
                // Self-destruct: corrupt own code to force crash
                memset(self->m_regions[0].base, 0xCC, 16);
                break;
            }
        }
        return 0;
    }
};
```

### 2.2 Hardware Breakpoint Detection

```cpp
bool DetectHardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Use direct syscall to avoid hooked GetThreadContext
    if (!SysNtGetContextThread(GetCurrentThread(), &ctx))
        return false;

    // Check DR0-DR3 for set breakpoints
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
        return true;  // Hardware breakpoint detected!

    // Check DR6 for breakpoint condition flags
    if (ctx.Dr6 & 0x0F)  // B0-B3 bits indicate breakpoint hit
        return true;

    // Check DR7 for enabled breakpoints
    if (ctx.Dr7 & 0xFF)  // L0-G3 enable bits
        return true;

    return false;
}

// Per-thread breakpoint scan:
bool ScanThreadsForBreakpoints() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te = { sizeof(te) };
    DWORD ourPid = GetCurrentProcessId();
    bool found = false;

    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID != ourPid) continue;
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT |
                                    THREAD_SUSPEND_RESUME,
                                    FALSE, te.th32ThreadID);
        if (!hThread) continue;

        SuspendThread(hThread);
        CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
        if (SysNtGetContextThread(hThread, &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 ||
                (ctx.Dr7 & 0xFF)) {
                found = true;
                // Optional: clear breakpoints
                ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
                ctx.Dr7 = 0;
                SysNtSetContextThread(hThread, &ctx);
            }
        }
        ResumeThread(hThread);
        CloseHandle(hThread);
    } while (Thread32Next(snap, &te));

    CloseHandle(snap);
    return found;
}
```

### 2.3 VM/Sandbox Detection

```cpp
class SandboxDetector {
public:
    // Check 1: Timing — RDTSC differential
    static bool DetectHypervisor() {
        uint64_t tsc1 = __rdtsc();
        Sleep(100);
        uint64_t tsc2 = __rdtsc();
        uint64_t diff = tsc2 - tsc1;

        // Real hardware: ~300K-500K ticks per 100ms
        // VM: ~1M-5M ticks (hypervisor overhead)
        return (diff > 5000000);  // Threshold varies by CPU
    }

    // Check 2: Registry artifacts
    static bool DetectVMRegistry() {
        HKEY hk;
        const wchar_t* artifacts[] = {
            L"SYSTEM\\CurrentControlSet\\Services\\VMTools",
            L"HARDWARE\\ACPI\\FADT\\TABLE\\VMW",
            L"SOFTWARE\\VMware\\VMware Tools",
            L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        };
        for (auto* path : artifacts) {
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0,
                              KEY_READ, &hk) == ERROR_SUCCESS) {
                RegCloseKey(hk);
                return true;  // VM artifact found
            }
        }
        return false;
    }

    // Check 3: Hardware — CPUID hypervisor bit
    static bool DetectCPUID() {
        int cpuInfo[4] = {};
        __cpuid(cpuInfo, 1);
        // Bit 31 of ECX = hypervisor present
        return (cpuInfo[2] & (1 << 31)) != 0;
    }

    // Check 4: MAC address prefix
    static bool DetectVMMac() {
        // Common VM MAC prefixes:
        // 00:05:69 (VMware), 00:0C:29 (VMware),
        // 08:00:27 (VirtualBox), 00:1C:42 (Parallels)
        // Implementation via GetAdaptersInfo
        return false;
    }

    // Check 5: Disk size (VMs typically have small disks)
    static bool DetectSmallDisk() {
        ULARGE_INTEGER freeBytes, totalBytes;
        if (GetDiskFreeSpaceExW(L"C:\\", nullptr, &totalBytes, &freeBytes)) {
            // VMs often have < 100GB
            return totalBytes.QuadPart < 100LL * 1024 * 1024 * 1024;
        }
        return false;
    }

    static bool IsSandbox() {
        int score = 0;
        if (DetectHypervisor()) score += 2;
        if (DetectCPUID()) score += 1;
        if (DetectVMRegistry()) score += 3;
        if (DetectSmallDisk()) score += 1;
        return score >= 3;
    }
};
```

### 2.4 Anti-Debug Integration (Packer Stub)

```cpp
// Add to packer stub (before decompression):
void PackerAntiDebug() {
    // Check 1: PEB BeingDebugged flag
    uint8_t beingDebugged = *(uint8_t*)(__readgsqword(0x60) + 2);
    if (beingDebugged) {
        // Debugger attached — crash or infinite loop
        while (1) __ud2();  // UD2 = undefined instruction
    }

    // Check 2: NtGlobalFlag
    uint32_t ntGlobalFlag = *(uint32_t*)(__readgsqword(0x60) + 0xBC);
    if (ntGlobalFlag & 0x70) {  // FLG_HEAP_ENABLE_TAIL_CHECK |
                                 // FLG_HEAP_ENABLE_FREE_CHECK |
                                 // FLG_HEAP_VALIDATE_PARAMETERS
        while (1) __ud2();
    }

    // Check 3: Direct syscall NtQueryInformationProcess
    // SSN resolved from PEB (Hades Gate), not disk
    uint32_t ssn = ResolveSSN(GetNtdllBase(),
                              "NtQueryInformationProcess");
    NTSTATUS status;
    DWORD debugPort = 0;
    BuildIndirectSyscall(ssn, NtCurrentProcess(),
                         ProcessDebugPort, &debugPort,
                         sizeof(debugPort), nullptr);
    if (debugPort != 0) {
        while (1) __ud2();
    }
}
```

---

## 3. Build System Specification

### 3.1 Directory Structure

```
LIBERTEA/
├── CMakeLists.txt              # Top-level build
├── src/
│   ├── main.cpp                # DllMain + init
│   ├── hook_installer.cpp      # Pattern scanning + hook installation
│   ├── pattern_data.cpp        # 73-pattern table
│   ├── overlay.cpp             # ImGui overlay
│   ├── network/
│   │   ├── http_monitor.cpp    # libcurl hooks
│   │   └── farming.cpp         # SC/Medal state machine
│   ├── probe/
│   │   ├── probe.cpp           # HW breakpoint capture
│   │   └── replay.cpp          # Replay orchestrator
│   └── syscall/
│       ├── stub_builder.cpp    # SSN resolution + stub construction
│       └── indirect_x64.asm    # Indirect syscall assembly
├── include/
│   ├── offsets.h               # Game DLL RVAs
│   ├── state.h                 # ReplayState, CapturedMission
│   └── scanner.h               # AOBPattern
├── packer/
│   └── pack.py                 # aPLib compression + PE rewriting
└── external/
    ├── imgui/                  # Dear ImGui v1.91.5
    └── hde64/                  # Length-disassembler engine
```

### 3.2 CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.20)
project(LIBERTEA VERSION 4.14 LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")  # /MT (static CRT)

# Compiler flags matching v414
add_compile_options(
    /O1                    # Minimize size
    /Os                    # Favor size over speed
    /Oi                    # Generate intrinsic functions
    /Oy-                   # No frame pointer omission (for stack tracing)
    /Ob2                   # Inline expansion level 2
    /GF                    # String pooling
    /Gy                    # Function-level linking
    /GL                    # Whole program optimization
    /std:c++17
    /W4                    # Warning level 4
    /WX-                   # Warnings not fatal
    /guard:cf              # Control Flow Guard
    /DYNAMICBASE
    /HIGHENTROPYVA
    /NXCOMPAT
)

# Linker flags
add_link_options(
    /LTCG                  # Link-time code generation
    /OPT:REF               # Remove unreferenced functions
    /OPT:ICF               # Identical COMDAT folding
    /ENTRY:0x3C4F30        # Entry point in .rsrc (packer sets this)
    /MERGE:.rdata=.text    # Merge read-only data into .text
    /NODEFAULTLIB          # No default libraries (static CRT only)
    /SECTION:.text,RXW     # Allow RWX (packer decompressor needs write)
)

# Sources
file(GLOB_RECURSE LIBERTEA_SOURCES
    src/*.cpp src/*.h include/*.h
    external/imgui/*.cpp external/imgui/*.h
    external/hde64/*.cpp external/hde64/*.h
)

# Assembly sources (indirect syscalls)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
    set(ASM_SOURCES src/syscall/indirect_x64.asm)
    enable_language(ASM_MASM)
endif()

add_library(${PROJECT_NAME} SHARED
    ${LIBERTEA_SOURCES} ${ASM_SOURCES}
)

target_include_directories(${PROJECT_NAME} PRIVATE
    include external/imgui external/hde64
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    kernel32 user32 gdi32 advapi32 ws2_32 opengl32 bcrypt winhttp
)

# Post-build: pack the DLL
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND python ${CMAKE_SOURCE_DIR}/packer/pack.py
        $<TARGET_FILE:${PROJECT_NAME}>
        ${CMAKE_SOURCE_DIR}/output/LIBERTEA_packed.dll
    COMMENT "Packing LIBERTEA.DLL with custom aPLib variant..."
)
```

### 3.3 Packer Pipeline (Python)

```python
#!/usr/bin/env python3
"""
pack.py — 3-Phase LIBERTEA Packer

Phase 1: Compress .text section with custom aPLib variant
Phase 2: Replace .text with stub (zero-size on disk)
Phase 3: Set entry point to .rsrc packer stub

Usage: python pack.py input.dll output.dll
"""
import struct, sys

def pack_aplib_variant(data: bytes) -> bytes:
    """Custom aPLib variant with bit-inverted gamma + SAR offset encoding.
    (See 02_PACKER_CRYPTO.md for algorithm spec.)"""
    # Implementation matches the decompression pseudocode in 00_MASTER
    raise NotImplementedError("See aPLib compressor reference")

def rewrite_pe(input_path: str, output_path: str):
    with open(input_path, 'rb') as f:
        dll = bytearray(f.read())

    # Parse DOS/PE headers
    dos_hdr = struct.unpack_from('<2s58xI', dll)
    pe_offset = dos_hdr[1]
    pe_sig = struct.unpack_from('<4s', dll, pe_offset)[0]
    assert pe_sig == b'PE\0\0', "Not a valid PE"

    # Locate .text section
    # For each section header: check name, modify raw size to 0,
    # store compressed payload in .rsrc #1, set characteristics

    # Set entry point to packer stub at RVA 0x3C4F30
    struct.pack_into('<I', dll, pe_offset + 0x28, 0x3C4F30)

    # Zero out TimeDateStamp
    struct.pack_into('<I', dll, pe_offset + 0x08, 0)

    with open(output_path, 'wb') as f:
        f.write(dll)

if __name__ == '__main__':
    rewrite_pe(sys.argv[1], sys.argv[2])
```

### 3.4 Compiler & Toolchain Versions

| Tool | Version | Purpose |
|------|---------|---------|
| MSVC | 19.40 (VS 2022 17.8+) | C++ compilation |
| CMake | 3.20+ | Build system |
| Python | 3.10+ | Packer script |
| MASM | (VS bundled) | Assembly stubs |
| ImGui | 1.91.5 | GUI overlay |
| hde64 | (public domain) | x64 length disassembler |

---

## 4. SIMD Pattern Scanner

### 4.1 AVX2 Scanner (32 bytes per instruction)

```cpp
#include <immintrin.h>  // _mm256_*

// Scan for a single pattern with wildcards using AVX2
uintptr_t ScanAVX2(const uint8_t* haystack, size_t haystackLen,
                   const uint8_t* pattern, const uint8_t* mask,
                   size_t patternLen) {
    if (patternLen > 32) return ScanByteByByte(haystack, haystackLen,
                                                pattern, mask, patternLen);

    // Precompute: for SIMD, we need to handle wildcards
    // Strategy: mask bytes where mask[i] == 0x00 to 0x00 in pattern
    // so they always compare equal
    alignas(32) uint8_t pat32[32] = {};
    alignas(32) uint8_t msk32[32] = {};
    memcpy(pat32, pattern, patternLen);
    memcpy(msk32, mask, patternLen);

    // For wildcard bytes: set pattern byte to 0, mask byte to 0
    // so the comparison always matches
    for (size_t i = 0; i < patternLen; i++) {
        if (msk32[i] == 0x00) pat32[i] = 0;  // Wildcard: match anything
    }

    // Invert mask: AVX compare needs 1 bits = must-match positions
    // _mm256_cmpeq_epi8 sets 0xFF on match, 0x00 on mismatch
    // We OR with (~mask) to ignore wildcard positions

    __m256i vPat = _mm256_loadu_si256((__m256i*)pat32);
    __m256i vMsk = _mm256_loadu_si256((__m256i*)msk32);
    __m256i vInvMsk = _mm256_xor_si256(vMsk,
                       _mm256_set1_epi32(0xFFFFFFFF));

    for (size_t i = 0; i <= haystackLen - patternLen; i += 32) {
        // Load 32 bytes from haystack
        __m256i vHay = _mm256_loadu_si256((__m256i*)(haystack + i));

        // Compare with pattern
        __m256i vCmp = _mm256_cmpeq_epi8(vHay, vPat);

        // OR with inverted mask (wildcards become matching)
        __m256i vResult = _mm256_or_si256(vCmp, vInvMsk);

        // Check if all 32 bytes matched (movemask == 0xFFFFFFFF)
        int maskResult = _mm256_movemask_epi8(
            _mm256_cmpeq_epi8(vResult, _mm256_set1_epi32(0xFFFFFFFF)));

        if (maskResult == 0xFFFFFFFF) {
            // Full match — verify exact bytes for patterns < 32
            return (uintptr_t)(haystack + i);
        }
    }
    return 0;
}

// Batch scanner: scan all 73 patterns in one pass
typedef struct {
    uintptr_t address;
    uint32_t  patternId;
    int32_t   offset;
} ScanResult;

int ScanAllPatternsAVX2(const uint8_t* textStart, size_t textSize,
                        const PatternEntry* patterns, int numPatterns,
                        ScanResult* results, int maxResults) {
    int found = 0;
    for (int p = 0; p < numPatterns && found < maxResults; p++) {
        uintptr_t addr = ScanAVX2(textStart, textSize,
                                  patterns[p].bytes,
                                  patterns[p].mask,
                                  16);  // All patterns are 16 bytes padded
        if (addr) {
            results[found].address   = addr + patterns[p].offset;
            results[found].patternId = patterns[p].patternId;
            results[found].offset    = patterns[p].offset;
            found++;
        }
    }
    return found;
}
```

### 4.2 SSE2 Fallback (16 bytes, no AVX2)

```cpp
#include <emmintrin.h>  // _mm_*

uintptr_t ScanSSE2(const uint8_t* haystack, size_t haystackLen,
                   const uint8_t* pattern, const uint8_t* mask,
                   size_t patternLen) {
    if (patternLen > 16) return ScanByteByByte(haystack, haystackLen,
                                                pattern, mask, patternLen);
    alignas(16) uint8_t pat16[16] = {};
    alignas(16) uint8_t msk16[16] = {};
    memcpy(pat16, pattern, patternLen);
    memcpy(msk16, mask, patternLen);

    for (size_t i = 0; i < patternLen; i++)
        if (msk16[i] == 0x00) pat16[i] = 0;

    __m128i vPat = _mm_loadu_si128((__m128i*)pat16);
    __m128i vInvMsk = _mm_xor_si128(
        _mm_loadu_si128((__m128i*)msk16),
        _mm_set1_epi32(0xFFFFFFFF));

    for (size_t i = 0; i <= haystackLen - patternLen; i += 16) {
        __m128i vHay = _mm_loadu_si128((__m128i*)(haystack + i));
        __m128i vCmp = _mm_cmpeq_epi8(vHay, vPat);
        __m128i vResult = _mm_or_si128(vCmp, vInvMsk);

        if (_mm_movemask_epi8(
                _mm_cmpeq_epi8(vResult, _mm_set1_epi32(0xFFFFFFFF))) == 0xFFFF)
            return (uintptr_t)(haystack + i);
    }
    return 0;
}
```

### 4.3 Boyer-Moore Integration

```cpp
// Boyer-Moore skip table for faster non-matching scans
// Use SIMD for first pass, then Boyer-Moore for verification
class BoyerMooreScanner {
    int m_skip[256];  // Bad character skip table
    size_t m_patternLen;

public:
    BoyerMooreScanner(const uint8_t* pattern, size_t len,
                      const uint8_t* mask) {
        m_patternLen = len;
        for (int i = 0; i < 256; i++)
            m_skip[i] = (int)len;
        for (size_t i = 0; i < len; i++) {
            if (mask[i] == 0xFF)  // Only skip on non-wildcard bytes
                m_skip[pattern[i]] = (int)(len - 1 - i);
        }
    }

    int Skip(uint8_t byte) const { return m_skip[byte]; }
};
```

---

## 5. Syscall Stub Diversity

### 5.1 Stub Variant Templates

```cpp
// Base stub: MOV R10, RCX; MOV EAX, SSN; SYSCALL; RET
// Variants randomize register allocation, instruction order, and junk

enum StubVariant : uint8_t {
    STUB_STANDARD    = 0,  // Same as original (4C 8B D1 B8 XX 0F 05 C3)
    STUB_ORDER_SWAP  = 1,  // MOV EAX first, then MOV R10, RCX
    STUB_STACK_SHUFF = 2,  // PUSH/POP around the call
    STUB_XOR_SSN     = 3,  // XOR-obfuscated SSN
    STUB_REX_ROTATE  = 4,  // Rotate REX prefixes
    STUB_JUNK_NOP    = 5,  // Random NOP/MOV/LEA between instructions
    STUB_INDIRECT    = 6,  // Indirect syscall with return spoofing
    STUB_PER_CALL    = 7,  // Fully dynamic per-call (stealth_call style)
};
```

### 5.2 Per-Variant Builder

```cpp
class StubBuilder {
    uint8_t  m_buf[64];   // Max stub size
    int      m_off = 0;

public:
    // Variant 0: Standard (for comparison)
    void BuildStandard(uint32_t ssn) {
        m_buf[m_off++] = 0x4C; m_buf[m_off++] = 0x8B; m_buf[m_off++] = 0xD1;  // MOV R10, RCX
        m_buf[m_off++] = 0xB8;                                                 // MOV EAX, imm32
        *(uint32_t*)(m_buf + m_off) = ssn; m_off += 4;
        m_buf[m_off++] = 0x0F; m_buf[m_off++] = 0x05;                          // SYSCALL
        m_buf[m_off++] = 0xC3;                                                  // RET
    }

    // Variant 1: Swapped instruction order
    void BuildOrderSwap(uint32_t ssn) {
        m_buf[m_off++] = 0xB8;                                  // MOV EAX, ssn (do this first)
        *(uint32_t*)(m_buf + m_off) = ssn; m_off += 4;
        m_buf[m_off++] = 0x4C; m_buf[m_off++] = 0x8B; m_buf[m_off++] = 0xD1;  // MOV R10, RCX
        m_buf[m_off++] = 0x0F; m_buf[m_off++] = 0x05;                          // SYSCALL
        m_buf[m_off++] = 0xC3;                                                  // RET
    }

    // Variant 2: Stack shuffle (PUSH/POP RAX around)
    void BuildStackShuffle(uint32_t ssn) {
        m_buf[m_off++] = 0x50;                                  // PUSH RAX
        m_buf[m_off++] = 0x4C; m_buf[m_off++] = 0x8B; m_buf[m_off++] = 0xD1;  // MOV R10, RCX
        m_buf[m_off++] = 0xB8;                                  // MOV EAX, ssn
        *(uint32_t*)(m_buf + m_off) = ssn; m_off += 4;
        m_buf[m_off++] = 0x0F; m_buf[m_off++] = 0x05;                          // SYSCALL
        m_buf[m_off++] = 0x58;                                  // POP RAX
        m_buf[m_off++] = 0xC3;                                                  // RET
    }

    // Variant 3: XOR-obfuscated SSN (ssn ^ key reconstructed at runtime)
    void BuildXorSsn(uint32_t ssn, uint32_t xorKey) {
        uint32_t encSsn = ssn ^ xorKey;
        m_buf[m_off++] = 0x4C; m_buf[m_off++] = 0x8B; m_buf[m_off++] = 0xD1;  // MOV R10, RCX
        m_buf[m_off++] = 0xB8;                                  // MOV EAX, encSsn
        *(uint32_t*)(m_buf + m_off) = encSsn; m_off += 4;
        m_buf[m_off++] = 0x35;                                  // XOR EAX, xorKey
        *(uint32_t*)(m_buf + m_off) = xorKey; m_off += 4;
        m_buf[m_off++] = 0x0F; m_buf[m_off++] = 0x05;                          // SYSCALL
        m_buf[m_off++] = 0xC3;                                                  // RET
    }

    // Variant 4: REX prefix rotation
    void BuildRexRotate(uint32_t ssn, int rexVariant) {
        // Rotate between 4C, 4D, 4E, 4F for MOV R10, RCX
        uint8_t rex[] = {0x4C, 0x4D, 0x4E, 0x4F};
        m_buf[m_off++] = rex[rexVariant & 3];
        m_buf[m_off++] = 0x8B; m_buf[m_off++] = 0xD1;                          // but still D1 = rcx
        m_buf[m_off++] = 0xB8;
        *(uint32_t*)(m_buf + m_off) = ssn; m_off += 4;
        m_buf[m_off++] = 0x0F; m_buf[m_off++] = 0x05;
        m_buf[m_off++] = 0xC3;
    }

    // Variant 5: Random junk insertion
    void BuildWithJunk(uint32_t ssn, uint32_t rngState) {
        BuildStandard(ssn);
        // Insert random NOPs and MOV reg,reg before SYSCALL
        // at offset 7 (between MOV EAX and SYSCALL)
        int insertPoint = 7;
        int junkLen = (rngState & 3) + 1;  // 1-4 junk bytes
        for (int i = 0; i < junkLen; i++) {
            // Shift existing bytes after insertPoint
            memmove(m_buf + insertPoint + 1, m_buf + insertPoint,
                    m_off - insertPoint);
            m_buf[insertPoint] = 0x90;  // NOP
            insertPoint++;
            m_off++;
        }
    }

    // Variant 6: Indirect syscall with return spoofing
    void BuildIndirect(uint32_t ssn, uintptr_t ntdllRetAddr) {
        m_buf[m_off++] = 0x4C; m_buf[m_off++] = 0x8B; m_buf[m_off++] = 0xD1;  // MOV R10, RCX
        m_buf[m_off++] = 0xB8;                                  // MOV EAX, ssn
        *(uint32_t*)(m_buf + m_off) = ssn; m_off += 4;
        // Push ntdll return address onto stack
        // When SYSCALL returns → goes to ntdll address → RET to us
        m_buf[m_off++] = 0x48; m_buf[m_off++] = 0xB8;                          // MOV RAX, imm64
        *(uint64_t*)(m_buf + m_off) = ntdllRetAddr; m_off += 8;
        m_buf[m_off++] = 0x50;                                  // PUSH RAX
        m_buf[m_off++] = 0x0F; m_buf[m_off++] = 0x05;                          // SYSCALL
        m_buf[m_off++] = 0xC3;                                                  // RET
    }

    int GetSize() const { return m_off; }
    const uint8_t* GetStub() const { return m_buf; }

    // Assign a random variant per stub, store which was used
    StubVariant PickRandom(uint32_t seed) {
        return (StubVariant)(seed % 7);  // Excludes PER_CALL (7)
    }
};
```

### 5.3 Dynamic Stub Manager

```cpp
class StubManager {
    // RW pool → sealed to RX after construction
    static constexpr size_t POOL_SIZE = 0x10000;
    uint8_t*   m_pool;
    uint32_t   m_used = 0;

public:
    bool Init() {
        m_pool = (uint8_t*)VirtualAlloc(nullptr, POOL_SIZE,
                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        return m_pool != nullptr;
    }

    // Build a unique stub for each call
    uintptr_t BuildStub(const char* funcName, uint32_t ssn) {
        StubBuilder sb;
        uint32_t variant = 0;
        // Hash function name for deterministic variant across calls
        uint32_t hash = fnv1a(funcName);
        StubVariant sv = (StubVariant)(hash % 7);

        switch (sv) {
        case STUB_STANDARD:   sb.BuildStandard(ssn); break;
        case STUB_ORDER_SWAP: sb.BuildOrderSwap(ssn); break;
        case STUB_STACK_SHUFF: sb.BuildStackShuffle(ssn); break;
        case STUB_XOR_SSN:    sb.BuildXorSsn(ssn, hash ^ 0xDEADBEEF); break;
        case STUB_REX_ROTATE: sb.BuildRexRotate(ssn, hash); break;
        case STUB_JUNK_NOP:   sb.BuildWithJunk(ssn, hash); break;
        case STUB_INDIRECT:   sb.BuildIndirect(ssn, FindNtdllRet()); break;
        }

        if (m_used + sb.GetSize() > POOL_SIZE) return 0;
        uint8_t* stub = m_pool + m_used;
        memcpy(stub, sb.GetStub(), sb.GetSize());
        m_used += sb.GetSize();
        return (uintptr_t)stub;
    }

    void Seal() {
        DWORD old;
        VirtualProtect(m_pool, POOL_SIZE, PAGE_EXECUTE_READ, &old);
        FlushInstructionCache(GetCurrentProcess(), m_pool, POOL_SIZE);
    }
};

// Per-call invocation (stealth_call style):
// Build stub fresh each call, execute, then zero out
uintptr_t PerCallStub(uint32_t ssn) {
    uint8_t stub[32];
    StubBuilder sb;
    sb.BuildStandard(ssn);  // Could also randomize per-call
    int size = sb.GetSize();

    // Allocate on stack or thread-local RWX page
    // WARNING: This creates RWX at runtime — higher risk
    // Better: pre-allocate pool, use FIFO replacement
    void* execMem = VirtualAlloc(nullptr, 32,
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!execMem) return 0;

    memcpy(execMem, stub, size);
    FlushInstructionCache(GetCurrentProcess(), execMem, size);

    // ... call via function pointer ...

    // Destroy after use
    DWORD old;
    VirtualProtect(execMem, 32, PAGE_READWRITE, &old);
    memset(execMem, 0, 32);
    VirtualFree(execMem, 0, MEM_RELEASE);
    return (uintptr_t)execMem;
}
```

### 5.4 FNV-1a Hash for Function Names

```cpp
// Used for deterministic stub variant assignment
// Replaces plain-text function names in .rdata
constexpr uint32_t fnv1a(const char* str) {
    uint32_t hash = 0x811C9DC5;
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 0x01000193;
    }
    return hash;
}

// Usage:
// Instead of: BuildStub("NtProtectVirtualMemory", ssn)
// Use: BuildStub(fnv1a("NtProtectVirtualMemory"), ssn)
// No plain-text API name in binary
```

---

*Last updated: 2026-07-05 | Accuracy baseline: 93.4%*
*Cross-ref: 12_THREADING_MODEL.md, 11_STRUCT_SUPPLEMENT.md, 07_DEV_GUIDE.md, 10_CROSS_REFERENCE.md*
