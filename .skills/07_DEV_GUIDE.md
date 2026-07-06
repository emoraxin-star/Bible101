# 07_DEV_GUIDE.md
# Developer's Guide to LIBERTEA.DLL
## How-To Implementation Recipes

This guide provides step-by-step recipes for implementing the core cheats in the style expected by production code. Each section corresponds to a specific feature type with practical, executable code.
---

## Adding a New NOP_PATCH Hook (e.g., Grenade Count)

### Prerequisites
- LIBERTEA v414 (732KB packed / 3.49MB unpacked)
- Function target: Grenade count decrementation
- Hook type: No-Op (replace with 0x90)

### Implementation Recipe

```cpp
// Step 1: Identify the grenade count function
// Pattern from offsets.h:
constexpr uint8_t GRENADE_PATTERN[] = {0x0F, 0x5B, 0xDB, 0xF3, 0x41, 0x0F, 0x59, 0x4E, 0x??, 0xF3};

// Step 2: Ensure pattern database includes it
// In pattern_data.c, add this entry:
const PatternEntry GRENADE_COUNT_HOOK = {
    .patternId = 0x123456,           // Unique identifier
    .hookType = HookType::NOP_PATCH,// Code type
    .moduleName = "game.dll",       // Target module
    .featureName = "GrenadeCount",   // Feature label
    .bytes     = GRENADE_PATTERN,   // 10 bytes
    .mask      = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0xFF}, // Ignore one byte
    .offset     = -0x20,             // Subtract 32 from found address
    .patchSize  = 5,                 // NOP 5-byte sled
    .patchBytes = {0x90,0x90,0x90,0x90,0x90}  // 5x NOP
};

// Step 3: Verify implementation
// Add to hook_installer_upgrade.c verify_logging
void VerifyGrenadeHook(uintptr_t resolvedAddr) {
    if (resolvedAddr && !ValidateNOP(resolvedAddr, 5)) {
        LOG_ERROR("Grenade hook invalid: %.16llx", resolvedAddr);
        return SetIntegrityViolation();
    }
    LOG_SUCCESS("Grenade hook installed: %.16llx", resolvedAddr);
}
```

---

## Adding a New CODE_PATCH Feature (e.g., God Mode)

### Prerequisites
- 3 hook addresses needed (God Mode includes protection bypass)
- Hack type: Code injection with health override
- Target: Player health comparison at `Player::TakeDamage`

### Implementation Recipe

```cpp
// Step 1: Create hook prototypes in hook_installer_upgrade.c
void AddGodModeHook(uintptr_t damageFunc);

// Step 2: Hook implementation (based on Liberta::GodMode.cpp)
void AddGodModeHook(uintptr_t damageFunc) {
    if (!damageFunc) return;
    
    // Verify function prologue (mov ecx, [rdx+0x8] / call ...)
    uint8_t pre1[6] = {0x8B, 0x8B, 0x08, 0x00, 0x00, 0x00};
    if (!CompareBytes((uint8_t*)damageFunc, pre1, 6, {0xFF,0xFF,0x00,0x00,0x00,0x00}))
        return;
    
    // Hook: jmp to bypass check (skip damage flow)
    // Original: call dword ptr [rdi+0x1A8]
    // Patch:    jmp overrideProc
    uintptr_t patch = BuildJMP(damageFunc + 6, overrideProc);
    InstallHook(damageFunc, patch);
    
    // Second hook: nop health clamp
    InstallNOPHook(damageFunc + 0x90, 4); // 0x90 NOP sled
    
    // Third: nop resistance calculation
    InstallNOPHook(damageFunc + 0x200, 2);
    
    LOG_SUCCESS("GodMode hooks: %.16llx -> override", damageFunc);
}
```

---

## Adding a New Syscall Type (Indirect Syscall Implementation)

### Prerequisites
- Need to fetch SSN from ntdll (not hardcoded)
- Want to comply with modern anti-debug (Hades Gate)
- Using direct syscall but with stack spoofing

### Implementation Recipe

```cpp
// Step 1: Implement PEB-based ntdll resolution (Hades Gate)
uintptr_t ResolveNtllBase() {
    uint32_t peb = __readgsqword(0x60);                    // PEB ptr
    uintptr_t ldr = *(uintptr_t*)(peb + 0x18);            // PEB->Ldr
    uintptr_t flink = *(uintptr_t*)(ldr + 0x20);         // InMemoryOrderModuleList
    
    // Second entry is ntdll (first is loader lock)
    uintptr_t ntdllHdr = *(uintptr_t*)(flink + 0x20);
    return ntdllHdr;
}

// Step 2: Resolve SSN from in-memory ntdll (Pattern A for Win10 1809+)
uint32_t ResolveSSN(uintptr_t ntdllBase, const char* funcName) {
    uint32_t peHeader = *(uint32_t*)(ntdllBase + 0x3C);    // PE header
    uint32_t optDir = *(uint32_t*)(ntdllBase + peHeader + 0x78);
    uint32_t expDir = *(uint32_t*)(ntdllBase + optDir + 0x70);
    
    uint32_t numNames = *(uint32_t*)(expDir + 0x20);
    uint32_t expTable = *(uint32_t*)(expDir + 0x24);
    uint32_t namePtrs = *(uint32_t*)(expDir + 0x2C);
    uint32_t ordinals = *(uint32_t*)(expDir + 0x34);
    
    // Retrieve function name from export table
    // Linearly search matching funcName
    for (uint32_t i = 0; i < numNames; i++) {
        char* exportedName = (char*)(ntdllBase + *(uint32_t*)(namePtrs + i * 4));
        if (strcmp(exportedName, funcName) == 0) {
            uint32_t ord = ordinals[i];                    // Ordinal
            uintptr_t funcRVA = *(uintptr_t*)(expTable + ord * 8);
            return (uint32_t)(funcRVA - (uintptr_t)ntdllBase); // Return SSN
        }
    }
    return 0; // Not found
}

// Step 3: Build indirect syscall stub with return spoofing
uintptr_t BuildIndirectSyscall(uint32_t ssn, uintptr_t targetAddr) {
    // All stubs in one place - find or allocate in RWX region
    static uintptr_t stubBase = 0;
    if (!stubBase) {
        stubBase = VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        // Apply W^X after construction
        VirtualProtect((void*)stubBase, 4096, PAGE_EXECUTE_READ, &oldProt);
    }
    
    // Stub layout: MOV R10,RCX; MOV EAX,SSN; PUSH ntdll ret; SYSCALL; POP RAX
    // This ensures SYSCALL returns to ntdll's stub location
    stubBuilder arm;
    arm.mov_r10_rcx();
    arm.mov_eax_ssn(ssn);
    arm.push_ntdll_ret(targetAddr);     // Push ntdll stub return
    arm.syscall();
    arm.pop_eax();
    arm.ret();
    
    uintptr_t stub = stubBase + StubAllocator::get_next_offset();
    StubAllocator::add_refcount(stub, 1);
    return stub;
}

// Helper for Stack Spoofing
void CreateStackSpoof(uintptr_t ntdllRetAddr) {
    // Build a fake call stack that appears as from ntdll
    // instead of from the cheat module
    // Use an auxiliary register context that the EDR/CA won't see
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(GetCurrentThread(), &ctx);
    ctx.Rsp -= 8;
    *(uintptr_t*)ctx.Rsp = ntdllRetAddr;  // Spoof this as caller
    SetThreadContext(GetCurrentThread(), &ctx);
}
```

---

## Developing a New Game State Flow Operation

### Prerequisites
- Understanding of current game flow: `Main Menu → Lobby → Loading → In-Mission → Post-Game`
- Need to trigger mission replay using `WM_SC_DISPATCH`
- Want to save/load game state via the backend

### Implementation Recipe

```cpp
// Step 1: Create a MissionStateTracker struct to manage state changes
struct MissionStateTracker {
    enum State {
        MENU,           // Main menu idle
        LOBBY,          // In lobby, ready checks
        LOADING,        // Loading server
        IN_MISSION,    // Active gameplay
        ENDING,         // Mission completes
        POST_GAME      // Results screen
    };
    
    State currentState = State::MENU;
    uint64_t lastTick = GetTickCount64();
    bool missionDirty = false;
    char currentMissionId[64] = {};
    
    // State transition handlers
    bool handleMenuToLobby(Message m) {
        if (m.message == WM_ROOM_READY) {
            currentState = LOBBY;
            lastTick = GetTickCount64();
            AddLog("[State] MENU → LOBBY");
            return true;
        }
        return false;
    }
    
    bool handleLobbyToLoading(Message m) {
        if (m.message == WM_SESSION_START) {
            currentState = LOADING;
            lastTick = GetTickCount64();
            AddLog("[State] LOBBY → LOADING");
            return true;
        }
        return false;
    }
    
    bool handleLoadingToInMission(Message m) {
        if (currentState == LOADING && m.arrivalTime > lastTick + 3000) {
            // Prevent false positives — must stay loading for >3s
            currentState = IN_MISSION;
            lastStateTick = lastTick = GetTickCount64();
            AddLog("[State] LOADING → IN_MISSION");
            return true;
        }
        return false;
    }
    // ... other transitions
};

// Step 2: Integrate with Replay engine
class MissionReplayOrchestrator {
    MissionStateTracker* state;
    ReplayEngine*      replay;
    
    MissionReplayOrchestrator() : state(new MissionStateTracker), replay(new ReplayEngine) {}
    
    // Primary dispatcher
    void dispatchMessage(const Message& m) {
        bool handled = false;
        handled |= state->handleMenuToLobby(m);
        handled |= state->handleLobbyToLoading(m);
        handled |= state->handleLoadingToInMission(m);
        
        // State-specific replay logic
        switch (state->currentState) {
        case MissionStateTracker::LOBBY:
            handleLobbyActions(m);
            break;
        case MissionStateTracker::IN_MISSION:
            handleInMissionActions(m);
            break;
        }
        
        // After action, if condition met, trigger replay
        if (shouldReplay(m)) {
            replay->TriggerReplay();
        }
    }
    
    void handleInMissionActions(const Message& m) {
        if (m.message == WM_BUILD_PAYLOAD) {
            // Extract mission data from payload for backup
            backupMissionState(m);
        } else if (m.message == WM_GAME_END) {
            // If mission ended unexpectedly, capture and prepare replay
            if (!g_state.captures.empty()) {
                pendingReplayStore = true;
            }
        }
    }
    
    // Modular: game state persistence
    void saveGameState() {
        // Save mission list, parsed and sorted
        std::sort(g_state.captures.begin(), g_state.captures.end(), 
            [](const CapturedMission& a, const CapturedMission& b) {
                return a.captureTime > b.captureTime; // Newest first
            });
        
        // Write to internal database
        SqliteDatabase::store("replay_state", "captures", 
            g_state.captures.data(), 
            g_state.captures.size() * sizeof(CapturedMission));
    }
    
    void loadGameState() {
        // Key for synthetic replay: combine 64-bit missionId + warTime
        uint64_t compositeKey = ((uint64_t)std::hash<std::string>{}(mdata.missionStr) << 32) ^ 
                                mdata.capturedWarTime;
        SqliteDatabase::query("SELECT * FROM mission_states WHERE key = ?", 
            compositeKey, outStates);
    }
};

// Usage example in main loop
void ProcessMessages() {
    Message m = GetNextWindowMessage();
    orchestrator.dispatchMessage(m); // Uses the MissionReplayOrchestrator
}
```

---

---

## Injection & Bootstrapping Protocol

### Architecture Overview
LIBERTEA uses standard DLL injection via `CreateRemoteThread` → `LoadLibraryW`, performed by `LIBERTEA_Bypass.exe` (the injector). The injector also handles self-update and GameGuard bypass.

### Injector Flow

```
LIBERTEA_Bypass.exe startup:
  1. Self-update check: GET /menu/version → compare → download if newer
  2. Enable SeDebugPrivilege for process access
  3. Disable GameGuard: find & rename/delete GameMon64.des, GameMon.des
  4. Find helldivers2.exe PID (Toolhelp32Snapshot → Process32First/Next)
  5. OpenProcess(PROCESS_ALL_ACCESS)
  6. VirtualAllocEx: allocate page for DLL path string
  7. WriteProcessMemory: write L"C:\\path\\to\\LIBERTEA.DLL"
  8. CreateRemoteThread: start = kernel32!LoadLibraryW, arg = remote path
  9. WaitForSingleObject(30s timeout)
  10. VirtualFreeEx: cleanup allocated memory
```

### Implementation Recipe

```cpp
// Injector.cpp — Standard DLL Injection
#include <windows.h>
#include <tlhelp32.h>

DWORD FindProcessId(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) do {
        if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}

bool InjectDLL(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return false;

    SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    void* pRemote = VirtualAllocEx(hProc, nullptr, pathSize,
                                   MEM_COMMIT, PAGE_READWRITE);
    if (!pRemote) { CloseHandle(hProc); return false; }

    WriteProcessMemory(hProc, pRemote, dllPath, pathSize, nullptr);

    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    auto pLoadLib = (LPTHREAD_START_ROUTINE)
        GetProcAddress(hKernel, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        pLoadLib, pRemote, 0, nullptr);
    if (!hThread) { VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProc); return false; }

    WaitForSingleObject(hThread, 30000);          // 30s timeout
    VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return true;
}

int main() {
    EnableSeDebugPrivilege();
    DisableGameGuard();           // Rename/delete GameMon64.des
    DWORD pid = FindProcessId(L"helldivers2.exe");
    if (pid && InjectDLL(pid, L"C:\\LIBERTEA.DLL"))
        return 0;
    return 1;
}
```

### GameGuard Bypass (Race Condition)

```cpp
bool DisableGameGuard() {
    // Attempt to disable before GameGuard kernel driver loads
    const wchar_t* targets[] = {
        L"C:\\Windows\\System32\\drivers\\GameMon64.des",
        L"C:\\Windows\\System32\\drivers\\GameMon.des",
    };
    bool any = false;
    for (auto* path : targets) {
        if (DeleteFileW(path)) any = true;
        // Rename alternative:
        // MoveFileExW(path, L"GameMon64.bak",
        //     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    // Fallback: SCM service stop
    // SC_HANDLE hSCM = OpenSCManagerW(..., SC_MANAGER_ALL_ACCESS);
    // OpenServiceW(hSCM, L"GameGuard", SERVICE_STOP);
    // ControlService(... SERVICE_CONTROL_STOP);
    return any;
}
```

### Self-Update Flow

```cpp
int CheckForUpdate() {
    int localVer = 0;
    FILE* f = fopen("LIBERTEA.version", "r");
    if (f) { fscanf(f, "%d", &localVer); fclose(f); }

    int serverVer = HttpGetInt(
        "https://libertea.libertea4.workers.dev/menu/version");
    if (serverVer <= localVer) return 0;    // Up to date

    // Download new DLL
    HttpGetToFile(
        "https://libertea.libertea4.workers.dev/menu/download",
        "LIBERTEA.DLL.tmp");

    MoveFileExW(L"LIBERTEA.DLL.tmp", L"LIBERTEA.DLL",
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);

    f = fopen("LIBERTEA.version", "w");
    if (f) { fprintf(f, "%d", serverVer); fclose(f); }

    // Relaunch injector with --retry to use new DLL
    wchar_t cmd[] = L"LIBERTEA_Bypass.exe --retry";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
    ExitProcess(0);
    return serverVer;
}
```

### Reflective DLL Injection (Alternative — No LoadLibraryW)

Reflective injection maps the DLL manually without calling `LoadLibraryW`, avoiding PEB module list entries.

```cpp
// Reflective loader stub (injected into target):
// 1. Parse own PE headers (in process memory after WriteProcessMemory)
// 2. Allocate memory for sections via VirtualAllocEx
// 3. Copy section data, apply relocations
// 4. Resolve imports (GetModuleHandle + GetProcAddress)
// 5. Call DllMain directly
// 6. SetLastError(0) to hide error state

// Key differences from standard injection:
// - No LoadLibraryW call → DLL not in PEB.InMemoryOrderModuleList
// - No kernel32!LoadLibraryW thread start → harder to detect
// - Requires manual PE mapping (section copy, reloc, import resolve)
// - DLL must be compiled with /DYNAMICBASE for reloc support
```

---

## Memory Manager & W^X Allocation Strategy

### Problem Statement
LIBERTEA currently uses `PAGE_EXECUTE_READWRITE` (RWX) for all allocated memory (syscall stubs, hook trampolines, code caves). This is a critical detection vector because:
- Normal code sections are `RX` (Read-eXecute), not RWX
- GameGuard AOB-scans for RWX allocations with large sizes
- W^X (Write XOR Execute) policy: memory is EITHER writable OR executable, never both

### Current Allocation Patterns (in SC_SO)

| Purpose | Size | Protection | Location | W^X Violation? |
|---------|------|-----------|----------|---------------|
| Syscall stubs | 4KB | RWX | VirtualAlloc | YES |
| Hook trampolines | 4KB pool (64B slots) | RWX | alloc_trampoline() | YES |
| Code caves | 4KB | RWX | AllocNear() | YES |
| Fake entity/vtable memory | 2KB-64KB | RWX | VirtualAlloc | YES |
| VEH ret stub | 4KB | RWX→RX after init | sc_guard.cpp | FIXED (transition to RX) |
| Deep copy buffers | Var | RW | VirtualAlloc | OK (data only) |

### W^X Enforcement Implementation

```cpp
// Memory Manager — W^X Compliant
class MemMgr {
    // Pool of RX pages for executable code (stubs, trampolines)
    static constexpr size_t EXEC_POOL_SIZE  = 0x10000;  // 64KB
    static constexpr size_t TRAMP_SLOT_SIZE = 128;      // Per-trampoline

    uint8_t*  m_execPool   = nullptr;     // RX pool base
    uint32_t  m_execUsed   = 0;           // Bytes consumed
    CRITICAL_SECTION m_cs;               // Thread safety

public:
    bool Init() {
        InitializeCriticalSection(&m_cs);
        // Allocate as RW, will be flipped to RX after population
        m_execPool = (uint8_t*)VirtualAlloc(nullptr, EXEC_POOL_SIZE,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        return m_execPool != nullptr;
    }

    // Allocate executable memory (write then lock)
    uint8_t* AllocExec(size_t size) {
        EnterCriticalSection(&m_cs);
        if (m_execUsed + size > EXEC_POOL_SIZE) {
            LeaveCriticalSection(&m_cs); return nullptr;
        }
        uint8_t* slot = m_execPool + m_execUsed;
        m_execUsed += size;
        LeaveCriticalSection(&m_cs);
        return slot;
    }

    // Freeze all exec allocations to RX (W^X enforcement)
    // Call once after all stubs/trampolines are built
    void Seal() {
        DWORD old;
        VirtualProtect(m_execPool, EXEC_POOL_SIZE,
                       PAGE_EXECUTE_READ, &old);
        FlushInstructionCache(GetCurrentProcess(),
                              m_execPool, EXEC_POOL_SIZE);
    }

    // Allocate non-executable (RW) data
    static uint8_t* AllocData(size_t size) {
        return (uint8_t*)VirtualAlloc(nullptr, size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    void Cleanup() {
        if (m_execPool) {
            DWORD old;
            VirtualProtect(m_execPool, EXEC_POOL_SIZE,
                           PAGE_READWRITE, &old);
            VirtualFree(m_execPool, 0, MEM_RELEASE);
        }
        DeleteCriticalSection(&m_cs);
    }
};

static MemMgr g_memMgr;
```

### AllocNear — Code Cave Allocation (Near Relative JMP Range)

Used for inline hooks that need the trampoline within ±2GB (x64 `JMP rel32` range).

```cpp
// Allocate memory within ±0x70000000 bytes of target (covers rel32 range)
static void* AllocNear(uintptr_t target, size_t size) {
    uintptr_t lo = (target > 0x70000000) ? target - 0x70000000 : 0x10000;
    uintptr_t hi = target + 0x70000000;
    for (uintptr_t a = lo; a < hi; a += 0x10000) {
        void* p = VirtualAlloc((void*)a, size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (p) return p;
    }
    return nullptr;
}

// Usage for a code cave hook:
uint8_t* cave = (uint8_t*)AllocNear(g_hookAddr, 4096);
// Write code into cave (RW)
// ... build stub instructions ...

// Seal: flip to RX
DWORD caveProt;
VirtualProtect(cave, 4096, PAGE_EXECUTE_READ, &caveProt);
FlushInstructionCache(GetCurrentProcess(), cave, stubSize);

// Now patch original: JMP rel32 to cave
DWORD oldProt;
VirtualProtect((void*)g_hookAddr, 10, PAGE_EXECUTE_READWRITE, &oldProt);
// Write JMP ...
VirtualProtect((void*)g_hookAddr, 10, oldProt, &oldProt);
FlushInstructionCache(GetCurrentProcess(), (void*)g_hookAddr, 10);
```

### Hook Trampoline Manager

```cpp
// Fixed-size trampoline pool (prevents fragmentation)
class TrampolinePool {
    static constexpr int POOL_SIZE = 64;   // Max trampolines
    static constexpr int SLOT_SIZE = 128;  // Bytes per trampoline

    uint8_t  m_mem[POOL_SIZE * SLOT_SIZE]; // In .data section (not allocated!)
    uint32_t m_used = 0;

public:
    TrampolinePool() {
        // Zero-initialized in .data — no runtime allocation needed
        // Make writable for population
        DWORD old;
        VirtualProtect(m_mem, sizeof(m_mem),
                       PAGE_READWRITE, &old);
    }

    uint8_t* Alloc() {
        if (m_used >= POOL_SIZE) return nullptr;
        uint8_t* slot = m_mem + m_used * SLOT_SIZE;
        m_used++;
        return slot;
    }

    void Seal() {
        DWORD old;
        VirtualProtect(m_mem, sizeof(m_mem),
                       PAGE_EXECUTE_READ, &old);
        FlushInstructionCache(GetCurrentProcess(), m_mem, sizeof(m_mem));
    }
};
```

### Inline Hook Helper (W^X Safe)

```cpp
// Full inline hook implementation with W^X compliance
void* InstallInlineHook(void* target, void* hookFn) {
    // Step 1: Analyze target prologue (find instruction boundary)
    uint8_t* fn = (uint8_t*)target;
    int stolen = 0;
    while (stolen < 14) {
        // Use a length-disassembler engine (hde64, Zydis, etc.)
        int len = length_disasm(fn + stolen);
        if (len == 0) return nullptr;
        stolen += len;
    }

    // Step 2: Allocate trampoline from pool
    uint8_t* tramp = g_memMgr.AllocExec(stolen + 14);
    if (!tramp) return nullptr;

    // Step 3: Build trampoline (copy stolen bytes + JMP back)
    memcpy(tramp, fn, stolen);
    int off = stolen;
    tramp[off++] = 0x48; tramp[off++] = 0xB8;  // MOV RAX, imm64
    *(uint64_t*)(tramp + off) = (uint64_t)(fn + stolen); off += 8;
    tramp[off++] = 0xFF; tramp[off++] = 0xE0;  // JMP RAX

    // Step 4: Make target writable, write hook JMP
    DWORD oldProt;
    VirtualProtect(fn, stolen, PAGE_EXECUTE_READWRITE, &oldProt);
    fn[0] = 0x48; fn[1] = 0xB8;                 // MOV RAX, imm64
    *(uint64_t*)(fn + 2) = (uint64_t)hookFn;
    fn[10] = 0xFF; fn[11] = 0xE0;               // JMP RAX
    for (int i = 12; i < stolen; i++) fn[i] = 0x90;  // NOP remaining
    VirtualProtect(fn, stolen, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), fn, stolen);

    return tramp;
}
```

### W^X Policy Summary

| Phase | Memory Protection | What Happens |
|-------|------------------|--------------|
| **Build** | RW (Read-Write) | Stubs/trampolines/caves allocated as RW. Code written. |
| **Seal** | RX (Read-Execute) | `VirtualProtect` → `PAGE_EXECUTE_READ`. `FlushInstructionCache`. |
| **Runtime** | RX (locked) | No writes possible. If a hook needs updating, unseal → write → reseal. |
| **Data only** | RW (no exec) | Mission captures, string buffers, config — never executable. |

---

## Testing the Implementation

Each recipe includes verification and logging for robustness. The pattern scanner verifies that all hooks were installed correctly, with detailed success/failure messages. The syscall diversity test measures how many distinct code paths are in use, preventing pattern-scan detection. The importer uses empirical evidence (wall-clock timeouts, memory state inspections) to make confident transitions, reducing false positives from frame-rate fluctuations or momentary stuttering.
