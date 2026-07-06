# 12_THREADING_MODEL.md
# Threading Model & Synchronization

Complete specification of LIBERTEA.DLL / SC_SO threading architecture, synchronization patterns, and thread safety contracts.

---

## 1. Thread Inventory

| ID | Thread Name | Created By | Priority | Affinity | Stack Size | Lifetime |
|----|------------|-----------|----------|----------|------------|----------|
| T0 | **Game Main** | Game (helldivers2.exe) | Normal | Any | Default | Process lifetime |
| T1 | **SC AutoSync** | SC_SO at startup | Below normal | Any | 64KB | Farming active |
| T2 | **UUID Rotate** | sc_limit.cpp Install() | Normal | Any | 64KB | Hook installed |
| T3 | **ScLoop (Farming)** | SC_SO at startup | Normal | Any | 256KB | Farming active |
| T4 | **VEH Handler** | OS on exception | HIGHEST (VEH) | Faulting thread | OS-managed | Process lifetime |
| T5 | **libcurl Callbacks** | libcurl internally | Normal | Any | libcurl-managed | Per HTTP request |
| T6 | **Injector** (external) | User launch | Normal | Any | Default | Exits after injection |

---

## 2. Thread Responsibilities

### T0: Game Main Thread
```
Owns:   Game window, WNDPROC, OpenGL context, ImGui context, game state globals
Runs:   Game loop → wglSwapIntervalEXT hook → ImGui::Render()
Access: All game globals (PlayerSession, ServerInfo, PeerManager, Entity)
Sync:   Receives WM_SC_DISPATCH / WM_GT_DISPATCH messages from other threads
Note:   ALL game DLL reads/writes must happen on this thread
```

### T1: SC AutoSync
```
Purpose: Poll PeerManager every 2s for lobby player IDs
Shared:  s_scIds[], s_scIdCount (protected by s_scIdsMutex)
Pattern: ReadProcessMemory(GetCurrentProcess(), ...) for PeerManager peeks
```

### T2: UUID Rotate
```
Purpose: Generate fresh UUIDs on demand for batch rotation
Shared:  g_uuid[], g_rotateReq, g_rotateAck (all std::atomic)
Pattern: Sleep(10) loop checking g_rotateReq flag
```

### T3: ScLoop (Farming State Machine)
```
Purpose: Run SC/Medal farming state machine (12 states)
Shared:  g_state (ReplayState), s_replayInProgress, s_apcGuard
Pattern: μsleep-based cooldown timing, posts WM_SC_DISPATCH to T0
```

### T4: VEH Handler
```
Purpose: Absorb ACCESS_VIOLATION, STACK_OVERFLOW, ILLEGAL_INSTRUCTION
Shared:  g_state, s_retStub (xor eax,eax; ret gadget)
Constraint: Runs on FAULTING thread (could be T0, T3, or T5)
```

### T5: libcurl Callbacks
```
Purpose: HTTP response parsing, mission ID injection
Shared:  g_scCallInFlight (std::atomic<bool>)
Constraint: Callbacks fire on libcurl internal thread pool
```

---

## 3. Synchronization Patterns

### Pattern A: std::atomic Flags (Lock-Free)
```cpp
// Used for: simple boolean state shared across threads
std::atomic<bool> replayInProgress{false};
std::atomic<bool> probeArmed{false};

// Writer (T3: ScLoop):
g_state.replayInProgress.store(true, std::memory_order_release);

// Reader (T0: Game Main via WM_SC_DISPATCH):
if (g_state.replayInProgress.load(std::memory_order_acquire)) { ... }
```

### Pattern B: std::mutex + Lock Guard (Shared Data)
```cpp
// Used for: vectors, captures, log buffers
std::mutex captureMutex;
std::vector<CapturedMission> captures;

// Writer (T0: Game Main after probe capture):
{
    std::lock_guard<std::mutex> lk(g_state.captureMutex);
    g_state.captures.push_back(std::move(cap));
}

// Reader (T3: ScLoop during replay):
{
    std::lock_guard<std::mutex> lk(g_state.captureMutex);
    if (!g_state.captures.empty()) { ... }
}
```

### Pattern C: Window Message Dispatch (Cross-Thread → T0)
```cpp
// Used for: executing code on Game Main thread from worker thread
#define WM_SC_DISPATCH  (WM_APP + 0x3EA)  // 0x87EA
#define WM_GT_DISPATCH  (WM_APP + 0x3EB)  // 0x87EB

// Poster (T3: ScLoop → T0):
PostMessageW(g_gameHwnd, WM_SC_DISPATCH, 0, (LPARAM)actObj);

// Handler (T0: WNDPROC):
LRESULT CALLBACK OverlayWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_SC_DISPATCH:
        // Executes on T0 — safe to access game globals
        HandleSCDispatch((ScActivityAPC*)lp);
        return 0;
    case WM_GT_DISPATCH:
        HandleGenericDispatch((void*)wp, (void*)lp);
        return 0;
    }
    return CallWindowProcW(origWndProc, hwnd, msg, wp, lp);
}
```

### Pattern D: APC + compare_exchange (Exclusive Access)
```cpp
// Used for: ensuring only one replay executes at a time
static std::atomic<bool> s_apcGuard{false};

// T3 attempts to queue replay via APC:
bool expected = false;
if (!s_apcGuard.compare_exchange_strong(expected, true)) {
    // Another replay in progress — skip
    return;
}
// ... execute replay ...
s_apcGuard.store(false, std::memory_order_release);
```

### Pattern E: VEH Exception Redirection (T4 → any)
```cpp
LONG CALLBACK VEH_CrashHandler(PEXCEPTION_POINTERS ep) {
    switch (ep->ExceptionRecord->ExceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION:    // 0xC0000005
    case EXCEPTION_STACK_OVERFLOW:      // 0xC00000FD
    case EXCEPTION_ILLEGAL_INSTRUCTION: // 0xC000001D
        // Redirect to safe stub — runs on faulting thread
        ep->ContextRecord->Rip = (uint64_t)s_retStub;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
```

---

## 4. Thread Lifecycle

### Startup Sequence
```
T0 (Game Main):
  1. DllMain called (packer decompress → import resolve → init)
  2. Pattern scanner runs (on T0)
  3. Hooks installed (on T0)
  4. VEH registered (on T0, handler runs on any thread)
  5. ImGui overlay initialized (on T0)
  6. Auth flow (on T0, blocking overlay)
  7. SC_SO startup:
     a. CreateThread → T1 (AutoSync, BelowNormal)
     b. CreateThread → T3 (ScLoop, Normal)
     c. (If sc_limit installed) CreateThread → T2 (UUIDRotate, Normal)
```

### Shutdown Sequence
```
User disables farming:
  T3: state → USER_OFF → wait → exit loop
  T3: thread exits naturally
  T1: thread exits naturally

DLL unload (FreeLibrary / process exit):
  T0: Signal all threads via std::atomic<bool> stop flags
  T0: WaitForSingleObject on each thread handle (1s timeout)
  T0: Uninstall hooks (restore original bytes)
  T0: Remove VEH
```

---

## 5. Critical Sections & Deadlock Prevention

### Lock Hierarchy (Strict Order)
```
Level 1 (highest): captureMutex       — CapturedMission vector
Level 2:            logMutex          — LogEntry vector
Level 3:            replayLogMutex    — ReplayLog vector
```

**Rule**: Always acquire in ascending order. Never hold Level N while acquiring Level N-1.

### Lock-free Paths (No Mutex Required)
- `g_state.replayInProgress` — std::atomic<bool>
- `g_state.probeArmed` — std::atomic<bool>
- `g_state.hookInstalled` — std::atomic<bool>
- `g_state.gatePatched` — std::atomic<bool>
- `s_apcGuard` — std::atomic<bool>
- `g_scCallInFlight` — std::atomic<bool>

### Thread Safety Table
| Shared Resource | Accessed By | Protection | Read/Write |
|----------------|-------------|-----------|------------|
| `g_state.captures` | T0 (write), T3 (read) | captureMutex | Both |
| `g_state.log` | Any | logMutex | Both |
| `g_state.replayLog` | T3 | replayLogMutex | Both |
| `g_state.replayInProgress` | T0, T3 | atomic | Read-heavy |
| `s_scIds[]`, `s_scIdCount` | T1 (write), T3 (read) | s_scIdsMutex | Both |
| `g_uuid[]` | T2 (write), T0 (read) | atomic rotateReq/rotateAck | Write-triggered |
| Game DLL globals | T0 ONLY | Window message dispatch | Read/write |

---

## 6. Performance Model

### Expected Thread Timings
| Thread | Wake Interval | CPU per Wake | Total CPU |
|--------|-------------|-------------|-----------|
| T0 (Game Main) | Every frame (~16ms @ 60fps) | ~0.5ms (ImGui) | ~3% |
| T1 (AutoSync) | Every 2000ms | ~0.1ms | <0.1% |
| T2 (UUID Rotate) | Every 10ms | ~0.01ms | <0.1% |
| T3 (ScLoop burning) | Every ~500ms (batch) | ~50ms | ~10% |
| T3 (ScLoop cooldown) | Every ~58000ms | ~0.1ms | <0.1% |
| T4 (VEH) | On exception only | ~0.01ms | Negligible |
| T5 (libcurl) | Per HTTP call | Variable | Network-bound |

---

*Last updated: 2026-07-05 | Accuracy baseline: 93.4%*
*Cross-ref: 11_STRUCT_SUPPLEMENT.md (ThreadPool section), 07_DEV_GUIDE.md (recipes), 10_CROSS_REFERENCE.md*
