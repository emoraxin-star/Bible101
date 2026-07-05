# SC_Replay_Source

A comprehensive DLL-based automation and replay framework for Helldivers 2, enabling mission capture, replay, Super Credits (SC) farming, and HTTP traffic interception — all operating from within the game process.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Directory Structure](#directory-structure)
4. [Module Reference](#module-reference)
   - [Core Engine](#core-engine)
   - [Capture System](#capture-system)
   - [HTTP Interception](#http-interception)
   - [Safety & Dispatch](#safety--dispatch)
   - [Foundation Layer](#foundation-layer)
   - [Feature Stubs](#feature-stubs)
5. [Data Flow](#data-flow)
6. [Key Technical Details](#key-technical-details)
   - [Hardware Breakpoint Probe](#hardware-breakpoint-probe)
   - [Inline Hooking (libcurl)](#inline-hooking-libcurl)
   - [AOB Pattern Scanning](#aob-pattern-scanning)
   - [Dynamic RVA Resolution](#dynamic-rva-resolution)
   - [Window Message Dispatch](#window-message-dispatch)
   - [Crash Absorption VEH](#crash-absorption-veh)
   - [Code Cave Injection (UUID Rotation)](#code-cave-injection-uuid-rotation)
   - [XOR String Obfuscation](#xor-string-obfuscation)
   - [Weapon Override System](#weapon-override-system)
   - [Session & Capture Serialization](#session--capture-serialization)
7. [Build & Dependencies](#build--dependencies)
   - [Platform Requirements](#platform-requirements)
   - [Windows APIs Used](#windows-apis-used)
   - [Third-Party Code](#third-party-code)
   - [Build Instructions](#build-instructions)
8. [Runtime Behavior](#runtime-behavior)
   - [Capture Mode](#capture-mode)
   - [Replay Mode](#replay-mode)
   - [SC Farming Mode](#sc-farming-mode)
   - [Offline / Baked Capture Mode](#offline--baked-capture-mode)
9. [Runtime Data Files](#runtime-data-files)
10. [Threading Model](#threading-model)
11. [Offset Versioning](#offset-versioning)
12. [Security & Evasion](#security--evasion)
13. [Limitations (Feature Stubs)](#limitations-feature-stubs)
14. [51 Weapons Table](#51-weapons-table)
15. [License Status](#license-status)

---

## Overview

SC_Replay_Source is a native **x64 DLL** compiled in C++17 for injection into the Helldivers 2 game process. It intercepts the game's internal HTTP traffic, captures mission state using hardware debug registers, and provides automated mission replay and Super Credits farming capabilities. The tool operates entirely from within the target process's address space, hooking into both Win32 APIs and the game's own DLL (`game.dll`) at known RVA offsets.

### Core Capabilities

| Capability | Mechanism |
|---|---|
| **Mission Capture** | x64 hardware breakpoints (Dr2/Dr3) + Vectored Exception Handler |
| **Mission Replay** | Modified mission payload injected via game's internal `BuildPayload` function |
| **SC Farming** | Automated Super Credits activity calls with randomized mission IDs |
| **HTTP Interception** | Inline hooks on libcurl's `curl_easy_setopt` / `curl_easy_perform` / `curl_easy_cleanup` |
| **Response Parsing** | Extraction of reward amounts from JSON API responses |
| **Signature Capture** | BCryptHashData hook for X-Signature nonce/key capture |
| **Crash Protection** | Vectored Exception Handler absorbing crashes in game code |
| **Dynamic Offsets** | Pattern-scanning RVA resolver for multi-version game support |

---

## Architecture

```
  ┌──────────────────────────────────────────────────────────┐
  │                     Public API Layer                      │
  │  replay.h    probe.h     farming.h    loadout.h           │
  │  license.h   http_monitor.h   sc_present.h   sc_guard.h  │
  │  sc_limit.h  sc_tracker.h                                 │
  └─────────────────────────┬────────────────────────────────┘
                            │
  ┌─────────────────────────┴────────────────────────────────┐
  │                   Core Engine                             │
  │  replay.cpp  (orchestrates capture, replay, farming)      │
  │  ├─ ReplayAPC()         — replay a captured mission       │
  │  ├─ ScActivityAPC()     — execute one SC activity         │
  │  ├─ ScLoopThread()      — automated farming loop          │
  │  └─ SC_AutoSyncLoop()   — lobby player ID sync            │
  └───────────────┬─────────────────────┬────────────────────┘
                  │                     │
  ┌───────────────┴────────┐  ┌────────┴─────────────────────┐
  │   Capture System        │  │   HTTP Interception           │
  │   probe.cpp             │  │   http_monitor.cpp            │
  │   (HW breakpoints)      │  │   (libcurl hooks)             │
  │   state.h               │  │   (POST/Response capture)     │
  │   baked_capture.h       │  │   (BCrypt signature capture)  │
  └─────────────────────────┘  └──────────────────────────────┘
                  │                     │
  ┌───────────────┴─────────────────────┴────────────────────┐
  │                Safety & Dispatch                          │
  │  sc_present.cpp     — window message dispatch             │
  │  sc_guard.cpp       — crash absorption VEH                │
  │  sc_limit.cpp       — UUID rotation code cave             │
  │  entity_protect.cpp — entity pointer safety stubs         │
  └───────────────────────────┬──────────────────────────────┘
                              │
  ┌───────────────────────────┴──────────────────────────────┐
  │                 Foundation Layer                          │
  │  offsets.h / offsets.cpp        — hardcoded RVAs          │
  │  derived_offsets.h              — computed offset helpers │
  │  scanner.h                      — AOB pattern scanner     │
  │  resolver.cpp                   — dynamic offset resolver │
  │  xstr.h                         — XOR string obfuscation  │
  │  sc_debug.h / logcrypt.h        — logging/instrumentation │
  └──────────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
SC_Replay_Source/
│
├── replay.h / replay.cpp          Core engine: ReplayAPC, ScActivityAPC, ScLoopThread, SC AutoSync
├── probe.h / probe.cpp            Hardware breakpoint probe for mission capture
├── http_monitor.h / http_monitor.cpp   HTTP traffic interception + curl hooking
├── state.h                        Global state, serialization, field overrides, weapon config
├── baked_capture.h                Hardcoded mission capture data (~16 KB binary constants)
│
├── offsets.h / offsets.cpp        All hardcoded RVA constants and slot structure definitions
├── derived_offsets.h              Computed offset helpers with fallback logic
├── scanner.h                      AOB (Array of Bytes) pattern scanner
├── resolver.h / resolver.cpp      Dynamic RVA resolution via pattern matching
│
├── sc_present.h / sc_present.cpp  Window message-based game thread dispatch
├── sc_guard.h / sc_guard.cpp      Crash absorption via Vectored Exception Handler
├── sc_limit.h / sc_limit.cpp      Mission UUID rotation via code cave injection
├── sc_tracker.h / sc_tracker.cpp  Atomic SC call counter
│
├── license.h / license.cpp        License system (disabled — always unlocked)
├── farming.h / farming.cpp        Farming cheat features (stubs)
├── loadout.h / loadout.cpp        Live weapon reader (stubs)
├── entity_protect.h / entity_protect.cpp  Entity memory protection (stubs)
│
├── xstr.h                         Compile-time XOR string obfuscation
├── logcrypt.h                     Encrypted logging stub
├── sc_debug.h                     Inline debug logging (disabled)
│
├── .gitattributes                 Git line-ending normalization
├── .gitignore                     Visual Studio gitignore (363 lines)
└── README.md                      This file
```

---

## Module Reference

### Core Engine

#### `replay.cpp` / `replay.h` (2,305 + 55 lines)
The master orchestrator. Contains the following subsystems:

**ReplayAPC** (~1,450 lines)
The primary mission replay function, executed on the game's main thread via window message dispatch:
- Loads a captured mission from `g_state.captures`
- Applies XP/Medals/Slips overrides via `FieldOverride` structs
- Updates war-time to reflect elapsed time since capture
- Cycles weapons through the 51-weapon table (every N replays)
- Injects current lobby player IDs into the mission payload
- Calls the game's internal `BuildPayload` function at `rv_fn0 - 0x10`
- Calls weapon stats function at `rv_fn0 - 0x10 - 0x140`
- VEH-guarded execution with context restoration on crash

**ScActivityAPC** (~200+ lines)
Super Credits activity execution:
- Validates the current game session state
- Calls the game's Activity function at `rv_fn1`
- Monitors serverInfo ring buffer before/after
- Launches a 10-second delayed monitoring thread to process results

**ScLoopThread**
The automated SC farming loop:
- Runs batches of 9 SC calls with 58-second inter-batch cooldown
- Alternates between SC activity (object ID `0x7F8FE16`) and Medal activity (object ID `0xA2C8A4E`)
- Generates random UUIDs for each mission call
- Writes mission IDs to game memory or uses POST body swap
- Tracks calls: sent, acked, skipped, retried, recovered, failed
- Supports `SC_GOAL` auto-stop and timer-based limits

**SC_AutoSyncLoop**
Background thread polling the PeerManager every 2 seconds:
- Reads current player IDs from the lobby
- Updates `s_scIds` array for payload lobby injection

**Mission ID Management**
- `TryAutoDetectMissionId()` — scans all writable memory for the golden mission ID string
- `LaunchMidScanAsync()` — background thread for memory scanning
- `WriteMidUUID()` — writes fresh UUIDs to all discovered hit locations
- `ValidateMissionStruct()` — validates candidate addresses by reading struct fields

**Fake Entity System**
Fallback when no real entity data is available:
- Creates a 2,048-entry fake vtable (all entries point to `xor rax, rax; ret`)
- Allocates a 65,536-byte fake entity and 65,536-byte fake fixup structure

**VEH Crash Protection**
- `VehHandler` — catches access violations, divide-by-zero, overflow, stack overflow during ReplayAPC
- `ScVehHandler` — same for ScActivityAPC
- Guard timeout thread (30s cooldown reset)

**Watchdog Threads**
- Guard timeout monitor (30s) — resets stuck APC guard
- Replay progress timeout monitor (30s)
- SC heartbeat monitor (150s) — restarts SC loop if stalled
- VEH re-registration (every 5 minutes)

**Core Functions**
- `GenerateUUID()` — Win32 CoCreateGuid wrapper
- `UuidToGuidLE()` / `UuidToRawBE()` / `GuidLEToUuid()` — UUID-GUID format conversion
- `TriggerReplay()` — initiates a replay APC via window message
- `TriggerSC()` — initiates an SC activity APC
- `ForceRewardSync()` — calls progression fetch function at `rv_fn9 + 1337`

**External Globals**
- `g_offlineBoostMode` — offline mode flag
- `g_burstActive` / `g_burstSent` / `g_burstTotal` / `g_burstDone` — burst replay state

---

### Capture System

#### `probe.cpp` / `probe.h` (704 + 25 lines)
The hardware breakpoint probe is the primary mission capture mechanism. It uses x64 debug registers (Dr2, Dr3) to intercept game function execution at precise addresses **without modifying a single byte of game code**.

**Hardware Breakpoint Handler**
Registered as a Vectored Exception Handler at priority 1:
- **Dr2 hit** (at BuildPayload entry): Captures RCX, RDX, R8, R9 register values and a stack flag
- **Dr3 hit** (post-BuildPayload return): Captures mission data from the returned structure
- **Dr3 hit** (instant-complete): Writes `2` to the mission object at offset `+0x20`

**Breakpoint Management**
- `SetHWBreakpointAllThreads()` — enumerates all process threads via `CreateToolhelp32Snapshot`, suspends each, sets Dr2, resumes
- `ClearHWBreakpointAllThreads()` — removes Dr2 from all threads
- `RearmWatchdog` — background thread re-applies breakpoints every 2 seconds

**CaptureFromContext()**
Performs a deep memory copy of the captured game state:
- Copies the ring buffer slot (3,208 bytes at `RING_SLOT_SIZE = 0xC88`)
- Deep-copies the entity memory region (up to 4 MB)
- Deep-copies the entity data (up to 64 KB)
- Snapshots mission data (up to 16 KB) and serial object data (up to 64 KB)
- Extracts war-time value from mission data at offset 0x38
- Saves the captured mission to `replay_cap.json`

**Instant Complete**
Sets a Dr3 breakpoint at the `InstantComplete` function address (`rv_fn6`). When triggered, writes value `2` to the mission object field at offset `+0x20`, instantly completing the mission. Toggled via `RearmIC()`.

**Thread Safety**
- `NtQueryInformationThread` — identifies game threads
- `SafeReadable()` — checks memory protection before reading
- `PauseDR2()` / `ResumeDR2()` — re-entrancy protection

#### `state.h` (392 lines)
Global shared state definitions:

```cpp
struct FieldOverride {
    uintptr_t offset;   // Target field offset in mission data
    uint32_t  value;    // Override value
    bool      enabled;  // Whether override is active
    char      label[32]; // Display label (e.g., "XP", "Medals", "Slips")
};

struct CapturedMission {
    // Pointers to game memory regions
    uintptr_t serverInfo, entityPtr, missionData;
    // Deep copies of entity data (VirtualAlloc-backed)
    uint8_t*  entityCopy;
    uint8_t*  entityDataCopy;
    // Ring buffer slot data (0xC88 bytes)
    uint8_t   slotData[GS::RING_SLOT_SIZE];
    // Mission and serial object snapshots
    uint8_t   missionDataSnapshot[16384];
    uint8_t   serObjSnapshot[65536];
    // URL (max 256) and mission ID string (max 64)
    char      url[256], missionStr[64];
    // Field override instances
    FieldOverride xpOverride, medalsOverride, slipsOverride;
};

struct ReplayState {
    bool probeArmed, hookInstalled;
    bool instantMissionEnabled;
    std::vector<CapturedMission> captures;
    int replayCount, cooldownRemaining;
    bool replayInProgress;
    int replayHardlock;  // 300 seconds
    bool autoReplayEnabled; // 45 second interval
    bool sessionLimitEnabled; // 30 minute limit
    bool replayLimitEnabled;  // max 10 replays
    bool gatePatched;
    uintptr_t gateAddress;
    uint8_t gateOrigByte;
    DWORD gameThreadId;
    HANDLE gameThreadHandle;
    uint32_t capturedWarTime, captureTickCount;
    uintptr_t gameBase, gameEnd;
    uintptr_t pServerInfo, pWarData, pEntityData;
    // Thread-safe logging
    std::vector<LogEntry> log, replayLog;
    std::mutex logMutex, replayLogMutex;
    // Activity capture data
    bool activityCaptured;
    char activityGmiStr[256];
    uint32_t activityObjectId;
};

struct WeaponOverride {
    bool allGunsMode;         // Cycle through all 51 weapons
    bool selectedGunsMode;    // Cycle through user-selected subset
    int  gunsReplaysPerWeapon; // Weapons switch every N replays (default 9)
    int  scPerReplay;         // SC target per replay
    bool forceNextWeapon;     // Skip to next weapon now
    bool selectedGuns[51];    // Checkbox array for selected mode
    int  currentGunIndex;     // Position in the weapon table
    int  replaysWithCurrent;  // Replays since last weapon switch
};
```

**Inline Globals**: `g_state`, `g_weaponOverride`, `g_hModule`

**Serialization Functions**:
- `SaveCapture()` — serialize a `CapturedMission` to `replay_cap.json`
- `LoadCapture()` — deserialize from `replay_cap.json`
- `LoadBakedCapture()` — load from `baked_capture.h` constants (offline mode)
- `SaveSessionStats()` / `LoadSessionStats()` — persist sent/acked counts to `session.json`

#### `baked_capture.h` (1,228 lines)
Hardcoded binary mission data constants for offline operation:
- `kBakedWarTime` = `73782850` — frozen war-time value
- `kBakedSerObjAddr` = `2654691347712` (0x269BFFF00)
- `kBakedObjectId` = `1309039571` (0x4E04D4D3)
- `kBakedUrl` — full API endpoint URL (Mission/end)
- `kBakedMd[]` — ~1,000+ bytes of serialized mission data
- `kBakedSlot[]` — ~1,218 bytes of ring buffer slot data
- `kBakedGs[]` — 112 bytes of game state / GMI data

This allows replay functionality without requiring a live probe capture.

---

### HTTP Interception

#### `http_monitor.cpp` / `http_monitor.h` (1,451 + 45 lines)
A full HTTP traffic interception engine built on inline hooks of libcurl's exported functions.

**libcurl API Hooking**
Hooks three core libcurl functions via x64 inline hooking:
| Hook | Purpose | Slot Tracking |
|---|---|---|
| `curl_easy_setopt` | Capture option values (URL, POST body, headers) | Up to 64 handles |
| `curl_easy_perform` | Capture POST body, inject missionId, intercept response | By handle |
| `curl_easy_cleanup` | Release slot tracking | By handle |

Hooking uses stolen bytes + trampoline: steals 14+ bytes from the function prologue, writes a `JMP` to the hook function, creates a trampoline of stolen bytes + `JMP` back.

**Request Classification**
URLs are classified into three categories:
- **MiniGame** — matchmaking/match requests
- **Activity** — Super Credits and Medal activity calls
- **Recon** — Reconnection requests

**Response Interception**
- Installs a custom `CURLOPT_WRITEFUNCTION` callback on tracked handles
- Captures full response body for Activity requests
- Parses JSON to extract: activity totals, rewarded/unrewarded counts, SC earned, bonus counts
- Provides callback mechanism (`MissionEndCallback`) for mission-end body capture

**Mission ID Injection**
- `try_inject_missionid()` — replaces the `missionId` field in Activity POST bodies with a provided UUID string
- `try_capture_golden()` — on first successful (HTTP 200) Activity response, captures the `missionId` from the outgoing POST body as the "golden" mission ID
- `extract_missionid()` — simple string-based JSON parser for the `"missionId"` field

**POST Body Swap**
- `ActivatePostSwap(uuid)` — swaps missionId in all outgoing Activity POSTs to the given UUID
- `DeactivatePostSwap()` — restores original behavior

**BCrypt Signature Capture**
Hooks `BCryptHashData` from `bcrypt.dll` to capture request signing:
- Detects both single-call and chunked signature computation patterns
- Captures the 8-byte signing nonce and 512-byte signing key
- Capable of detecting chunked calls where first call provides nonce and second provides key

**Auth Header Capture**
Captures from `CURLOPT_HTTPHEADER` options:
- Authorization header
- Cookie header
- X-Session header
- X-Auth header
- X-Token header
- Content-Type header
- Accept header
- Base URL for API endpoint

**Clone-Based Replay Testing**
The `clone_worker` thread function tests signature replay:
- Creates a new libcurl handle
- Copies all captured headers and POST body
- Sends the replayed request to the captured endpoint
- Verifies that X-Signature replay produces valid responses

**Call Result Tracking**
Tracks comprehensive statistics:
- Activity totals (total calls made)
- Rewarded vs. no-reward counts
- SC earned total
- Bonus counts
- Retry tracking: recovered vs. permanently failed
- Per-batch and cumulative counters

**Key Functions**
- `InstallWinHttpHooks()` — main hook installer
- `hk_setopt()` / `hk_perform()` / `hk_cleanup()` — hook trampolines
- `hk_BCryptHashData()` — BCrypt hook (captures signing material)
- `intercept_write_cb()` — response body callback
- `hook_inline()` — x64 inline hook engine using hde64 disassembly
- `install_response_capture()` — swap write function/data callbacks per handle

**hde64 Disassembler** (embedded, lines 304–517)
The Hacker Disassembler Engine x64 is embedded directly in `http_monitor.cpp`. It provides:
- Accurate x64 instruction length calculation
- Prefix, opcode, ModR/M, SIB, and displacement field detection
- Required for calculating the minimum "stolen bytes" for inline hook trampolines

---

### Safety & Dispatch

#### `sc_present.cpp` / `sc_present.h` (111 + 10 lines)
**Window Message-Based Dispatch**
Instead of using `QueueUserAPC`, `CreateRemoteThread`, or other detectable injection methods, the tool subclasses the game's main window and uses custom window messages:

| Message | Purpose |
|---|---|
| `WM_SC_DISPATCH` (0x8000 + 0x7EA) | Triggers SC Activity APC on game thread |
| `WM_GT_DISPATCH` (0x8000 + 0x7EB) | Generic function dispatch |

The window is found by class name (`"Helldivers2"`) or title (`"HELLDIVERS 2"`). A custom `WNDPROC` replaces the original, and on receiving the custom messages, executes the queued callback on the game's main thread. A `std::atomic<bool>` re-entrancy guard prevents overlap.

#### `sc_guard.cpp` / `sc_guard.h` (195 + 19 lines)
**Crash Absorption VEH**
A Vectored Exception Handler registered at priority 1 that catches and suppresses crashes:

- When any non-owned thread crashes within `game.dll` or the game executable:
  - Sets `RAX = 0`, `RIP = s_retStub` (a `xor eax, eax; ret` gadget in allocated memory)
  - Records the absorption event timestamp
- If 3+ crashes occur within 5 minutes, sets `s_shouldBackoff = true`
- Tool-owned threads (up to 16, registered via `RegisterOwnThread()`) are exempt
- `NotifyScApc()` arms the SC-specific crash guard

**Absorption Stub**: `48 31 C0 C3` = `xor rax, rax; ret`

#### `sc_limit.cpp` / `sc_limit.h` (181 + 11 lines)
**Code Cave UUID Rotation**
Injects a small assembly stub near the target hook location in `game.dll`:

- Scans for a specific AOB pattern to locate the hook point
- `AllocNear()` allocates memory within ±0x70000000 bytes (within relative JMP range)
- Injects assembly that:
  - Saves/restores registers (push/pop all volatile registers)
  - Checks `g_enabled` flag (atomic bool)
  - If enabled and source buffer (R8) is non-null, does `rep movsb` (copies 36 bytes from `g_uuid` to destination)
  - Falls through to the original instruction stream
- Background thread handles UUID auto-rotation
- `ForceUUID()` for manual override

#### `sc_tracker.cpp` / `sc_tracker.h` (9 + 9 lines)
Simple atomic call counter for SC operations:
- `AddCall()` — increments atomic counter
- `GetCallCount()` — returns current count
- `GetEstimatedSC()` — estimates SC earned as `count * 10`
- `Reset()` — zeroes counter

#### `entity_protect.cpp` / `entity_protect.h` (37 + 13 lines)
Entity pointer safety stubs (all empty in this release build). The only implemented function is:

- `IsAlive(addr, vtable)` — uses `__try/__except` to safely read a vtable pointer at an address and compare it, checking if the entity object is still valid

---

### Foundation Layer

#### `offsets.h` / `offsets.cpp` (71 + 35 lines)
**Namespace**: `GS` (Global State)

Defines all hardcoded Relative Virtual Addresses (RVAs) for functions and global pointers within `game.dll`:

**Function RVAs**
| Label | Variable | Purpose | Default |
|---|---|---|---|
| FN_A | `rv_fn0` | BuildPayload function | `0xEEEA80` |
| FN_B | `rv_fn1` | Activity function | `0xEEF040` |
| FN_C | `rv_fn5` | Enqueue function | `0xEF9030` |
| FN_D | `rv_fn6` | InstantComplete function | `0x525C3E` |
| FN_F | `rv_fn8` | (Internal call) | `0xEF74E0` |
| FN_9 | `rv_fn9` | Progression fetch function | `0xEE9E00` |
| FN_GT | `rv_gt` | Gate function | `0xF0889F` |

**Global Pointer RVAs**
| Label | Variable | Purpose | Default |
|---|---|---|---|
| PTR_A | `rv_gp1` | ServerFactory global | `0x1A7F738` |
| PTR_C | `rv_gp3` | SessionData global | `0x1A7F788` |
| PTR_D | `rv_gp4` | ServerInfo global | `0x1A91BA8` |
| PTR_PM | `rv_gp7` | PeerManager global | `0x1A925B8` |

**SC-Specific RVAs**
| Variable | Purpose |
|---|---|
| `rv_sc_act` | Activity function (alternate resolution) |
| `rv_sc_gbl` | GameGlobal pointer |
| `rv_sc_mid` | MissionId field offset |
| `rv_sc_ses` | Session dispatch offset |

**Peer Manager Offsets**
| Variable | Purpose |
|---|---|
| `rv_pm_cnt` | Peer count field offset |
| `rv_pm_slt` | Peer slot base offset |

**Server Info Offsets**
| Variable | Purpose |
|---|---|
| `rv_si_ctr` | Ring buffer counter offset |
| `rv_si_flg` | Server info flag offset |
| `rv_si_url` | URL buffer offset |
| `rv_si_que` | Queue buffer offset |
| `rv_si_rb` | Request buffer offset |

**Ring Buffer Slot Constants**
| Constant | Value | Description |
|---|---|---|
| `RING_SLOT_SIZE` | `0xC88` (3,208) | Bytes per slot |
| `RING_SLOT_COUNT` | `64` | Number of slot entries |
| Slot offsets: flag, type hash, version, URL, serial object, entity data, etc. | Various | Layout of each ring buffer entry |

**Entity Constants**
- `ENT_SESSION_ID` = `0x11B0B0`
- `ENT_GATE_STRING` = `0x31D7BC`
- `TYPE_MISSION_END` = `0x1E555EA6`

**Signatures**
- `ENQUEUE_SIG[]` = `{0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83}` — known function prologue for verifying the enqueue function at runtime
- `kGO` = `0x74` (JE opcode), `kGP` = `0xEB` (JMP opcode) — used for gate function byte patching

---

#### `derived_offsets.h` (48 lines)
Computed offset helpers with fallback logic. Each function attempts to use the primary SC-specific RVA, falling back to computed values from base function RVAs:

| Function | Primary | Fallback |
|---|---|---|
| `GetActivityFnRVA()` | `rv_sc_act` | `rv_fn0 + 0x230` |
| `GetGameGlobalRVA()` | `rv_sc_gbl` | `rv_gp4 + 8` |
| `GetMissionIdOffset()` | `rv_sc_mid` | (none) |
| `GetSessionDispatch()` | `rv_sc_ses` | (none) |
| `GetPeerMgrCountOff()` | `rv_pm_cnt` | (none) |
| `GetPeerMgrSlotOff()` | `rv_pm_slt` | (none) |
| `GetSICtrOff()` | `rv_si_ctr` | (none) |

---

#### `scanner.h` (65 lines)
**Namespace**: `AOB`

Array-of-Bytes pattern scanner for finding code/data within loaded modules.

```cpp
struct AOBPattern {
    uint8_t  bytes[64];  // Pattern bytes
    bool     mask[64];   // true = wildcard
    uint32_t length;     // Pattern length

    static AOBPattern parse(const char* pattern);
    // Parses IDA-style strings: "48 89 5C ?? 08 57 48 83"
};

bool ScanModule(const char* moduleName, const AOBPattern& pattern);
bool ScanModule(const char* moduleName, const char* pattern);
```

Uses `GetModuleHandleA` + `GetModuleInformation` (from `psapi.dll`) to determine module bounds, then performs byte-level scanning with wildcard support.

---

#### `resolver.cpp` / `resolver.h` (244 + 17 lines)
**Dynamic RVA Resolution**

When the game updates and hardcoded offsets become stale, the resolver uses AOB pattern matching to find the correct RVAs at runtime.

```cpp
struct RvaReport {
    const char* name;       // Human-readable label
    uintptr_t   hardcoded;  // Originally hardcoded value
    uintptr_t   resolved;   // Newly resolved value
    bool        found;      // Whether pattern matched
    bool        updated;    // Whether resolved differs from hardcoded
    const char* method;     // Pattern description (e.g., "v21 build payload xref")
};

std::vector<RvaReport> ResolveAllRVAs(uintptr_t gameBase, size_t gameSize);
```

**Resolved Offsets**
| Label | GS Variable | Hardcoded | Resolution Method |
|---|---|---|---|
| FN_C (Enqueue) | `rv_fn5` | `0xEF9030` | Match known function prologue bytes |
| FN_D (InstantComplete) | `rv_fn6` | `0x525C3E` | Byte match with different register |
| FN_F | `rv_fn8` | `0xEF74E0` | Prologue stack allocation pattern |
| FN_9 (Progression) | `rv_fn9` | `0xEE9E00` | Pattern around constant `0x1E7941B` |
| FN_GT (Gate) | `rv_gt` | `0xF0889F` | Context byte match |
| PTR_A (ServerFactory) | `rv_gp1` | `0x1A7F738` | RIP-relative xref |
| FN_B (Activity) | `rv_fn1` | `0xEEF040` | Derived from PTR_A xref − `0x21` |
| PTR_D (ServerInfo) | `rv_gp4` | `0x1A91BA8` | RIP-relative xref |
| PTR_C (SessionData) | `rv_gp3` | `0x1A7F788` | RIP-relative xref |
| FN_A (BuildPayload) | `rv_fn0` | `0xEEEA80` | Derived from PTR_C xref − `0x1F4` |
| PTR_PM (PeerManager) | `rv_gp7` | `0x1A925B8` | RIP-relative xref |

Each offset may have multiple pattern variants for different game versions (v20, v21, v22). If any offset requires a fallback pattern, the resolver dumps `game.dll` to `game_current.dll` for offline analysis.

---

#### `xstr.h` (55 lines)
**Compile-Time XOR String Obfuscation**

Hides string literals in the binary using compile-time XOR encryption:

```cpp
// XOR algorithm: char ^ (0x5A ^ (i * 0x37))
XStrN<11> str("Hello World");   // Char string
XStrW<11> wstr(L"Hello World"); // Wide string

// Macros for convenience
XSTR("sensitive_string")    // Obfuscated char string
XWSTR(L"sensitive_string")  // Obfuscated wchar_t string

// Decrypt at runtime
str.d();  // Returns decrypted const char*
```

Each character is XOR'd with a key that varies by position (`0x5A ^ (i * 0x37)`), making simple binary string search ineffective against the compiled DLL.

---

### Feature Stubs

These modules have empty or placeholder implementations in this source release:

#### `farming.cpp` / `farming.h` (19 + 36 lines)
Stubbed farming cheat features:
- `SetMultiplierHook`, `AddSamples`, `SamplesReward`, `ForceDifficulty`, `InstantShuttle`, `ReplayRefresh`
- Default config: `difficulty = 10`, `common = 100`, `rare = 100`, `super = 100`

#### `loadout.cpp` / `loadout.h` (5 + 6 lines)
- `ReadLiveWeapons()` — always returns `false`
- `GetLoadoutStatus()` — always returns `"N/A"`

#### `license.cpp` / `license.h` (28 + 21 lines)
- `IsUnlocked()` — always returns `true` (no license enforcement in this build)
- `Validate(key)`, `Revoke()`, `GetStatus()`, `GetCacheFilePath()` — all stubbed

#### `logcrypt.h` (5 lines)
- `LogCrypt::WriteLog()` — empty function body

#### `sc_debug.h` (4 lines)
- `sc_dbg()` and `sc_dbg_hex()` — empty inline functions (all debug logging removed)

---

## Data Flow

### Capture Flow

```
Probe::Install()
    │
    ▼
Set Dr2 HW breakpoint at BuildPayload function entry (rv_fn0 address)
Set Dr3 HW breakpoint at post-BuildPayload return address
    │
    ▼
Game thread executes → hits Dr2 breakpoint
    │
    ▼
Vectored Exception Handler (HWBreakpointHandler)
    ├─ Captures RCX, RDX, R8, R9 register values
    ├─ Captures stack state flag
    └─ Returns EXCEPTION_CONTINUE_EXECUTION
    │
    ▼
Game thread continues → hits Dr3 breakpoint (post-return)
    │
    ▼
CaptureFromContext()
    ├─ Copies ring buffer slot (0xC88 bytes at RING_SLOT_SIZE)
    ├─ Deep-copies entity memory (up to 4 MB)
    ├─ Deep-copies entity data (up to 64 KB)
    ├─ Snapshots mission data (up to 16 KB)
    ├─ Snapshots serial object data (up to 64 KB)
    ├─ Extracts war-time from missionData + 0x38
    ├─ Stores in g_state.captures as CapturedMission
    └─ Saves to replay_cap.json via SaveCapture()
```

### Replay Flow

```
TriggerReplay()
    │
    ▼
ScPresent::QueueCall(ReplayAPC)
    │
    ▼
WM_GT_DISPATCH posted to game window
    │
    ▼
Custom WNDPROC receives message on game thread
    │
    ▼
ReplayAPC()
    ├─ Loads captured mission data from g_state.captures
    ├─ Applies FieldOverride values (XP, Medals, Slips)
    ├─ Updates war-time based on elapsed time since capture
    ├─ Cycles weapons through 51-weapon table (every N replays)
    ├─ Injects current lobby player IDs at offsets 0x68 and 0x2C8
    ├─ Writes modified data into game memory
    ├─ Calls BuildPayload function in game.dll (at rv_fn0 - 0x10)
    ├─ Calls weapon stats function (at rv_fn0 - 0x10 - 0x140)
    └─ (VEH-guarded — restores context on crash)
    │
    ▼
Game sends modified mission data to server
http_monitor captures response for reward tracking
```

### SC Farming Flow

```
ScLoopThread
    │
    ▼
Generate random UUID (CoCreateGuid)
Generate random objectId for SC (0x7F8FE16) or Medal (0xA2C8A4E) activity
    │
    ▼
Write mission UUID to game memory:
    ├─ Option A: WriteMidUUID() — patch all found hit locations
    └─ Option B: ActivatePostSwap() — swap missionId in POST body
    │
    ▼
ScPresent::QueueSC(actObj)
    │
    ▼
WM_SC_DISPATCH posted to game window
    │
    ▼
Game thread executes ScActivityAPC()
    ├─ Validates session state
    ├─ Calls game's Activity function (at rv_fn1)
    ├─ Monitors serverInfo ring buffer (before/after)
    └─ Launches 10s delayed monitor thread
    │
    ▼
http_monitor intercepts HTTP response
    ├─ Classifies as Activity
    ├─ Captures response body
    ├─ Parses reward amounts from JSON
    ├─ Updates call tracking counters
    └─ Captures golden missionId on first success
    │
    ▼
58-second cooldown between batches of 9 calls
Repeat until SC goal reached or timer expires
```

---

## Key Technical Details

### Hardware Breakpoint Probe

The probe leverages the x64 debug register architecture:

| Register | Purpose | Trigger Address |
|---|---|---|
| **Dr2** | BuildPayload entry point capture | `rv_fn0` |
| **Dr3** | Post-BuildPayload return capture | Return address on stack |
| **Dr3** (alt) | Instant complete | `rv_fn6` (InstantComplete function) |

**Debug Register Layout (Dr7)**
- Local enable bits (L0–L3): controls which threads the breakpoint fires on
- Read/Write bits (RW0–RW3): set to `0b00` (execute-only breakpoint)
- Length bits (LEN0–LEN3): set to `0b00` (1-byte granularity)

**Key advantage**: No code modifications — anti-cheat systems that scan for byte patches or software breakpoints (`INT 3` / `0xCC`) won't detect hardware debug registers without specifically checking `GetThreadContext`.

**Limitations**: Only 4 debug registers total (Dr0–Dr3), and the probe uses only Dr2 and Dr3 to leave Dr0 and Dr1 available for potential game debugger usage.

---

### Inline Hooking (libcurl)

The `hook_inline()` function in `http_monitor.cpp` implements standard x64 inline hooking:

1. **Disassemble** the target function prologue using **hde64** (Hacker Disassembler Engine x64)
2. **Steal** enough bytes to cover at least 14 bytes (minimum for a 64-bit absolute JMP: `FF 25 00 00 00 00` + 8-byte address)
3. **Allocate** a trampoline via `VirtualAlloc` (PAGE_EXECUTE_READWRITE):
   - Copy stolen bytes
   - Conditionally append `JMP` to `original_function + stolen_len`
4. **Write** a `JMP [rip+0]` + target address at the function entry
5. **Record** the handle-to-slot mapping in a fixed-size slot array (64 entries)

**Stolen byte calculation** (via hde64):
```cpp
int len = 0;
hde64s hs;
while (len < 14) {
    len += hde64_disasm((void*)(target + len), &hs);
}
```

**Trampoline layout**:
```
[stolen bytes (variable length)]
[JMP to original_function + stolen_len (14 bytes)]
```

---

### AOB Pattern Scanning

`scanner.h` provides byte-pattern scanning with IDA-style wildcard support:

```cpp
AOBPattern p = AOBPattern::parse("48 89 5C ?? 08 57 48 83 ?? ?? 48 8B");
//                                  ^^ ^^ ^^ vv ^^ ^^ ^^ ^^ vv vv ^^ ^^
//                                  fixed bytes         wildcard (??)
```

The scan iterates through the module's memory region byte-by-byte, comparing each byte against the pattern (respecting the boolean mask for wildcards), and returns the address of the first match.

**Used by**:
- `resolver.cpp` for dynamic offset resolution
- `sc_limit.cpp` for finding the UUID rotation hook point
- `replay.cpp` for `ScanForActivityFunction()` and `IsEnqueueSafe()`

---

### Dynamic RVA Resolution

The resolver (`resolver.cpp`) implements a multi-version offset resolution strategy:

**For function addresses**, it uses instruction-level pattern matching:
- Known function prologue bytes (stack frame setup, register pushes)
- Known constants embedded in the function (e.g., constant `0x1E7941B` in the progression function)
- Relative offsets between related functions (e.g., Activity function is always 33 bytes before ServerFactory's instruction xref)

**For global pointer addresses**, it uses RIP-relative xref analysis:
1. Scan for instructions that reference the pointer: `LEA REG, [RIP + displacement]`
2. Parse the `displacement` field
3. Compute the target address: `instruction_address + instruction_length + displacement`
4. Read the pointer value from the game module's global data section

**Fallback handling**: Each target has one or more backup patterns. A fallback is considered compromised and triggers a `game.dll` dump.

---

### Window Message Dispatch

The `ScPresent` system avoids common injection vectors:

| Approach | Rationale |
|---|---|
| `CreateRemoteThread` | Highly detectable, commonly monitored |
| `QueueUserAPC` | Game threads not always in alertable state |
| `SetWindowsHookEx` | May not be in same hook chain |
| **Custom window messages** | Uses the game's own message pump, zero extra syscalls |

The game window is located by:
1. Class name: `"Helldivers2"` (primary)
2. Window title: `"HELLDIVERS 2"` (fallback)
3. `EnumWindows` + `GetClassNameA` / `GetWindowTextA`

`SetWindowLongPtrA(GWLP_WNDPROC, ...)` replaces the original window procedure. The replacement passes through all messages except `WM_SC_DISPATCH` and `WM_GT_DISPATCH`, which are intercepted and dispatched on the game's main thread.

---

### Crash Absorption VEH

`ScGuard` registers a Vectored Exception Handler at priority 1 (the highest priority — executes before any other handlers):

```
Exception occurs in game code (e.g., access violation, divide by zero)
    │
    ▼
ScGuard VEH (priority 1)
    ├─ Check: is the faulting address in game.dll or game.exe?
    ├─ Check: is the faulting thread owned by this tool? (skip if yes)
    ├─ Check: s_shouldBackoff? (skip if backoff in effect)
    ├─ Record timestamp of crash event
    ├─ Set RAX = 0 (clear return value)
    ├─ Set RIP = s_retStub (xor eax, eax; ret)
    └─ Return EXCEPTION_CONTINUE_EXECUTION
        (exception is fully absorbed — game continues running)
    │
    ▼
Backoff logic: if 3+ crashes in 5 minutes → s_shouldBackoff = true
```

The crash absorption effectively makes the game resilient to crashes caused by tool operations, preventing both game termination and crash-telemetry-based detection.

---

### Code Cave Injection (UUID Rotation)

`ScLimit` creates a code cave by:

1. Scanning for a known AOB pattern in `game.dll` (identifies the hook point)
2. Allocating memory near the target with `AllocNear()`:
   - Searches within ±0x70000000 bytes (the range of a 32-bit relative JMP)
   - Uses `VirtualAlloc(MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)`
3. Injects assembly:
   ```asm
   push rax
   push rcx
   push rdx
   push rsi
   push rdi
   push rbx
   push rbp
   push r8
   push r9
   push r10
   push r11
   push r12
   push r13
   push r14
   push r15
   pushfq

   cmp byte ptr [g_enabled], 0
   je skip
   test r8, r8
   jz skip
   mov rsi, [g_uuid]        ; source = rotation UUID buffer
   mov rcx, 36              ; count = 36 bytes (UUID string + null)
   rep movsb                ; memcpy(dest=R8, src=RSI, cnt=36)

   skip:
   popfq
   pop r15
   pop r14
   pop r13
   pop r12
   pop r11
   pop r10
   pop r9
   pop r8
   pop rbp
   pop rbx
   pop rdi
   pop rsi
   pop rdx
   pop rcx
   pop rax

   ; (fall through to original instructions)
   ```
4. The background `rotate_thread` cycles through a set of pre-generated UUIDs

---

### XOR String Obfuscation

`xstr.h` provides compile-time string obfuscation to prevent plain-text string search in the binary:

**Encryption algorithm**:
```cpp
template <size_t N>
struct XStrN {
    char data[N];
    constexpr XStrN(const char(&src)[N]) {
        for (size_t i = 0; i < N; i++)
            data[i] = src[i] ^ (0x5A ^ (i * 0x37));
    }
    const char* d() const {
        return data; // Decryption omitted in this release build
    }
};
```

Each character is XOR'd with a key derived from its position: `key = 0x5A ^ (position * 0x37)`. This produces different encrypted values for the same character appearing at different positions.

All production string constants (API URLs, game function names, window class names, debug messages) use the `XSTR()` macro to prevent static analysis tools from discovering strings.

---

### Weapon Override System

The weapon system manages a table of 51 Helldivers 2 weapons with internal IDs:

| Index | Weapon Name | Internal ID |
|---|---|---|
| 0 | AR-23 Liberator | 2852344585 |
| 1 | AR-23P Liberator Penetrator | 2584612689 |
| 2 | AR-23C Liberator Concussive | 4042525201 |
| 3 | R-63 Diligence | 4052470460 |
| 4 | R-63CS Diligence Counter Sniper | 1944231224 |
| 5 | SMG-37 Defender | 1392065413 |
| 6 | MP-98 Knight | 2681533880 |
| 7 | SG-8 Punisher | 456945495 |
| 8 | SG-8S Slugger | 3886356347 |
| 9 | SG-225 Breaker | 3450040247 |
| 10 | SG-225SP Breaker Spray&Pray | 3654533182 |
| 11 | SG-225IE Breaker Incendiary | 1796165750 |
| 12 | LAS-5 Scythe | 3866352840 |
| 13 | LAS-16 Sickle | 2746251822 |
| 14 | PLAS-1 Scorcher | 925809350 |
| 15 | PLAS-101 Purifier | 3808114828 |
| 16 | ARC-12 Blitzer | 2136163121 |
| 17 | R-36 Eruptor | 610029066 |
| 18 | CB-9 Exploding Crossbow | 1663589294 |
| 19 | JAR-5 Dominator | 790644647 |
| 20 | P-2 Peacemaker | 3122012393 |
| 21 | P-19 Redeemer | 1822777433 |
| 22 | P-113 Verdict | 188142069 |
| 23 | P-4 Senator | 3115390823 |
| 24 | LAS-7 Dagger | 1270056193 |
| 25 | GP-31 Grenade Pistol | 2856670298 |
| 26 | PLAS-15 Loyalist | 1293181137 |
| 27 | SG-22 Bushwhacker | 4061102636 |
| 28 | FLAM-66 Torcher | 3120995212 |
| 29 | FLAM-40 Flamethrower | 3585403884 |
| 30 | ARC-3 Arc Thrower | 3977104437 |
| 31 | LAS-98 Laser Cannon | 975520411 |
| 32 | LAS-99 Quasar Cannon | 2706975592 |
| 33 | RS-422 Railgun | 2460486419 |
| 34 | GL-21 Grenade Launcher | 4130961272 |
| 35 | EAT-17 Expendable Anti-Tank | 1704002426 |
| 36 | GR-8 Recoilless Rifle | 2750027659 |
| 37 | FAF-14 Spear | 82856471 |
| 38 | AC-8 Autocannon | 2077663824 |
| 39 | APW-1 Anti-Materiel Rifle | 2051465721 |
| 40 | MG-43 Machine Gun | 1500305061 |
| 41 | MG-206 Heavy Machine Gun | 69999893 |
| 42 | M-105 Stalwart | 610366017 |
| 43 | MG-101 Gatling Sentry | 1873419027 |
| 44 | AX/TX-13 "Guard Dog" Rover | 1021424552 |
| 45 | A/G-16 Gatling Sentry | 2399353262 |
| 46 | A/M-12 Mortar Sentry | 767959545 |
| 47 | A/MLS-4X Rocket Sentry | 1676894626 |
| 48 | A/AC-8 Autocannon Sentry | 394174918 |
| 49 | EXO-45 Patriot Exosuit | 2036335043 |
| 50 | EXO-49 Emancipator Exosuit | 3894692685 |

**Cycling modes**:
- `allGunsMode`: cycles sequentially through all 51 weapons (index 0→50, loop to 0)
- `selectedGunsMode`: cycles only through weapons where `selectedGuns[i] == true`

**Switch logic**: Every `gunsReplaysPerWeapon` replays (default 9), the weapon index advances to the next weapon. `forceNextWeapon` can skip to the next weapon immediately.

**Scan mechanism**: The replay function scans the mission data buffer for known weapon IDs and patches them to the currently selected weapon ID.

---

### Session & Capture Serialization

The tool uses a custom JSON format (no external JSON library):

**`replay_cap.json`** — Mission capture data:
```json
{
    "url": "https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/end",
    "missionStr": "abcdef01-2345-6789-abcd-ef0123456789",
    "warTime": 73782850,
    "captureTick": 123456789,
    "serObjAddr": 2654691347712,
    "serObjSize": 65536,
    "objectId": 1309039571,
    "xp": 10000,
    "medals": 15,
    "slips": 500,
    "entSize": 4194304,
    "entDataSize": 65536,
    "mdSize": 16384,
    "slotSize": 3208,
    "gsSize": 112,
    "serObjData": "hex_encoded_binary_data...",
    "md": "hex_encoded_binary_data...",
    "slot": "hex_encoded_binary_data...",
    "gs": "hex_encoded_binary_data...",
    "entity": "hex_encoded_binary_data...",
    "entityData": "hex_encoded_binary_data..."
}
```

**`session.json`** — Session statistics:
```json
{
    "sent": 150,
    "acked": 148
}
```

Parsing uses simple string operations (`strstr`, `strchr`, `sscanf`) to find `"key": value` pairs, making it lightweight with zero dependency overhead.

---

## Build & Dependencies

### Platform Requirements

| Requirement | Detail |
|---|---|
| **Compiler** | Visual Studio 2022+ (C++17) |
| **Platform** | Windows 10/11 x64 |
| **Target** | x64 DLL (Release) |
| **Tools** | MSVC toolchain (cl.exe, link.exe) |
| **Windows SDK** | 10.0.19041.0 or later |

### Windows APIs Used

| API | Purpose |
|---|---|
| **kernel32.dll** | Memory allocation, thread management, process operations, synchronization |
| **ntdll.dll** | Thread information queries, APC queuing |
| **psapi.dll** | Module information enumeration |
| **dbghelp.dll** | Stack frame / call-site analysis |
| **bcrypt.dll** | Hooking BCryptHashData for signature capture |
| **ole32.dll** | UUID generation via CoCreateGuid |
| **libcurl** (game's import) | HTTP request/response interception |
| **tlhelp32.h** | Thread enumeration for breakpoint deployment |

**Key Win32 Functions**: `VirtualAlloc`, `VirtualProtect`, `VirtualQuery`, `GetModuleHandle`, `GetProcAddress`, `CreateThread`, `WaitForSingleObject`, `GetTickCount64`, `FlushInstructionCache`, `GetSystemInfo`, `SuspendThread`, `ResumeThread`, `GetThreadContext`, `SetThreadContext`, `FindWindowA`, `SetWindowLongPtrA`, `FindWindowA`, `PostMessageA`, `AddVectoredExceptionHandler`, `NtQueryInformationThread`

### Third-Party Code

| Library | Source | Purpose |
|---|---|---|
| **hde64** (Hacker Disassembler Engine x64) | Embedded in `http_monitor.cpp` (lines 304–517) | x64 instruction length calculation for inline hooking |

No external package managers (NuGet, vcpkg, Conan) are used. All dependencies are either Windows system APIs or embedded source.

### Build Instructions

Since no project file is included, create a new Visual Studio project or compile manually:

```powershell
# Create a new DLL project in Visual Studio 2022
# Add all .cpp files to the project
# Configure as x64 Release
# Properties:
#   - Configuration Type: Dynamic Library (.dll)
#   - C++ Language Standard: ISO C++17 (/std:c++17)
#   - Runtime Library: Multi-threaded (/MT) or Multi-threaded DLL (/MD)
#   - Optimization: Maximum (/O2)
#   - Preprocessor: WIN32_LEAN_AND_MEAN; NOMINMAX; _CRT_SECURE_NO_WARNINGS

# Or compile manually:
cl /LD /EHsc /O2 /std:c++17 /MT ^
   /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   *.cpp ^
   /Fe:sc_replay.dll ^
   psapi.lib ole32.lib user32.lib ^
   /link /DLL
```

**Output**: `sc_replay.dll` (or equivalent name)

**Injection**: The DLL must be injected into the Helldivers 2 process (`helldivers2.exe`) at runtime. Standard injection methods apply (manual mapping, `CreateRemoteThread` + `LoadLibrary`, etc.).

---

## Runtime Behavior

### Capture Mode

1. **Start the game** normally and begin a mission.
2. **Inject the DLL** into the `helldivers2.exe` process.
3. **Arm the probe** — `Probe::Install()` installs HW breakpoints.
4. **Complete the mission** naturally (or use InstantComplete).
5. The probe captures the mission state automatically when `BuildPayload` executes.
6. The capture is saved to `replay_cap.json` in the DLL's directory.

### Replay Mode

1. **Load a capture** from `replay_cap.json` or from the baked capture data.
2. **Configure overrides** — set XP, Medals, Slips values in the `FieldOverride` structs.
3. **Configure weapon** — select weapon via `allGunsMode`, `selectedGunsMode`, or `forceNextWeapon`.
4. **Trigger replay** — `TriggerReplay()` queues a `ReplayAPC` call on the game thread.
5. The game sends the modified mission payload as if a real mission was completed.
6. **Burst replay** — sends N replays staggered 500ms apart for batch operations.

### SC Farming Mode

1. **Configure goals** — set `SC_GOAL` for auto-stop or timer-based limits.
2. **Start the loop** — `ScLoopThread` begins automated farming.
3. The loop alternates between SC activity and Medal activity calls.
4. Each call generates a fresh random mission UUID.
5. Activity responses are intercepted for reward tracking.
6. The loop pauses when cooldowns are reached (58s between batches).

**Farming configurable parameters**:
- SC goal (auto-stop threshold)
- Session limit (default: 30 minutes)
- Replay limit (default: max 10 replays)
- Cooldown interval (default: 58 seconds per batch of 9)
- Auto-replay interval (default: 45 seconds)
- Activity type: SC (`0x7F8FE16`) or Medal (`0xA2C8A4E`)

### Offline / Baked Capture Mode

When no live capture is available, the tool loads mission data from `baked_capture.h`:
- Uses `kBakedMd`, `kBakedSlot`, `kBakedGs` for mission, slot, and game state data
- Uses `kBakedWarTime` for the war-time value
- Uses `kBakedUrl` for the API endpoint
- Uses `kBakedSerObjAddr` for the serial object pointer
- This mode is flagged by `g_offlineBoostMode`

---

## Runtime Data Files

| File | Purpose | Created At |
|---|---|---|
| `replay_cap.json` | Serialized mission capture data | Mission capture time |
| `session.json` | Session statistics (sent/acked counts) | On DLL initialization |
| `game_current.dll` | Dumped game.dll for offset analysis | When RVA resolver detects fallback |

The DLL's directory (returned by `GetModuleFileNameW`) is used as the root for all data files.

---

## Threading Model

The tool uses a carefully designed multi-threaded architecture:

| Thread | Purpose | Priority | Lifetime |
|---|---|---|---|
| **Game Main Thread** | Executes `ReplayAPC` and `ScActivityAPC` via window messages | Normal | Game process lifetime |
| **ScLoopThread** | Automated SC farming loop | Below normal | Until stopped or goal reached |
| **SC_AutoSyncLoop** | Reads lobby player IDs from PeerManager every 2s | Below normal | Indefinite |
| **RearmWatchdog** | Re-applies HW breakpoints every 2s | Below normal | While probe is armed |
| **MidScanAsync** | Background memory scan for mission ID strings | Below normal | Until scan complete |
| **RotateThread** | UUID rotation for sc_limit | Below normal | Indefinite |
| **DeferFreeThread** | Delayed memory cleanup | Lowest | As needed |
| **GuardTimeout** | Resets stuck APC guard every 30s | Below normal | Indefinite |
| **ReplayProgressTimeout** | Resets stuck replay every 30s | Below normal | While replay active |
| **SCHeartbeat** | Restarts SC loop if stalled (150s timeout) | Below normal | While SC active |
| **VEHReRegister** | Re-registers VEH handlers every 5 minutes | Below normal | Indefinite |
| **CloneWorker** | Tests X-Signature replay via cloned libcurl handle | Normal | On demand |
| **Monitor** | 10-second delayed SC activity monitor | Below normal | Per SC call |

**Synchronization**: All shared state is protected by `std::mutex` instances and `std::atomic` variables. The re-entrancy guard for window message dispatch uses a `std::atomic<bool>` compare-exchange loop.

---

## Offset Versioning

The resolver (`resolver.cpp`) supports multiple game versions:

```
v20 ──► Hardcoded offsets in offsets.cpp
v21 ──► Byte patterns variant 1 (fallback)
v22 ──► Byte patterns variant 2 (fallback)
```

When a resolved offset differs from the hardcoded value, it indicates a game update has occurred and the pattern-based fallback was used. This triggers:
1. A `game_current.dll` dump for offline analysis
2. An `RvaReport` with `found = true` and `updated = true`

If no pattern matches, the `RvaReport` has `found = false` and the hardcoded value is used as a last resort.

---

## Security & Evasion

The tool implements several anti-detection measures:

| Technique | Purpose |
|---|---|
| **Hardware breakpoints** (not `INT 3` patches) | Avoids software breakpoint detection |
| **VEH crash absorption** | Prevents crash telemetry from reaching game servers |
| **Window message dispatch** | Avoids `CreateRemoteThread` detection |
| **XOR string obfuscation** | Hides string literals from static analysis |
| **No byte patches on critical paths** | HW breakpoints instead of code modification |
| **Inline hooks at import level** | libcurl hooks avoid game code modification |
| **Guard timeout / backoff** | Prevents repeated crash patterns |
| **Low-priority background threads** | Minimizes performance impact |

---

## Limitations (Feature Stubs)

The following features exist as API declarations but have empty or placeholder implementations in this source release:

| Module | Stubbed Functions | Description |
|---|---|---|
| `farming.cpp` | All functions | Cheat features (multiplier, samples, difficulty, instant shuttle) |
| `loadout.cpp` | All functions | Live weapon reader |
| `license.cpp` | All functions except `IsUnlocked()` | License validation/activation |
| `entity_protect.cpp` | Most functions | Entity memory protection |
| `http_monitor.cpp` | `ScanForActivityFunction()` | Activity function scanner |
| `http_monitor.cpp` | `Install()` partial | Dispatch hook installation (disabled) |
| `logcrypt.h` | `WriteLog()` | Encrypted logging |
| `sc_debug.h` | `sc_dbg()`, `sc_dbg_hex()` | Debug logging |

These stubs represent features that were removed or disabled for this particular source release. The API is preserved so the build compiles cleanly.

---

## 51 Weapons Table

The complete weapon table (`kAG` and `kSG` arrays in `replay.cpp`):

| # | Weapon | Internal ID (uint32) |
|---|---|---|
| 0 | AR-23 Liberator | 2852344585 |
| 1 | AR-23P Liberator Penetrator | 2584612689 |
| 2 | AR-23C Liberator Concussive | 4042525201 |
| 3 | R-63 Diligence | 4052470460 |
| 4 | R-63CS Diligence Counter Sniper | 1944231224 |
| 5 | SMG-37 Defender | 1392065413 |
| 6 | MP-98 Knight | 2681533880 |
| 7 | SG-8 Punisher | 456945495 |
| 8 | SG-8S Slugger | 3886356347 |
| 9 | SG-225 Breaker | 3450040247 |
| 10 | SG-225SP Breaker Spray&Pray | 3654533182 |
| 11 | SG-225IE Breaker Incendiary | 1796165750 |
| 12 | LAS-5 Scythe | 3866352840 |
| 13 | LAS-16 Sickle | 2746251822 |
| 14 | PLAS-1 Scorcher | 925809350 |
| 15 | PLAS-101 Purifier | 3808114828 |
| 16 | ARC-12 Blitzer | 2136163121 |
| 17 | R-36 Eruptor | 610029066 |
| 18 | CB-9 Exploding Crossbow | 1663589294 |
| 19 | JAR-5 Dominator | 790644647 |
| 20 | P-2 Peacemaker | 3122012393 |
| 21 | P-19 Redeemer | 1822777433 |
| 22 | P-113 Verdict | 188142069 |
| 23 | P-4 Senator | 3115390823 |
| 24 | LAS-7 Dagger | 1270056193 |
| 25 | GP-31 Grenade Pistol | 2856670298 |
| 26 | PLAS-15 Loyalist | 1293181137 |
| 27 | SG-22 Bushwhacker | 4061102636 |
| 28 | FLAM-66 Torcher | 3120995212 |
| 29 | FLAM-40 Flamethrower | 3585403884 |
| 30 | ARC-3 Arc Thrower | 3977104437 |
| 31 | LAS-98 Laser Cannon | 975520411 |
| 32 | LAS-99 Quasar Cannon | 2706975592 |
| 33 | RS-422 Railgun | 2460486419 |
| 34 | GL-21 Grenade Launcher | 4130961272 |
| 35 | EAT-17 Expendable Anti-Tank | 1704002426 |
| 36 | GR-8 Recoilless Rifle | 2750027659 |
| 37 | FAF-14 Spear | 82856471 |
| 38 | AC-8 Autocannon | 2077663824 |
| 39 | APW-1 Anti-Materiel Rifle | 2051465721 |
| 40 | MG-43 Machine Gun | 1500305061 |
| 41 | MG-206 Heavy Machine Gun | 69999893 |
| 42 | M-105 Stalwart | 610366017 |
| 43 | MG-101 Gatling Sentry | 1873419027 |
| 44 | AX/TX-13 "Guard Dog" Rover | 1021424552 |
| 45 | A/G-16 Gatling Sentry | 2399353262 |
| 46 | A/M-12 Mortar Sentry | 767959545 |
| 47 | A/MLS-4X Rocket Sentry | 1676894626 |
| 48 | A/AC-8 Autocannon Sentry | 394174918 |
| 49 | EXO-45 Patriot Exosuit | 2036335043 |
| 50 | EXO-49 Emancipator Exosuit | 3894692685 |

---

## License Status

The license module (`license.cpp`) is fully stubbed. `IsUnlocked()` unconditionally returns `true`, meaning no license validation occurs in this build. All other license functions (`Validate`, `Revoke`, `GetStatus`, `GetCacheFilePath`) are no-ops.
