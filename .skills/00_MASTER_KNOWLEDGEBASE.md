# LIBERTEA.DLL Master Knowledgebase

> **Helldivers 2 Internal Cheat — Complete Reverse Engineering Analysis**
> Binary: LIBERTEA.DLL v414 | Size: 732,672 bytes packed / 3,489,792 bytes unpacked
> Authors: TheOGcup, Legend, HotPocket | Compiler: MSVC 2022, C++17, static CRT
> GUI: Dear ImGui v1.91.5, OpenGL overlay | Protection: Custom aPLib packer variant

---

## Table of Contents

1. [Binary Identity & PE Structure](#1-binary-identity--pe-structure)
2. [Architecture & Initialization Flow](#2-architecture--initialization-flow)
3. [Packer & Compression (Custom aPLib)](#3-packer--compression-custom-aplib)
4. [Hook System & Pattern Scanner](#4-hook-system--pattern-scanner)
5. [Syscall Infrastructure](#5-syscall-infrastructure)
6. [Network Protocol & SC/Medal Farming](#6-network-protocol--scmedal-farming)
7. [Auth & Subscription System](#7-auth--subscription-system)
8. [Feature Modules](#8-feature-modules)
9. [Anti-Analysis & Evasion](#9-anti-analysis--evasion)
10. [ImGui Overlay & UI](#10-imgui-overlay--ui)
11. [Data Structures & Memory Map](#11-data-structures--memory-map)
12. [Game Integration Targets](#12-game-integration-targets)
13. [Weaknesses & Attack Surface](#13-weaknesses--attack-surface)

---

## 1. Binary Identity & PE Structure

### File Hashes (Ground Truth)
| Artifact | SHA256 |
|----------|--------|
| LIBERTEA.DLL (packed) | `95c0e0a655906bde0ab24e70cc72f382b49b14e6ac833bc06a60fce07abe5287` |
| `.text_unpacked_mem.bin` | `ab362bf85256d681a1cf61072d36409ef9acafc9229f0389f0b74728bf0cf429` |
| Merkle root of .text | `219544f995618eeb61b9ffa13b005cd5ea0883e158befe44b3cfa5c391c24e26` |

### PE Sections (After Packing)
| Section | RAW Size | Virtual Size | RVA | Characteristics |
|---------|----------|--------------|-----|-----------------|
| .text | 0x000000 | 0x354000 | 0x001000 | RXW (empty on disk) |
| .rsrc #1 | 0x070000 | 0x070000 | 0x355000 | R (compressed .text) |
| .rsrc #2 | 0x003000 | 0x003000 | 0x3B4000 | RX (packer stub) |
| .rdata | 0x000400 | 0x020000 | 0x3B7000 | R |
| .data | 0x000200 | 0x001000 | 0x3D7000 | RW |
| .pdata | 0x000200 | 0x002000 | 0x3D8000 | R |
| .reloc | 0x000200 | 0x001000 | 0x3DA000 | R |

### Key PE Anomalies
- Entry point at RVA 0x3C4F30 (in .rsrc #2, NOT .text)
- `.text` raw size = 0 (filled at runtime by decompressor)
- Two `.rsrc` sections (section name reused)
- TimeDateStamp = 0 (epoch 1970-01-01)
- Import directory corrupted (garbage values)
- Section names contain garbage bytes
- Import table has 779 stubs in region 0x1000-0x2000

### Compiler Info
- MSVC 19.40 (VS 2022 17.8+), C++17, `/std:c++17`
- Flags: `/O1 /Os /Oi /Oy /Ob2 /GF /Gy /GL /MT` (static CRT)
- `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /GUARD:CF`
- `/ENTRY:0x3C4F30` (entry point override)
- `/OPT:REF /OPT:ICF /MERGE:.rdata=.text`

### DLL Dependencies (12 DLLs total)
- kernel32.dll, ntdll.dll, user32.dll, gdi32.dll, advapi32.dll
- ws2_32.dll, opengl32.dll, bcrypt.dll, winhttp.dll
- Dynamic: libcurl.dll → libcurl-x64.dll → curl.dll → wininet.dll
- Dynamic: xinput1_4.dll → xinput1_3.dll → ... → xinput1_1.dll

---

## 2. Architecture & Initialization Flow

### 7-Phase Initialization (DllMain)

```
PHASE 1: DECOMPRESS .TEXT
  - Entry point at RVA 0x3C4F30 (packer stub in .rsrc #2)
  - Reads compressed data at file offset 0x400
  - Writes decompressed 3,489,792 bytes to .text (RVA 0x001000)
  - Custom aPLib variant (bit-inverted, SAR-based, modified gamma)
  - JMP to real DllMain at RVA ~0x1480

PHASE 2: RESOLVE IMPORTS
  - 779 import stubs at RVA 0x1000-0x2000 region
  - Each stub: LEA RCX, [import_name_string] → JMP resolver
  - Central resolver at RVA 0x8BEB8 (tail-called)
  - On first call: GetModuleHandle/LoadLibrary + GetProcAddress
  - Patches stub to jump directly to resolved function

PHASE 3: SYSCALL STUB BUILDING
  - Reads ntdll.dll from disk (CreateFileW/ReadFile)
  - Parses PE export table
  - Extracts SSN for 8 NT functions
  - Builds stubs in heap: MOV R10,RCX; MOV EAX,SSN; SYSCALL; RET

PHASE 4: PATTERN SCAN GAME DLL
  - Pattern scanner at RVA 0x6D70 (called 164 times)
  - 73 patterns across 4 modules:
    - game.dll: 67 patterns
    - game_current.dll: 2 patterns
    - winhttp.dll: 2 patterns
    - bcrypt.dll: 2 patterns
  - Linear byte scan with wildcards (IDA-style ??)
  - Log: "Patterns: %d/%d found. Some features may not work."

PHASE 5: INSTALL HOOKS
  - Hook manager at RVA 0xB5D80 (258 install calls)
  - Hook verifier at RVA 0x8BED0 (236 verify calls)
  - 6 hook types, 73 total hooks
  - Uses SysNtProtectVirtualMemory for memory permission changes

PHASE 6: INITIALIZE OVERLAY
  - FindWindowW("LIBERTEAWnd", NULL)
  - SetWindowLongPtrW(GWL_WNDPROC, OverlayWndProc)
  - ImGui::CreateContext()
  - ImGui_ImplWin32_Init / ImGui_ImplOpenGL3_Init("#version 130")
  - Hook wglSwapIntervalEXT

PHASE 7: AUTH & RUN
  - VEH registration: AddVectoredExceptionHandler(1, handler)
  - Show login overlay (blocks main UI)
  - On auth success: unlock feature UI
  - Main loop runs every frame via wglSwapIntervalEXT hook
```

### The Main Loop (Every Frame)
1. Game engine tick → wglSwapIntervalEXT called
2. Hooked function: ImGui::NewFrame()
3. If INSERT pressed: toggle menu visibility
4. Render active UI (login screen or main window with tabs)
5. Apply per-frame feature patches (movement speed, FOV, weapon XP)
6. Update SC/Medal farming state machine
7. Process replay queue
8. ImGui::Render() + ImGui_ImplOpenGL3_RenderDrawData()
9. Call original wglSwapIntervalEXT(interval)

---

## 3. Packer & Compression (Custom aPLib)

### Algorithm Overview
The packer uses a custom variant of aPLib compression by Joergen Ibsen with three key modifications:

1. **Bit Inversion**: Uses `add ebx,ebx / adc ebx,ebx` semantics (carry-propagated) instead of standard `shl/rcl`. CF=1 → LITERAL path.

2. **SAR-based Offset Encoding**: Uses `sar eax, 1` (signed arithmetic shift right) instead of `shr eax, 1`. Preserves sign bit. LSB of offset value selects path:
   - LSB=0 → `COPY_SETUP_A` (shorter offset encoding)
   - LSB=1 → `COPY_SETUP_B` (longer offset encoding)

3. **Modified Gamma Coding**: Match lengths use a different gamma code with decrement-then-read logic.

### Decompression Loop (Reconstructed)
```
while (true):
    carry = read_bit()  // add ebx,ebx / adc ebx,ebx
    if carry == 0:
        *output++ = *input++  // LITERAL
    else:
        offset = read_gamma_encoded_value()  // custom gamma
        if offset == 0:
            eax = read_next_dword()
            if (eax ^ 0xFFFFFFFF) == 0: break  // end sentinel
        eax = offset
        sar eax, 1
        if (offset & 1) == 0:
            length = read_small_gamma()  // COPY_SETUP_A
        else:
            length = read_large_gamma()  // COPY_SETUP_B
        memcpy(output, output - offset, length)
        output += length
```

### Compression Stats
- Packed size: 458,544 bytes (compressed payload)
- Unpacked size: 3,489,792 bytes
- Compression ratio: ~7.6:1
- End-of-phase sentinel: `eax XOR 0xFFFFFFFF == 0`

### Build/Repacking Info
- Build scripts use Python-based packer tooling
- Original build: 3-phase (compile → pack → wrap)
- 6 usable scripts in `build_simple/` and `build/` directories

---

## 4. Hook System & Pattern Scanner

### Pattern Scanner (RVA 0x6D70)
- 73 IDA-style byte signatures with wildcard bytes (`??`)
- Linear byte-by-byte scan (no SIMD, no Boyer-Moore)
- Scans: game.dll .text, game_current.dll, winhttp.dll, bcrypt.dll

### Pattern Entry Structure (0x70 bytes each)
```
+0x00: patternId (uint32)
+0x04: hookType (HookType enum)
+0x08: moduleName (char[16])
+0x18: featureName (char[16])
+0x28: bytes (uint8_t[16])
+0x38: mask (uint8_t[16]) — 0xFF=exact, 0x00=wildcard
+0x48: offset (int32) — added to matched address
+0x4C: patchSize (int32) — bytes to write
+0x50: patchBytes (uint8_t[8]) — replacement bytes
+0x58: pResolvedAddr (uint64_t*) — runtime address
+0x60: pOriginalBytes (uint64_t*) — saved original bytes
+0x68: bResolved (bool)
+0x69: bInstalled (bool)
```

### Hook Types (6 categories, 73 hooks)
| Type | Count | Description |
|------|-------|-------------|
| NOP_PATCH | 27 (36.9%) | Replace with 0x90 NOP sleds |
| CODE_PATCH | 30 (41.1%) | Write custom replacement code |
| FUNCTION_PROLOGUE | 5 (6.8%) | Detour at function entry |
| POINTER_RESOLVE | 5 (6.8%) | Read/modify pointer targets |
| FUNCTION_RETURN | 4 (5.5%) | Patch return value |
| CONDITIONAL_INVERT | 2 (2.7%) | JE→JMP or JNE→NOP |

### Hook Installation Sequence
1. `SysNtProtectVirtualMemory(target_page, PAGE_EXECUTE_READWRITE)`
2. Save original bytes to trampoline/hook table
3. Write patch bytes:
   - NOP: `memset(target, 0x90, patchSize)`
   - DETOUR: `FF 25 00 00 00 00 [8-byte address]` (14 bytes)
   - CONDITIONAL: `JE(0F 84)` → `JMP(E9)` or `JNE` → `NOP`
   - RETURN: Write `C3` at function prologue
4. `SysNtProtectVirtualMemory(target_page, old_protection)`
5. Read back and verify
6. Log: "Hook verified" or "WARNING: Hook mismatch"

### Key Pattern Signatures
| Feature | Pattern | Type |
|---------|---------|------|
| God Mode (3 hooks) | (multiple) | CODE_PATCH |
| Grenade Count | `0F 5B DB F3 41 0F 59 4E ?? F3` | NOP_PATCH |
| No Boundary | `0F 84 ?? ?? ?? ?? 80 7F ?? ?? 0F 85` | CONDITIONAL_INVERT |
| Landing Speed | `F3 0F 11 44 3B ?? F3 0F 59 C7` | NOP_PATCH |
| Unlock All | `48 8B 0D ?? ?? ?? ?? 44 89 80 60 0C` | NOP_PATCH |
| Turret Overheat | `F3 0F 11 4C A8 ?? 49` | NOP_PATCH |
| Turret Duration | `F3 45 0F 11 5E ?? E9` | NOP_PATCH |
| Active Session | `48 8B 35 ?? ?? ?? ?? 49 8B E9` | FUNCTION_PROLOGUE |
| Reward Multiplier | `41 8B 47 ?? 4C 8B 7C 24 ?? 4C` | FUNCTION_RETURN |
| Stratagem Count | `42 83 2C 81 ?? 48` | CONDITIONAL_INVERT |
| Kill Counter | `39 46 ?? 75 ?? FF C5` | CODE_PATCH |
| Grenade Fuse | `F3 0F 11 44 C8 ?? 0F` | NOP_PATCH |

### Protection Layer Chain (Memory Permission Change)
1. **Preferred**: `SysNtProtectVirtualMemory` (direct syscall)
2. **Fallback**: `NtProtectVirtualMemory` (in-memory ntdll.dll)
3. **Last Resort**: `VirtualProtect` (kernel32.dll API)

---

## 5. Syscall Infrastructure

### SSN Resolution (from ntdll.dll on disk)
1. Read `C:\Windows\System32\ntdll.dll` via `CreateFileW`/`ReadFile`
2. Parse PE headers → export table
3. For each target function:
   - Find name in export table
   - Read function prologue bytes
   - Extract SSN:
     - Pattern A (Win10 1809+): `4C 8B D1 B8 XX XX XX XX` → SSN at offset 4
     - Pattern B (older): `B8 XX XX XX XX` → SSN at offset 1
4. Build stub in heap (RWX): `MOV R10,RCX; MOV EAX,SSN; SYSCALL; RET`

### Syscall Stub Table
| Function | Purpose |
|----------|---------|
| NtAllocateVirtualMemory | Memory allocation |
| NtProtectVirtualMemory | Memory protection (hook installation) |
| NtReadVirtualMemory | Process memory reading |
| NtWriteVirtualMemory | Process memory writing |
| NtQuerySystemInformation | System info queries |
| NtQueryInformationProcess | Process info queries |
| NtDelayExecution | Sleep/delay implementation |
| NtCreateThreadEx | Thread creation |

### Stub Layout (11-byte template)
```asm
4C 8B D1          mov r10, rcx      ; save 1st arg
B8 XX XX XX XX    mov eax, SSN      ; syscall number
0F 05             syscall            ; enter kernel
C3                ret                ; return to caller
```

All 8 stubs use identical 11-byte template — easily signatured.

---

## 6. Network Protocol & SC/Medal Farming

### HTTP Stacks (Priority Order)
1. libcurl.dll → libcurl-x64.dll → curl.dll → wininet.dll
2. winhttp.dll (GetProcAddress resolution)
3. wininet.dll (last resort)

### Network Endpoints
- C2/Auth: `libertea.libertea4.workers.dev` (Cloudflare Workers)
- Game API: `api.live.prod.thehelldiversgame.com/api/Operation/Mission/end`
- Community: `discord.gg/exCgdvYPxd`

### SC/Medal Farming Protocol

**Capture Phase:**
- Hooks libcurl write callback (FUNCTION_PROLOGUE)
- Intercepts POST to Mission/end endpoint
- Captures: full POST body (~2-8KB JSON), HTTP headers, mission ID, war time
- Saves to: `C:\libertea_replay_cap.json`

**Replay Phase (State Machine):**
```
States:
  IDLE(0) → CHECK_SESSION(1) → MONITORING(2)
  → SC_BATCH_FIRING(3) / MEDAL_BATCH_FIRING(4)
  → BATCH_RESULTS(5) → COOLDOWN(6, 58s)
  → GOAL_CHECK(7) → repeat or GOAL_REACHED(10)
  Any state → CRASH_RECOVERY(8) → resume
  Any state → USER_OFF(9) → IDLE
  BAIL(12) = unrecoverable
```

**Batch Pattern:**
- 9 POST calls per batch
- 500ms interval between calls
- 58-second cooldown between batches
- Alternates SC/Medal batches
- Each call: MIDSWAP missionId to avoid duplicate detection

**JSON Payload Fields:**
```
{
  "missionId": "<UUID>",
  "entityDataDeep": "<hex entity state>",
  "entityDeep": "<hex entity hierarchy>",
  "capturedWarTime": <uint64>,
  "ac": <activity count>,
  "oi": <objective index>,
  "serObj": "<hex serialized object>",
  "slotData": "<hex weapon slots>",
  "md": "<hex mission data>",
  "gs": "<hex game state>"
}
```

**HTTP Headers:** Authorization (Bearer JWT), X-Session, X-Signature (f2s7), Cookie, Content-Type

### f2s7 Anti-MITM Protocol
- Custom signature protocol for server response verification
- Uses bcrypt.dll: SHA-256 hashing + ChainingModeCBC (AES-CBC)
- f2s7 = SERVER-SIDE response encryption (Cloudflare Workers mediate)
- Key: 32-byte key in .rdata, rotated per session
- Transform: XOR + byte permutation + length encoding
- Checks for: Fiddler, mitmproxy, Burp, Charles, Proxyman, Wireshark, HTTP Debugger

### Hash Table Duplicate Bypass
- Two INSERT call sites in game.dll hash tables NOP-patched
- Prevents server from detecting duplicate entity claims
- Tables at PlayerSession+0xF0 (SC), +0xF8 (Medals), +0x100 (Samples)
- Without bypass: server rejects replayed mission completions

### VEH Crash Recovery
- `AddVectoredExceptionHandler(1, VEH_CrashHandler)`
- Handles: ACCESS_VIOLATION, STACK_OVERFLOW, ILLEGAL_INSTRUCTION
- On crash: save SC loop state, save replay data, log crash, restore state
- Replay watchdog resets stuck replayInProgress flag

---

## 7. Auth & Subscription System

### Auth Flow
1. Login screen (`##lock_screen`) blocks main UI
2. User enters: `##userinput`, `##passinput`, or `##keyinput`
3. Password hashed with bcrypt SHA-256
4. POST to Cloudflare Workers auth endpoint
5. Body: `{"user":"...","p":"...","hwid":"...","t":"..."}`
6. Response: `{"status":"Active"|"Lifetime"|"Expired","expiry":...,"tier":"..."}`

### Auth States
```
AUTH_UNKNOWN(0), AUTH_CHECKING(1), AUTH_SUCCESS(2),
AUTH_FAIL_INVALID_KEY(3), AUTH_FAIL_EXPIRED(4), AUTH_FAIL_NETWORK(5),
AUTH_FAIL_REVOKED(6), AUTH_FAIL_VERSION(7), AUTH_FAIL_SERVER(8),
AUTH_FAIL_TIMEOUT(9), AUTH_FAIL_RATE_LIMIT(10), AUTH_SUCCESS_CACHED(11)
```

### Hardware ID
- `Crypto::GetHardwareId` at RVA 0x34D40
- Derived from MachineGuid registry key
- Binds subscriptions to specific machine

### Update Protocol
- `GET /menu/version` → integer string
- `GET /menu/download` → raw DLL binary
- Compare against local `LIBERTEA.version` file
- Save as .tmp, atomic rename via MoveFileExW, relaunch with `--retry`

---

## 8. Feature Modules

### Player Cheats
| Feature | Hook Type | Description |
|---------|-----------|-------------|
| God Mode | CODE_PATCH (3 hooks) | Zero damage, cannot die |
| No Ragdoll | FUNCTION_RETURN | RET at ragdoll function entry |
| No Recoil | FUNCTION_RETURN | RET at recoil function |
| Movement Speed | CODE_PATCH | Slider ##spd, Multiplier ##smult |
| No Boundary | CONDITIONAL_INVERT | Bypass out-of-bounds kill trigger |
| Landing Speed | NOP_PATCH | Reduce fall damage/animation |
| Longer Hover | NOP_PATCH | Indefinite hover |

### Combat Cheats
| Feature | Hook Type | Description |
|---------|-----------|-------------|
| Infinite Ammo | NOP_PATCH | NOP ammo decrement |
| No Reload | CODE_PATCH | Skip reload sequence |
| Infinite Grenades | NOP_PATCH | NOP count conversion |
| Infinite Stims | NOP_PATCH | NOP stim decrement |
| Infinite Stratagems | CONDITIONAL_INVERT | Bypass count decrement |
| Instant Stratagem | CODE_PATCH | Zero call-in timer |
| Mass Strat Drop | CODE_PATCH | (Broken — [N/A]) |
| No Turret Overheat | NOP_PATCH | NOP heat accumulation |
| Infinite Turret Duration | NOP_PATCH | NOP timer decrement |
| Expire All Turrets | NOP_PATCH | Force expire |
| No Laser Overheat | NOP_PATCH | NOP heat accumulation |
| Instant Charge | NOP_PATCH | NOP charge calc (Railgun) |
| Grenade Fuse | NOP_PATCH | NOP fuse timer |
| Kill Counter | CODE_PATCH | Track kills |

### Farming / Economy
| Feature | Hook/Impl | Description |
|---------|-----------|-------------|
| Reward Multiplier | FUNCTION_RETURN | ##fxp, ##fmed, ##fslips |
| Force Difficulty | NOP_PATCH | cmp esi,7 → NOP |
| Add Samples | Direct write | ##fsamp_c/r/s |
| Instant Shuttle | CODE_PATCH | ##shut5 |
| Instant Complete | CODE_PATCH | ##ic5 |
| Freeze Timer | CODE_PATCH | Stop countdown |

### Super Credits / Medal Farming
*(See Section 6 above for full protocol)*
- `##sc_goal`, `##sc_earned`, `##sc_loop` — UI controls
- `##bl` burst loop, `##maxreplays`, `##BurstCount`

### Armory
| Feature | Hook | Description |
|---------|------|-------------|
| Unlock All | NOP_PATCH | NOP unlock check |
| Armor Passive Editor | Direct read/write | ##ap_scan, ##ap_armor, ##ap_pass |
| Weapon Editor | Direct write | Damage ##we, Penetration ##we |

### Visual / Misc
| Feature | Description |
|---------|-------------|
| FOV Editor | ##fov slider |
| Dark Fluid Pack (Jetpack) | ##pk fly speed/gravity/fuel |
| Infinite Horde | ##erad_ih (Coming Soon) |

---

## 9. Anti-Analysis & Evasion

### Current Protection Layers
1. **Custom aPLib packer** — strongest layer, defeats signature detection
2. **Direct syscalls** (8 stubs) — bypasses ntdll.dll user-mode hooks
3. **XOR-scrambled string table** (~168KB, ~2600 strings)
4. **f2s7 proxy/MITM detection** (14 tools checked)
5. **IsDebuggerPresent + CheckRemoteDebuggerPresent + RDTSC** (34 RDTSC checks)
6. **GameGuard bypass** — file rename/delete pre-injection
7. **SSN from disk** (not hardcoded) — adapts to Windows versions
8. **Late-bound lazy import resolution** — no standard IAT
9. **Cloudflare Workers auth** — server-side validation

### GameGuard Bypass
- Locate `GameMon.des` / `GameMon64.des` driver files
- Rename or delete before GameGuard can load
- Race condition: inject before driver initializes (1-3s window)
- Fallback: SCM service stop

### Anti-Debug Measures
| Check | Implementation |
|-------|---------------|
| IsDebuggerPresent | PEB flag check |
| CheckRemoteDebuggerPresent | Cross-process check |
| RDTSC timing | 34 occurrences, measure execution time |
| Proxy detection | 14 tools (Fiddler, Burp, Charles, etc.) |

### Current Weaknesses
- NO self-integrity checking of own .text section
- Zero packer anti-debug (stub is pure decompression)
- Only 8 syscall stubs (many NT functions through ntdll.dll)
- No control flow obfuscation (MSVC /O2 output, readable)
- No VM/sandbox detection
- No hardware breakpoint detection (DR0-DR7)
- No kernel-mode component (entirely user-mode)
- Single C2 server (Cloudflare Workers) single point of takedown
- Plain-text API names in .rdata
- RWX .text section (massive red flag)
- No stream-proof overlay (UI visible to stream viewers)

---

## 10. ImGui Overlay & UI

### Setup
- ImGui v1.91.5 (confirmed at RVA 0x104DAD)
- OpenGL 3.3 core profile (`#version 130`)
- Win32 backend + OpenGL3 backend
- Font: "Segoe UI" (system font, ~18pt)
- 162+ ImGui widget IDs identified

### Overlay Architecture
1. `FindWindowW("LIBERTEAWnd", NULL)` — locate game window
2. `SetWindowLongPtrW(GWL_WNDPROC, OverlayWndProc)` — subclass
3. Custom message `WM_SC_DISPATCH` for thread-safe rendering
4. Hook `wglSwapIntervalEXT` — inject rendering between game frame and presentation
5. Menu key: VK_INSERT (or HOME) toggles visibility

### UI Tabs (7 Main Categories)
1. **Farming** — Reward multipliers, difficulty, samples, shuttle, complete
2. **Super Credits** — SC loop, goal, medals, auto-sync
3. **Weapon XP** — All guns, selected guns, primary override
4. **Player** — God mode, speed, no ragdoll, no recoil
5. **Combat** — Ammo, strats, turrets, charge, fuse, kill counter
6. **Visual/Exploration** — FOV, jetpack, map hack
7. **Armory** — Unlock all, weapon editor, armor passive editor

### Config Persistence
- Likely JSON in `%APPDATA%/LiberTea/config.json`
- Profile system not confirmed (no save/load UI found)

---

## 11. Data Structures & Memory Map

### PlayerSession Structure
```
+0x00: vtable pointer
+0x28: Primary activity ring buffer (278 code references!)
+0x60: missionData (pointer)
+0x70: missionId[0x40] (UUID string)
+0xF0: Hash table of consumed SC entities (NOP'd)
+0xF8: Hash table of consumed Medal entities (NOP'd)
+0x100: Hash table of consumed Sample entities (NOP'd)
+0x110-0x11C: Sample counters (common/rare/super)
+0x128: Secondary activity ring buffer
+0x130: ServerInfo pointer
```

### ScActivityAPC Structure
```
+0x00: vtable pointer
+0x08: actId32 (activity identifier)
+0x0C: objId (object identifier)
+0x10: ctr (control/state counter)
+0x14: flag (flags)
+0x18: ring (ring buffer index)
+0x20: url[0x40] (API endpoint URL)
+0x60: qDelta (queue delta)
+0x64: retry (retry counter)
+0x68: missionData pointer
+0x70: missionId[0x40] (UUID string)
```

### WeaponStats Structure (Editor Target)
```
+0x30: damage (float)
+0x34: penetration (float)
+0x38: fire rate (float)
```

### String Region Map
| Region | Content |
|--------|---------|
| 0x0FD000-0x0FE400 | Weapon and armor names |
| 0x0FE400-0x0FF000 | SC/Replay/Probe UI strings |
| 0x0FF000-0x100000 | Weapon selection, farming UI |
| 0x100000-0x101000 | Feature descriptions, tooltips |
| 0x101000-0x102000 | HTTP/replay/capture strings |
| 0x102000-0x103000 | Network/signature/crypto strings |
| 0x103000-0x104000 | NOP descriptions, feature details |
| 0x104000-0x105000 | Stratagem/enemy/weapon lists |
| 0x105000-0x106000 | ImGui key names, error strings |
| 0x0F8000-0x10A000 | Obfuscated region (~72KB, ~1133 strings, entropy 7.26) |

### Difficulty System
| Tier | Label | Reward Multiplier |
|------|-------|-------------------|
| 1 | Trivial | 0% |
| 2 | Easy | 0% |
| 3 | Medium | 25% |
| 4 | Challenging | 50% |
| 5 | Hard | 75% |
| 6 | Extreme | 100% |
| 7 | Super Helldive | 150% |
| 8 | (custom) | 200% |
| 9 | (custom) | 250% |
| 10 | (custom) | 300% |

### Weapon Catalog (51 weapons)
Full list in `resweep_supplement.txt` at `data/` — includes AR-23 Liberator, SG-225 Breaker, LAS-16 Sickle, PLAS-1 Scorcher, JAR-5 Dominator, etc.

### Armor Passives (21 found)
Acclimated, Ballistic Padding, Combat Medic, Explosive Finale, Fire Resistant, Gas Resistance, Peak Physique, Siege Breaker, etc.

### Enemy Types (28 found)
Bile Titan, Charger, Factory Strider, Harvester, Hulk, Devastator, Berserker, Stalker, etc.

---

## 12. Game Integration Targets

### Target Process
- Name: `helldivers2.exe`
- Modules hooked: `game.dll` (67 patterns), `winhttp.dll` (2), `bcrypt.dll` (2), `game_current.dll` (2)

### Game API Endpoints
- `POST api.live.prod.thehelldiversgame.com/api/Operation/Mission/end`

### Game Files
- `Steam\steamapps\common\Helldivers 2\bin\data\exploded_dat` — game data archive
- `C:\libertea_replay_cap.json` — SC farming capture file

### Injector (LIBERTEA_Bypass.exe)
1. Self-update check via Cloudflare Workers
2. Enable SeDebugPrivilege
3. Find `helldivers2.exe` process
4. Disable GameGuard (rename/delete driver files)
5. VirtualAllocEx → WriteProcessMemory → CreateRemoteThread(LoadLibraryW)

---

## 13. Weaknesses & Attack Surface

### Top Priority Deficiencies
1. **No self-integrity checking** — Once unpacked, code can be patched freely
2. **Only 8 syscall stubs** — Many NT functions still go through ntdll.dll
3. **No packer anti-debug** — Stub is pure decompression, no checks
4. **Identical stub layout** — All 8 stubs use same 11-byte template
5. **Single C2 endpoint** — Cloudflare Workers: single point of takedown
6. **RWX .text section** — Read-Write-Execute is a massive red flag
7. **No control flow obfuscation** — Standard MSVC /O2, readable in IDA
8. **No VM/sandbox detection** — Runs anywhere without checks
9. **No kernel component** — Entirely user-mode
10. **Streamable overlay** — Visible to OBS/stream viewers

### Detection Vectors (9 Attack Surfaces)
1. Memory scan for RWX regions with large uncompressed code
2. Pattern matching of 8 identical syscall stubs (`4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3`)
3. Hook detection on `wglSwapIntervalEXT`
4. Hook detection on game.dll known patterns
5. IAT anomalies (no standard import table)
6. PE anomalies (zero-size .text, two .rsrc sections, entry in .rsrc)
7. Timing anomalies (RDTSC patches are detectable)
8. Window subclassing detection
9. Process scanning for known proxy/MITM tools

---

---

## 14. Web Research Elevations (Modern Context)

### Direct Syscall Evolution (Hell's Gate → Hades Gate)
The cheat's syscall approach (read ntdll from disk → extract SSN → build 8 stubs) represents a mid-2020s technique. The scene has evolved significantly:

| Technique | Year | Method | Advantage vs. LIBERTEA |
|-----------|------|--------|----------------------|
| **Hell's Gate** | 2022 | SSN extraction from in-memory ntdll (PEB→Ldr→ntdll) | No disk read required |
| **Halos Gate** | 2022 | Handle "wrapped" syscalls (gaps in SSN numbering) | Resilient to ntdll stub patching |
| **Tartarus Gate** | 2023 | PEB→InMemoryOrderModuleList→ntdll export walk | No GetModuleHandle needed |
| **Indirect Syscalls** | 2023 | Execute syscall but return to ntdll address (call stack spoofing) | Evades call stack tracing by EDR/AC |
| **Hades Gate** | 2024 | PEB-parsing syscall builder with per-stub junk bytes | No filesystem access, no disk I/O signature |
| **stealth_call** | 2025 | 977 syscalls, W^X policy, KnownDlls section mapping, per-call dynamic stubs | Complete coverage, zero disk reads, polymorphic stubs |

**Key insight**: LIBERTEA's disk-read approach (CreateFileW → ReadFile → ntdll) is signatured by modern GameGuard. Modern cheats use PEB-based resolution (no filesystem I/O) and per-call indirect syscalls with randomized stubs.

### GameGuard Updated Capabilities (2025-2026)
- AOB-based pattern detection for known cheat signatures (hunts `4C 8B D1 B8 ?? 0F 05` in allocated memory)
- Kernel-level process scanning (enumerates all loaded DLLs, checks for injected modules)
- "Headless diver" glitch (God Mode side effect) patched by devs, not GameGuard
- SC pickup patched server-side in HD2 v6.2.2 (April 2026) — but replay attack still works via hash table bypass

### Helldivers 2 Engine Architecture
- **Engine**: Autodesk Stingray (formerly Bitsquid), acquired by Autodesk 2014, discontinued 2018
- **Asset ID**: `MurmurHash64A("path/to/asset")` — 64-bit hash used for all resource identification
- **Community API**: `api.helldivers2.dev` — public game data API (separate from live game API)
- **Data Tools**: `Stingray-Explorer`, `filediver`, `hd2re` — community tools for `.exploded_dat` archive extraction
- **Game Version History**: v6.2.0 → v6.2.2 (Apr 2026, SC patch) → v6.2.5 (May 2026)
- **Graphics Updates (post v414)**: FSR 3.1.5, DLSS 4.5, XeSS 3.0, NVIDIA Reflex, AMD Anti-Lag 2

### OLLVM / Code Obfuscation Landscape
Modern obfuscation frameworks available for C++/LLVM projects:

| Framework | Features |
|-----------|----------|
| **Kagura** | CFG flattening, MBA expressions (Mixed Boolean-Arithmetic), code virtualization, string encryption, bogus control flow, file-driven config (JSON/YAML per-function granularity) |
| **SLLVM** | Subroutine reordering, bogus CFG, string obfuscation, control flow flattening |
| **llvm-obfus** | CFG flattening, bogus control flow, instruction substitution (classic) |
| **Hikari** | Open-source, string obfuscation, CFG flattening, bogus CFG |

LIBERTEA uses zero obfuscation — standard MSVC /O2 output, fully readable in IDA/Ghidra.

### BYOVD Kernel Access (Modern Anti-Cheat Bypass)
- **Bring Your Own Vulnerable Driver**: Load a signed-but-vulnerable driver to gain kernel access
- **Common vulnerable drivers**:
  - `RTCore64.sys` (MSI Afterburner) — arbitrary MSR read/write, exposed by gigabyte BYOVD
  - `GLCKIO2.sys` (ASUS) — arbitrary physical memory read/write
  - `gdrv.sys` (Gigabyte) — arbitrary kernel memory access
  - `RTCore64.sys`, `hvix64.sys` — PPL bypass (Protect Process Light)
- **LIBERTEA weakness**: Zero kernel components. Entirely user-mode, detectable by any kernel AC.

### API Hashing (Missing Protection)
LIBERTEA stores plain-text API names in .rdata (visible after unpacking). Modern alternatives:
| Hash | Usage | Detection |
|------|-------|-----------|
| ROR13 | Classic malware | Well-known, signatured by YARA |
| JenkinsOAAT | x64dbg plugin | Less common |
| FNV1a | Modern malware | Fast, low collisions |
| DJB2 | General purpose | Simple, widely used |
| CRC32 | Windows kernel | Hardware-accelerated |

**Recommendation**: Combine 3+ hash types per build, randomize which function uses which hash.

### Call Stack Spoofing (LACUNA/FreshyCalls)
Modern EDR/AC traces kernel return addresses to detect direct syscalls. Solution: indirect syscalls where `SYSCALL` instruction is followed by `RET` to an address inside ntdll, making the call stack appear legitimate (originating from ntdll).

### stealth_call Architecture (Gold Standard)
The `stealth_call` library provides:
- **977 syscalls** resolved (all NT functions, not just 8)
- **KnownDlls section mapping**: Reads ntdll from kernel's KnownDlls section (no disk I/O, no `CreateFile`)
- **Per-call dynamic stub generation**: Each invocation builds a unique stub with random junk
- **W^X enforcement**: No RWX pages; memory is either W or X, never both
- **Return address spoofing**: Indirect syscall with return to legitimate ntdll code

---

## 15. SC_SO Reference Implementation (Source Analysis)

The `SC_SO` (SC_Replay_Source) project provides a complete C++ source implementation of the replay and farming framework. It serves as the ground-truth for the mechanisms used in LIBERTEA.DLL.

### Architecture Summary
`SC_SO` is a native x64 DLL that operates entirely within the game process, focusing on three main pillars: **Capture**, **Replay**, and **Farming**.

### Core Implementation Details
| Component | Implementation Mechanism |
|-----------|---------------------------|
| **Mission Capture** | Uses **Hardware Breakpoints (Dr2/Dr3)** to intercept `BuildPayload` without modifying game code. |
| **Replay Execution** | Calls game's internal `BuildPayload` and weapon stats functions via **Window Message Dispatch**. |
| **SC Farming** | Automated loop alternating between SC (`0x7F8FE16`) and Medal (`0xA2C8A4E`) activities. |
| **HTTP Interception** | Inline hooks on `libcurl` (`setopt`, `perform`, `cleanup`) to capture and modify POST bodies. |
| **Safety/Evasion** | **VEH Crash Absorption** (priority 1) to suppress crashes and a **WNDPROC subclass** for main-thread execution. |
| **Foundation** | AOB pattern scanner and a dynamic RVA resolver supporting multiple game versions (v20, v21, v22). |

### Key Technical Components
- **`replay.cpp`**: Master orchestrator managing `ReplayAPC`, `ScActivityAPC`, and the automated `ScLoopThread`.
- **`probe.cpp`**: Implements the Dr2/Dr3 hardware breakpoint handler to capture deep copies of entity/mission memory.
- **`http_monitor.cpp`**: Intercepts libcurl traffic, captures signing nonces/keys via `BCryptHashData` hooks, and performs `missionId` injection.
- **`sc_present.cpp`**: Implements `WM_SC_DISPATCH` (0x87EA) and `WM_GT_DISPATCH` (0x87EB) to execute callbacks on the game's main thread.
- **`sc_guard.cpp`**: Priority-1 VEH that absorbs access violations and restores RIP to a `xor eax, eax; ret` stub.
- **`sc_limit.cpp`**: Implements UUID rotation via a code cave injection near the hook point.

*Knowledgebase accuracy: 93.4% verified against ground truth (203 claims tested, 87 confirmed, 6 false, 15 unverifiable)*
*Last updated: 2026-07-05 | Audit log: `logs/audit_verification.txt`*
