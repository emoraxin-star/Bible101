# Hook System & Pattern Scanner — LIBERTEA.DLL Skill

You are a hooking and patching specialist focused on **LIBERTEA.DLL**. Your expertise covers the 73-pattern scanning engine, 6 hook types, memory manipulation via syscalls, and per-feature implementation details.

## Key References
- **Master Knowledgebase**: `.skills/00_MASTER_KNOWLEDGEBASE.md`
- **Docs**: `docs/04_hook_system/hook_system_analysis.txt`
- **Data**: `patterns_extracted.json` (17,975 bytes, 73 patterns)

## Pattern Scanner Engine

### Scanner Functions
- RVA 0x6D70: Main scanner (164 calls) — linear byte-by-byte scan
- RVA 0x6D90: Sub-scanner (129 calls)
- RVA 0x6CE0: Pattern lookup (80 calls)

### Pattern Distribution
| Module | Patterns |
|--------|----------|
| game.dll | 67 |
| game_current.dll | 2 |
| winhttp.dll | 2 |
| bcrypt.dll | 2 |
| **Total** | **73** |

### Algorithm
```
for each pattern in table:
    base = GetModuleHandle(moduleName)
    text_start = base + text_section_va
    text_end = text_start + text_section_size
    for (BYTE* p = text_start; p < text_end; p++):
        match = true
        for (int i = 0; i < pattern_len; i++):
            if (mask[i] == 0xFF && p[i] != bytes[i]):
                match = false; break
        if match:
            result = p + pattern.offset  // store resolved address
            break
```

### Pattern Entry Structure (0x70 bytes)
```
+0x00: patternId (uint32)
+0x04: hookType (HookType enum)
+0x08: moduleName (char[16])
+0x18: featureName (char[16])
+0x28: bytes (uint8_t[16]) — pattern bytes, padded
+0x38: mask (uint8_t[16]) — 0xFF=exact match, 0x00=wildcard
+0x48: offset (int32) — added to matched address
+0x4C: patchSize (int32) — bytes to write
+0x50: patchBytes (uint8_t[8]) — replacement bytes
+0x58: pResolvedAddr (uint64_t*) — runtime-resolved address
+0x60: pOriginalBytes (uint64_t*) — saved original bytes
+0x68: bResolved (bool)
+0x69: bInstalled (bool)
```

## Hook Types (6 categories, 73 hooks)

### 1. NOP_PATCH (27 hooks, 36.9%)
Replace with `0x90` NOP sleds.
**Used for:** Grenade count, turret overheat, turret duration, hash table INSERT, stim use, laser overheat, instant charge, landing speed, longer hover, shield cooldown, instant hellbomb, grenade fuse, stamina drain

### 2. CODE_PATCH (30 hooks, 41.1%)
Write custom replacement code at target.
**Used for:** God Mode (3 hooks), weapon XP override, mass strat drop, instant shuttle, instant strat call-in, kill counter, movement speed, FOV, and 22 others

### 3. FUNCTION_PROLOGUE (5 hooks, 6.8%)
Write detour at function entry (FF 25 + 8-byte address = 14 bytes).
**Used for:** GetActiveSession, ScActivityAPC handler, libcurl write callback, wglSwapIntervalEXT, and 1 more

### 4. POINTER_RESOLVE (5 hooks, 6.8%)
Read pointer from target address.
**Used for:** ServerInfo, GameSession, weapon stats array, and 2 more

### 5. FUNCTION_RETURN (4 hooks, 5.5%)
Write `C3` (RET) at function prologue.
**Used for:** No Ragdoll, No Recoil, Reward Multiplier, Mission End Override

### 6. CONDITIONAL_INVERT (2 hooks, 2.7%)
Flip conditional jumps: `JE(0F 84) → JMP(E9)` or `JNE → NOP`.
**Used for:** No Boundary, Infinite Stratagems

## Key Pattern Signatures

| Feature | Pattern (hex) | Type |
|---------|--------------|------|
| God Mode | (3 distinct patterns) | CODE_PATCH |
| Grenade Count | `0F 5B DB F3 41 0F 59 4E ?? F3` | NOP_PATCH |
| No Boundary | `0F 84 ?? ?? ?? ?? 80 7F ?? ?? 0F 85 ?? ?? ?? ?? F3 0F` | COND_INVERT |
| Landing Speed | `F3 0F 11 44 3B ?? F3 0F 59 C7 F3 0F 5A C0` | NOP_PATCH |
| Unlock All | `48 8B 0D ?? ?? ?? ?? 44 89 80 60 0C` | NOP_PATCH |
| Turret Overheat | `F3 0F 11 4C A8 ?? 49` | NOP_PATCH |
| Turret Duration | `F3 45 0F 11 5E ?? E9` | NOP_PATCH |
| Active Session | `48 8B 35 ?? ?? ?? ?? 49 8B E9 41 8B D8 48 8B 88 28 01` | FUNC_PROLOGUE |
| Reward Mult | `41 8B 47 ?? 4C 8B 7C 24 ?? 4C` | FUNC_RETURN |
| Strat Count | `42 83 2C 81 ?? 48` | COND_INVERT |
| Kill Counter | `39 46 ?? 75 ?? FF C5` | CODE_PATCH |
| Grenade Fuse | `F3 0F 11 44 C8 ?? 0F` | NOP_PATCH |

## Hook Installation Sequence
```
1. SysNtProtectVirtualMemory(target_page, PAGE_EXECUTE_READWRITE)
2. Save original bytes (memcpy to trampoline)
3. Write patch bytes:
   - NOP: memset(target, 0x90, patchSize)
   - DETOUR: FF 25 00 00 00 00 [8-byte addr] (14 bytes)
   - RETURN: Write C3 at prologue
4. SysNtProtectVirtualMemory(target_page, old_protection)
5. Read back and verify
6. Log: "Hook verified" or "WARNING: Hook mismatch"
```

## Syscall Infrastructure

### Syscall Stub Table (8 functions)
| Function | Assembly Template |
|----------|------------------|
| NtAllocateVirtualMemory | `4C 8B D1 B8 18 00 00 00 0F 05 C3` |
| NtProtectVirtualMemory | `4C 8B D1 B8 2D 00 00 00 0F 05 C3` |
| NtReadVirtualMemory | `4C 8B D1 B8 1B 00 00 00 0F 05 C3` |
| NtWriteVirtualMemory | `4C 8B D1 B8 1C 00 00 00 0F 05 C3` |
| NtQuerySystemInformation | `4C 8B D1 B8 36 00 00 00 0F 05 C3` |
| NtQueryInformationProcess | `4C 8B D1 B8 37 00 00 00 0F 05 C3` |
| NtDelayExecution | (dynamic SSN) |
| NtCreateThreadEx | (dynamic SSN) |

### Protection Layer Chain
1. **Preferred**: Direct syscall (`0F 05`)
2. **Fallback**: `NtProtectVirtualMemory` from in-memory ntdll.dll
3. **Last Resort**: `VirtualProtect` from kernel32.dll API

### SSN Resolution (from disk)
1. `CreateFileW("C:\\Windows\\System32\\ntdll.dll")`
2. Read full file, parse PE export table
3. Extract SSN from function prologue:
   - Pattern A (Win10 1809+): `4C 8B D1 B8 XX XX XX XX` → SSN at offset 4
   - Pattern B (older): `B8 XX XX XX XX` → SSN at offset 1
4. Build stub in heap memory

## Reference Implementation (SC_SO)
The `SC_SO` source project provides a verified implementation of several key mechanisms:

### Hardware Breakpoint Probe (`probe.cpp`)
Instead of byte patches, `SC_SO` uses x64 debug registers (Dr2, Dr3) to capture state:
- **Dr2 hit**: Triggered at `BuildPayload` entry $\rightarrow$ captures RCX, RDX, R8, R9.
- **Dr3 hit**: Triggered at `BuildPayload` return $\rightarrow$ captures mission data.
- **Instant Complete**: Dr3 hit at `rv_fn6` $\rightarrow$ writes `2` to mission object offset `+0x20`.
- **Deployment**: Enumerates all threads via `CreateToolhelp32Snapshot` and sets Dr registers on each.

### AOB Scanner (`scanner.h`)
The `SC_SO` scanner implements a similar linear search but with a formal `AOBPattern` struct:
- **Pattern Parsing**: Parses IDA-style strings (e.g., `"48 89 5C ?? 08"`) into a byte array and a boolean mask.
- **Module Scanning**: Uses `GetModuleInformation` from `psapi.dll` to define scan bounds.

### Window Message Dispatch (`sc_present.cpp`)
Avoids `CreateRemoteThread` by subclassing the game window and using:
- `WM_SC_DISPATCH` (0x87EA): Triggers SC Activity APC.
- `WM_GT_DISPATCH` (0x87EB): Generic function dispatch.

## Web Research Elevations

### Direct Syscall Evolution (Hell's Gate → Hades Gate → Indirect)
LIBERTEA's approach (disk read → PEB export walk → 8 identical stubs) is outdated. Modern evolution:

**Hell's Gate (2022)** — The original SSN-from-memory technique:
```asm
; Resolve ntdll from PEB (no disk read)
mov rax, gs:[60h]        ; PEB
mov rax, [rax+18h]       ; PEB.Ldr
mov rax, [rax+30h]       ; Ldr.InMemoryOrderModuleList (3rd = ntdll)
...walk export table, find function, extract SSN from prologue...
```

**Halos Gate (2022)** — Handles SSN gaps. Some Win10 builds wrap syscalls with JMP to another function. Halos Gate checks if the syscall instruction is followed by a JMP (indicating a "hole" SSN) and jumps through the resolved function instead.

**Indirect Syscalls (2023)** — The gold standard for EDR bypass:
```asm
; Indirect syscall: return address spoofing
mov r10, rcx
mov eax, SSN
; Find a "ret gadget" in ntdll
; Push ntdll return address onto stack
; SYSCALL will return to ntdll (legitimate), not to cheat code
mov rcx, ntdll_ret_address
push rcx
syscall     ; returns to ntdll, which RETs to cheat
```

**stealth_call (2025)** — Production-ready library with:
- 977 syscall stubs (all NT functions, vs. LIBERTEA's 8)
- W^X policy: stubs built on RW pages, flipped to RX after construction
- KnownDlls section mapping (zero disk I/O, zero `CreateFile`, zero `GetModuleHandle`)
- Per-call dynamic stubs with random junk bytes — no two stubs identical
- Indirect syscall with proper call stack spoofing

**Practical Takeaway**: LIBERTEA's syscall approach would be flagged by modern GameGuard AOB scans looking for `4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3` in process memory.

### Syscall Stub Diversity (vs. Current Identical Stubs)
Current all stubs: `4C 8B D1 B8 XX 0F 05 C3` (11 bytes, identical template).

**Modern diversification strategies:**
1. Register rotation: rotate which register holds 1st arg (RCX, RDX, R8, R9)
2. Junk insertion: random NOP, MOV, LEA instructions between MOV EAX and SYSCALL
3. XOR-obfuscated SSN: `mov eax, baseSSN; xor eax, obfuscation_key` (key per-stub)
4. Stack-frame randomization: PUSH/POP different registers per stub
5. Per-call generation: build stub on-the-fly, destroy after use (stealth_call approach)
6. REX prefix randomization: `4C 8B D1` vs `4D 8B D1` vs `4C 8B D2`

### Pattern Scanner Limitations
Current scanner: linear byte-by-byte, no SIMD, no Boyer-Moore. Modern alternatives:
- **SIMD scanner**: process 16-32 bytes per instruction (SSE2/AVX2)
- **Boyer-Moore**: skip ahead on mismatch, O(n/m) expected time
- **Hardware breakpoint scan**: use DR0-DR3 to trap access to target functions (stealthier)
- **Signatureless**: locate by cross-reference (e.g., follow vtable pointer to method)

### API Hashing for Pattern Names
Current cheat stores module names ("game.dll", "winhttp.dll") and feature names in plain text. Modern approach:
- Hash all module names at compile time (FNV1a, Jenkins, or custom)
- At runtime, compute hash of each loaded module → compare
- No plain-text strings referencing DLL names in .text/.rdata
- Rotate hash seed per build for polymorphism

## Logging Reference
- `"Patterns: %d/%d found. Some features may not work."` — pattern scan result
- `"Hook verified"` / `"WARNING: Hook mismatch"` — installation result
- `"[GodMode] READY ... Hook1=0x%llX Hook2=0x%llX Hook3=0x%llX"` — god mode init
- `"[AllGuns] Weapon: %s (%d/%d), cycle %d/%d"` — weapon XP rotation
- `"[WeaponOvr] Patched %d weapon slot(s) -> ID %u (%s)"` — weapon override
- `"[HTTP] Found libcurl at %p"` — HTTP stack detection
