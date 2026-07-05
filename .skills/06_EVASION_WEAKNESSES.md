# Anti-Analysis & Evasion — LIBERTEA.DLL Skill

You are an anti-analysis and detection-evasion specialist focused on **LIBERTEA.DLL**. Your expertise covers the cheat's current protection layers, known weaknesses, detection vectors, and improvement strategies.

## Key References
- **Master Knowledgebase**: `.skills/00_MASTER_KNOWLEDGEBASE.md`
- **Brainstorm**: `BRAINSTORM_IMPROVEMENTS.txt` (comprehensive improvement analysis)
- **Guess**: `13%_Guess.txt` (confidence-rated findings)
- **Logs**: `logs/agentI_syscall_infra.txt`, `logs/hyper5_anti_analysis.txt`

## Current Protection Layers (Defense-in-Depth)

### Layer 1: Custom aPLib Packer (Stealth)
- Modified aPLib variant with bit inversion, SAR-based offsets, custom gamma coding
- Zero-size .text on disk (filled at runtime)
- Entry point in .rsrc section (not .text)
- Section names corrupted to garbage bytes
- Two .rsrc sections (PE anomaly)
- **Strength**: Defeats static signature detection
- **Weakness**: Zero integrity checking — once unpacked, all code visible

### Layer 2: Direct Syscalls (8 stubs)
- Bypasses ntdll.dll user-mode hooks
- SSN resolved dynamically from disk
- **Strength**: Avoids NtProtectVirtualMemory monitoring
- **Weakness**: Only 8 functions stubbed; many NT calls through ntdll
- **Weakness**: All 8 stubs use identical 11-byte template — easy to signature

### Layer 3: XOR-Scrambled Strings
- ~2600 strings in ~168KB .rdata obfuscated region
- Not all strings obfuscated (API names visible in .rdata)
- **Weakness**: Single XOR key pattern; centralized deobfuscation function

### Layer 4: f2s7 Anti-MITM
- Custom signature protocol for server response verification
- Detects 14 proxy/MITM tools
- HMAC-SHA256 + AES-CBC
- **Weakness**: Single C2 server = single point of monitoring/takedown

### Layer 5: Anti-Debug
| Check | Implementation | Bypass Difficulty |
|-------|---------------|-------------------|
| IsDebuggerPresent | PEB flag | Trivial (NOP/Bypass) |
| CheckRemoteDebuggerPresent | Cross-process | Trivial |
| RDTSC (34x) | Timing | Easy (plugin) |

### Layer 6: GameGuard Bypass
- Rename/delete GameMon64.des before driver loads
- Race condition: inject before driver initializes (1-3s window)
- **Strength**: Works without kernel access
- **Weakness**: Fragile — relies on file rename before driver loads

### Layer 7: HWID Fingerprinting
- `Crypto::GetHardwareId` at RVA 0x34D40
- Derived from MachineGuid registry key
- Binds subscriptions to specific hardware

### Layer 8: Encrypted C2 Traffic
- HTTPS + f2s7 custom body encryption
- bcrypt SHA-256 + AES-CBC

### Reference Implementation Evasion (SC_SO)
The `SC_SO` source project demonstrates several high-efficiency evasion patterns:
- **Window Message Dispatch**: Instead of `CreateRemoteThread` or `QueueUserAPC`, it uses `WM_SC_DISPATCH` (0x87EA) and `WM_GT_DISPATCH` (0x87EB) via window subclassing to execute code on the game's main thread.
- **HW Breakpoint Probe**: Uses Dr2/Dr3 registers to capture mission data, avoiding all byte patches on critical code paths.
- **Crash Absorption**: A priority-1 VEH that catches access violations and restores RIP to a `xor eax, eax; ret` stub, preventing crash telemetry.
- **Surgical Memory Writes**: Uses a code cave injection via `AllocNear()` to rotate UUIDs without patching main function prologues.

## Critical Weaknesses (Priority Ordered)

### #1: NO Self-Integrity Checking (CRITICAL)
- Once unpacked, code can be freely patched/modified
- No checksumming of .text or .rdata sections
- Auth check, SSN resolver, hook installer — ALL unpatchable
- **Impact**: Analyst can NOP auth → free access; NOP pattern scanner → feed fake addresses
- **Fix**: 5-layer integrity system (CRC32C, code block hashing, IAT verification, stack integrity, server-side challenge)

### #2: Incomplete Syscall Coverage
- Only 8 NT functions have direct stubs
- NtOpenProcess, NtClose, NtCreateFile, etc. still go through ntdll.dll
- All 8 stubs use SAME 11-byte template: `4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3`
- **Impact**: Anti-cheat can hook unsyscalled functions; pattern-scan for stub signature

### #3: RWX .text Section
- `.text` characteristics = `RXW` (Read-Execute-Write)
- Massive red flag for any memory scanner
- Normal memory: code sections are RX only

### #4: Single C2 Server
- Cloudflare Workers endpoint: `libertea.libertea4.workers.dev`
- Single trademark/DMCA takedown = entire cheat goes offline
- **Fix**: Multi-layer C2 (Tor .onion + IPFS + VPS mesh + DGA + Blockchain)

### #5: Readable Code (No Obfuscation)
- Standard MSVC /O2 optimization output
- No control flow flattening
- Readable in IDA/Ghidra after unpacking
- Function names, calling conventions visible

### #6: No VM/Sandbox Detection
- Runs in any environment without checks
- Analysts can use VMs freely
- No timing, registry, or hardware checks

### #7: No Hardware Breakpoint Detection
- DR0-DR4 registers unchecked
- Analysts can set breakpoints without detection
- No GetThreadContext(DEBUG_REGISTERS) calls

### #8: Streamable Overlay
- ImGui overlay renders directly on game window
- Visible to OBS/XSplit stream capture
- Streamers can accidentally reveal cheat UI
- **Fix**: Stream-proof mode with anti-capture

### #9: Standard DLL Injection
- Uses CreateRemoteThread → LoadLibraryW
- Creates PEB module list entry
- RWX allocated memory region visible
- **Fix**: Reflective DLL injection + PE header stripping + per-function mapping

### #10: Identical Builds Per User
- Every copy identical after decompression
- One signature detects all copies
- **Fix**: Polymorphic builds (LLVM pass: reorder functions, rotate constants)

## Detection Vectors (9 Attack Surfaces)

### 1. Memory Scan
- RWX regions with 3.49MB uncompressed code
- Large heap allocations (syscall stubs, string buffers)

### 2. Syscall Stub Signature
- Pattern: `4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3`
- All 8 stubs identical → high-confidence detection

### 3. Hook Detection
- wglSwapIntervalEXT hooked (OpenGL overlay)
- game.dll known patterns checked for modifications
- Function prologues with `FF 25` indirect jump

### 4. IAT Anomalies
- No standard import table
- Lazy resolution patching detected as memory modification

### 5. PE Anomalies
- Zero-size .text section
- Two .rsrc sections
- Entry point in .rsrc
- TimeDateStamp = 0

### 6. Window Subclassing
- `SetWindowLongPtrW(GWL_WNDPROC, overlayProc)`
- Detectable by checking game window's WNDPROC

### 7. VEH Registration
- `AddVectoredExceptionHandler(1, handler)` is visible
- Exception handler chain can be enumerated

### 8. Process Scan
- 14 proxy/MITM tools checked via CreateToolhelp32Snapshot
- These scans are themselves detectable

### 9. File System Activity
- `C:\libertea_replay_cap.json` — persistent farming data
- `n\GameMon64.des` — GameGuard file manipulation
- ntdll.dll read from disk (unusual for most programs)

## Packer Anti-Debug (MISSING)
- Packer stub has ZERO anti-debug checks
- Pure decompression: entry point → decompress → jump to real code
- Analyst can attach debugger before decompression starts
- **Fix**: Add PEB BeingDebugged check + NtQueryInformationProcess direct syscall in packer stub

## Improvement Recommendations (From BRAINSTORM_IMPROVEMENTS.txt)

### Highest Priority
1. **Self-integrity verification** (5 layers, server-side challenge)
2. **Expand syscall coverage** (add missing NT stubs, diversify stub layout)
3. **Polymorphic build system** (LLVM pass for per-user unique builds)

### High Priority
4. **Reflective DLL injection** (no LoadLibraryW, no PEB entry)
5. **Anti-debug in packer stub** (cheap, high impact)
6. **Multi-layer C2 infrastructure** (Tor + IPFS + VPS mesh)
7. **Stream-proof overlay** (hide from screen capture)

### Medium Priority
8. Hardware breakpoint detection
9. VM/sandbox detection
10. Control flow obfuscation (ollvm)
11. Per-string encryption with decentralized deobfuscation
12. Kernel driver component (BYOVD)

## Syscall Stub Diversity (Critical Fix)
Current stubs (all identical):
```asm
4C 8B D1    mov r10, rcx
B8 XX XX XX XX  mov eax, SSN
0F 05       syscall
C3          ret
```

**Proposed variants:**
```asm
; Variant 1: Swapped order
B8 XX XX XX XX    mov eax, SSN
4C 8B D1          mov r10, rcx
0F 05             syscall
C3                ret

; Variant 2: Stack shuffle
50                push rax
4C 8B D1          mov r10, rcx
B8 XX XX XX XX    mov eax, SSN
0F 05             syscall
58                pop rax
C3                ret

; Variant 3: XOR loader
4C 8B D1          mov r10, rcx
B8 XX XX XX XX    mov eax, SSN
35 XX XX XX XX    xor eax, obfuscated_key
0F 05             syscall
C3                ret

; Variant 4: REX-prefixed
4C 8B D1          mov r10, rcx
B8 XX XX XX XX    mov eax, SSN
0F 05             syscall
C3                ret
(with random NOP/junk inserts between instructions)
```

## Web Research Elevations

### BYOVD: Kernel Access Without Signed Driver
The most significant evolution in anti-cheat bypass is **Bring Your Own Vulnerable Driver (BYOVD)**. Instead of writing a new kernel driver (which requires Microsoft signing), cheat developers load a signed-but-vulnerable driver.

**Common vulnerable drivers weaponized for game cheating:**

| Driver | Signed By | Vulnerability | Cheat Use Case |
|--------|----------|---------------|----------------|
| `RTCore64.sys` | MSI | Arbitrary MSR read/write (CVE-2019-16098) | Disable AC kernel callbacks, read physical memory |
| `GLCKIO2.sys` | ASUS | Arbitrary physical memory access | Map game process memory from kernel |
| `gdrv.sys` | Gigabyte | Arbitrary kernel memory read/write | PPL bypass, driver loading |
| `hw.sys` | Hardware vendors | Various | Kernel mode execution |
| `RTCore64.sys` | MSI | MSR write → disable PG (Patchguard) | Disable Kernel Patch Protection |

**PPL (Protected Process Light) Bypass**: GameGuard runs as PPL to protect itself. BYOVD can:
1. Load vulnerable driver via `ZwLoadDriver`
2. Use it to write to EPROCESS → remove PPL protection
3. Then read GameGuard memory, patch its detection routines

**LIBERTEA implication**: The cheat has zero kernel components → any kernel-level AC (GameGuard) can detect it by scanning process memory from Ring 0. A BYOVD component would allow:
- Removing PPL from GameGuard process
- Hiding cheat's RWX memory allocation from kernel enumeration
- Hooking GameGuard's pattern scanner to suppress detections

### GameGuard AOB Scanning (2025-2026)
GameGuard now performs:
- **Memory pattern scans**: Searches process memory for known cheat byte sequences
- **High-risk targets**: `4C 8B D1 B8 ?? 0F 05 C3` (syscall stub template), `90 90 90 90` (NOP sleds), `FF 25` (detour hooks)
- **Kernel-level enumeration**: Scans PEB module list for unlinked/injected modules
- **Timing analysis**: RDTSC-based detection of hypervisors/debuggers (overlaps with LIBERTEA's own RDTSC usage)

**LIBERTEA counters**: The identical 11-byte syscall stubs are trivial to AOB-scan. All NOP_PATCH hooks create NOP sleds (`90 90 90 90`) — the most basic detectable pattern.

### Hell's Gate Family for Syscall Resolution
Instead of reading ntdll from disk (current approach), the Hell's Gate family uses PEB-based resolution:

```asm
; Hades Gate: PEB walk, no disk, no API
mov rax, gs:[60h]        ; PEB
mov rax, [rax+18h]       ; Ldr
mov rbx, [rax+20h]       ; InMemoryOrderModuleList.Flink
mov rbx, [rbx+20h]       ; ntdll base (2nd entry in Win10+)
mov esi, [rbx+3Ch]       ; PE signature offset
add rsi, rbx             ; PE header
mov r12d, [rsi+88h]      ; Export directory RVA
add r12, rbx             ; Export directory
; Walk exports, find target function SSN
```

**Advantages over current approach**:
- No `CreateFileW` call (filesystem monitoring evasion)
- No `ReadFile` call (disk I/O pattern detection)
- No `GetModuleHandle` call (API hook evasion)
- Works even if ntdll is not on disk (rare, but possible)

### Indirect Syscalls & Call Stack Spoofing (LACUNA)
EDR/GameGuard can detect direct syscalls by examining kernel return addresses. If `SYSCALL` is followed by `RET` to an address outside ntdll → detected as cheat.

**Indirect syscall technique**:
1. Find a `RET` gadget inside ntdll's .text
2. Build stub that pushes ntdll address as return address
3. `SYSCALL` → kernel returns to ntdll → ntdll `RET` to cheat

Tools: `FreshyCalls`, `stealth_call`, `LACUNA`

### API Hashing (ROR13 Alternative)
Current cheat stores plain-text names. The scene standard is hashing:

| Hash | Usage | Why Better |
|------|-------|------------|
| **ROR13** | Classic | Too well-known now; YARA rules exist |
| **JenkinsOAAT** | Modern malware | Avalanche effect, minimal collisions |
| **FNV1a** | Performance-sensitive | Very fast, low collisions, easy to implement |
| **CRC32** | Windows kernel | Hardware-accelerated on modern CPUs, 4-byte hash |

**Recommendation**: Multi-hash approach. Hash module names with FNV1a, NT function names with CRC32, use random salt per build to prevent signature-based detection of hash values.

### Call Stack Spoofing for Pattern Scanner Protection
If GameGuard monitors call stacks during memory scans, it can detect the cheat's pattern scanner calling `VirtualProtect` / `NtProtectVirtualMemory`. Counter:
- Route all memory permission changes through indirect syscalls
- Spoof the return address to appear as legitimate game code
- Use timer-based delayed execution to evade synchronous monitoring

### Modern Obfuscation Passes (Kagura)
LIBERTEA's code is standard MSVC /O2 — readable in any disassembler. Kagura OLLVM passes provide:
- **MBR (Mixed Boolean-Arithmetic)**: `a + b` → `(a ^ b) + 2*(a & b)` — defeats pattern matching
- **CFG Flattening**: Remove function structure → single big switch in a loop
- **Bogus Control Flow**: Insert opaque predicates that always take one path
- **String Encryption**: Per-function encrypted strings with MBA-wrapped decryptors
- **Split Basic Blocks**: Break each basic block into smaller pieces → more CFG complexity
- **File-driven config**: JSON/YAML per-function granularity

**Integration**: Add Kagura as LLVM pass after Clang-CL compilation, before linking.

### stealth_call Architecture (Production Reference)
The `stealth_call` library (2025) sets the modern standard:
- **977 syscall stubs** — all NT functions (vs. 8 in LIBERTEA)
- **KnownDlls section mapping**: No disk read, no CreateFile — reads ntdll from kernel's KnownDlls section
- **W^X enforcement**: Memory is either Writable OR Executable, never both
- **Per-call stub generation**: Each invocation creates a unique stub with randomized junk bytes
- **Indirect syscall with return spoofing**: Legitimate-looking call stack
- **Stub cache**: Reuse stubs within a session, destroy on unload

### Detection Risk Matrix (Updated 2026)
| Detection Vector | LIBERTEA Risk | BYOVD Mitigation | Indirect Syscall Mitigation | OLLVM Mitigation |
|-----------------|---------------|------------------|----------------------------|------------------|
| AOB syscall stubs | **HIGH** (identical stubs) | Low | **FULL** (per-call random) | Low |
| NOP sled patterns | **HIGH** (27 NOP_PATCH) | None | None | **MEDIUM** (replace with MOV) |
| RWX memory | **HIGH** (3.49MB) | **FULL** (kernel hide) | None | None |
| File I/O (ntdll read) | **HIGH** | Low | **FULL** (PEB method) | None |
| Call stack tracing | **MEDIUM** (direct syscall) | Low | **FULL** (indirect) | Low |
| GameGuard kernel scan | **HIGH** | **FULL** (PPL bypass) | Low | Low |
| DLL injection detection | **HIGH** (LoadLibraryW) | **FULL** (hide from PEB) | None | None |
| Window subclassing | **MEDIUM** | None | None | None |
| VEH chain enumeration | **LOW-MEDIUM** | **FULL** (kernel VEH hide) | None | None |

## Key Defensive Strings (Logs & Messages)
- `"Patterns: %d/%d found. Some features may not work."`
- `"Hook verified"` / `"WARNING: Hook mismatch"`
- `"Game may have updated..."`
- `"=== LIBERTEA CRASH LOG ==="`
- `"Session expired or access revoked. Contact TheOGcup."`
- `"ScPresent::Install: hwnd=%p origWndProc=%p"`
- `"[HTTP] Found libcurl at %p"`
