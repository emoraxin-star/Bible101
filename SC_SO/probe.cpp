#include "probe.h"
extern bool g_probeEnabled;
#include "state.h"
#include "entity_protect.h"
#include "license.h"
#include "offsets.h"
#include <cstring>
#include <string>
#include <algorithm>
#include <tlhelp32.h>

#define ProbeLog(...) do{}while(0)

bool g_probeEnabled = false;

typedef LONG (WINAPI* NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NtQueryInformationThread_t g_NtQIT = nullptr;

static uintptr_t GetThreadStartAddr(HANDLE hThread) {
    if (!g_NtQIT) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) g_NtQIT = (NtQueryInformationThread_t)GetProcAddress(ntdll, "NtQueryInformationThread");
    }
    if (!g_NtQIT) return 0;
    uintptr_t startAddr = 0;
    g_NtQIT(hThread, 9 , &startAddr, sizeof(startAddr), nullptr);
    return startAddr;
}

static bool IsGameThread(HANDLE hThread, uintptr_t gameBase, uintptr_t gameEnd) {
    uintptr_t start = GetThreadStartAddr(hThread);
    if (start == 0) return true;
    return (start >= gameBase && start < gameEnd);
}

static bool SafeReadable(const void* addr, size_t len) {
    if (!addr) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    uintptr_t addrEnd   = reinterpret_cast<uintptr_t>(addr) + len;
    if (addrEnd > regionEnd) return false;
    DWORD prot = mbi.Protect & 0xFF;
    return (prot == PAGE_READONLY  || prot == PAGE_READWRITE ||
            prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE ||
            prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_WRITECOPY);
}

static void*   g_vehHandle    = nullptr;
static uintptr_t g_breakAddr  = 0;
static volatile bool g_hookActive = false;

static volatile bool g_rearmRunning = false;
static HANDLE g_rearmThread = nullptr;

static DWORD WINAPI RearmWatchdog(LPVOID) {
    while (g_rearmRunning && g_hookActive && g_breakAddr) {
        DWORD pid = GetCurrentProcessId();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te{};
            te.dwSize = sizeof(te);
            if (Thread32First(snap, &te)) {
                do {
                    if (te.th32OwnerProcessID != pid) continue;
                    if (te.th32ThreadID == GetCurrentThreadId()) continue;
                    HANDLE hThread = OpenThread(
                        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                        FALSE, te.th32ThreadID);
                    if (hThread) {
                        CONTEXT ctx{};
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        SuspendThread(hThread);
                        if (GetThreadContext(hThread, &ctx)) {

                            if (ctx.Dr2 != g_breakAddr) {
                                ctx.Dr2 = g_breakAddr;
                                ctx.Dr7 &= ~(0xFULL << 24);
                                ctx.Dr7 |= (1ULL << 4);
                                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                                SetThreadContext(hThread, &ctx);
                            }
                        }
                        ResumeThread(hThread);
                        CloseHandle(hThread);
                    }
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }
        Sleep(2000);
    }
    return 0;
}

static uintptr_t g_instBreakAddr   = 0;
static volatile bool g_instActive  = false;

static uintptr_t s_pcRcx = 0, s_pcRdx = 0, s_pcR8 = 0, s_pcR9 = 0;
static uint8_t   s_pcFlag = 0;
static uintptr_t s_pcRetAddr = 0;
static bool      s_postCapturePending = false;

static void CaptureFromContext(void* serverInfo, void* slot,
                               const char* missionStr, void* missionData,
                               uint8_t flag);

static bool SetHWBreakpoint(HANDLE hThread, uintptr_t addr) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) {
        return false;
    }

    if ((ctx.Dr7 & (1ULL << 4)) && ctx.Dr2 != 0 && ctx.Dr2 != addr) {
        return false;
    }
    ctx.Dr2 = addr;
    ctx.Dr7 &= ~(0xFULL << 24);
    ctx.Dr7 |= (1ULL << 4);
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!SetThreadContext(hThread, &ctx)) {
        return false;
    }
    return true;
}

static void ClearHWBreakpoint(HANDLE hThread) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx)) {
        ctx.Dr2 = 0;
        ctx.Dr7 &= ~(1ULL << 4);
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(hThread, &ctx);
    }
}

static bool SetDR1Breakpoint(HANDLE hThread, uintptr_t addr) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return false;
    if ((ctx.Dr7 & (1ULL << 6)) && ctx.Dr3 != 0 && ctx.Dr3 != addr) {
        return false;
    }
    ctx.Dr3 = addr;
    ctx.Dr7 &= ~(0xFULL << 28);
    ctx.Dr7 |= (1ULL << 6);
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return SetThreadContext(hThread, &ctx);
}

static void ClearDR1Breakpoint(HANDLE hThread) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx)) {
        ctx.Dr3 = 0;
        ctx.Dr7 &= ~(1ULL << 6);
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(hThread, &ctx);
    }
}

static bool SetHWBreakpointAllThreads(uintptr_t addr, uintptr_t , uintptr_t ) {
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    int count = 0, skipped = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                    FALSE, te.th32ThreadID);
                if (hThread) {
                    if (te.th32ThreadID != GetCurrentThreadId()) {
                        SuspendThread(hThread);
                        if (SetHWBreakpoint(hThread, addr)) count++;
                        ResumeThread(hThread);
                    } else {
                        if (SetHWBreakpoint(hThread, addr)) count++;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return count > 0;
}

static void ClearHWBreakpointAllThreads() {
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                    FALSE, te.th32ThreadID);
                if (hThread) {
                    if (te.th32ThreadID != GetCurrentThreadId()) {
                        SuspendThread(hThread);
                        ClearHWBreakpoint(hThread);
                        ResumeThread(hThread);
                    } else {
                        ClearHWBreakpoint(hThread);
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static bool SetDR1BreakpointAllThreads(uintptr_t addr, uintptr_t , uintptr_t ) {
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    int count = 0, skipped = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                    FALSE, te.th32ThreadID);
                if (hThread) {
                    if (te.th32ThreadID != GetCurrentThreadId()) {
                        SuspendThread(hThread);
                        if (SetDR1Breakpoint(hThread, addr)) count++;
                        ResumeThread(hThread);
                    } else {
                        if (SetDR1Breakpoint(hThread, addr)) count++;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return count > 0;
}

static void ClearDR1BreakpointAllThreads() {
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                    FALSE, te.th32ThreadID);
                if (hThread) {
                    if (te.th32ThreadID != GetCurrentThreadId()) {
                        SuspendThread(hThread);
                        ClearDR1Breakpoint(hThread);
                        ResumeThread(hThread);
                    } else {
                        ClearDR1Breakpoint(hThread);
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static uintptr_t        g_nameBreakAddr    = 0;
static volatile bool    g_nameCaptureArmed = false;
static Probe::PlayerInfo g_playerNames[4]  = {};
static int               g_playerNameCount = 0;

static LONG WINAPI HWBreakpointHandler(EXCEPTION_POINTERS* ep) {
    if (!g_hookActive && !g_instActive) return EXCEPTION_CONTINUE_SEARCH;

    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        CONTEXT* ctx = ep->ContextRecord;

        if (g_hookActive && (ctx->Dr6 & (1ULL << 2)) && ctx->Rip == g_breakAddr) {
            s_pcRcx = ctx->Rcx;
            s_pcRdx = ctx->Rdx;
            s_pcR8  = ctx->R8;
            s_pcR9  = ctx->R9;
            s_pcFlag = 0;

            uintptr_t rsp = ctx->Rsp;
            if (SafeReadable((void*)(rsp + 0x28), 1))
                s_pcFlag = *(uint8_t*)(rsp + 0x28);

            s_pcRetAddr = 0;
            if (SafeReadable((void*)rsp, 8))
                s_pcRetAddr = *(uintptr_t*)rsp;

            if (s_pcRetAddr) {

                ctx->Dr3 = s_pcRetAddr;
                ctx->Dr7 &= ~(0xFULL << 28);
                ctx->Dr7 |= (1ULL << 6);
                s_postCapturePending = true;
            } else {

                CaptureFromContext((void*)s_pcRcx, (void*)s_pcRdx,
                                   (const char*)s_pcR8, (void*)s_pcR9, s_pcFlag);
            }

            ctx->Dr6 = 0;
            ctx->EFlags |= 0x10000;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (s_postCapturePending && (ctx->Dr6 & (1ULL << 3)) && ctx->Rip == s_pcRetAddr) {
            CaptureFromContext((void*)s_pcRcx, (void*)s_pcRdx,
                               (const char*)s_pcR8, (void*)s_pcR9, s_pcFlag);
            s_postCapturePending = false;

            if (g_instActive) {
                ctx->Dr3 = g_instBreakAddr;
                ctx->Dr7 &= ~(0xFULL << 28);
                ctx->Dr7 |= (1ULL << 6);
            } else {
                ctx->Dr3 = 0;
                ctx->Dr7 &= ~(1ULL << 6);
            }

            ctx->Dr6 = 0;
            ctx->EFlags |= 0x10000;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (g_instActive && (ctx->Dr6 & (1ULL << 3)) && ctx->Rip == g_instBreakAddr) {
            uintptr_t missionObj = ctx->Rsi;
            if (missionObj && SafeReadable((void*)(missionObj + 0x20), 1)) {
                *(uint8_t*)(missionObj + 0x20) = 2;
            }
            ctx->Dr6 = 0;
            ctx->EFlags |= 0x10000;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static void CaptureFromContext(void* serverInfo, void* slot,
                               const char* missionStr, void* missionData,
                               uint8_t flag)
{
    bool shouldCapture = g_state.probeArmed.load() && g_probeEnabled;
    if (!shouldCapture) return;

    if (!missionStr || !SafeReadable(missionStr, 1) || missionStr[0] == '\0')
        return;
    if (!SafeReadable(slot, GS::RING_SLOT_SIZE))
        return;

    if (g_state.gameThreadId == 0) {
        g_state.gameThreadId = GetCurrentThreadId();
        g_state.gameThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, g_state.gameThreadId);
        g_state.AddLog("[Probe] Game thread captured");
    }

    CapturedMission cap{};
    cap.serverInfo  = reinterpret_cast<uintptr_t>(serverInfo);
    cap.entityPtr   = reinterpret_cast<uintptr_t>(missionStr) - GS::ENT_GATE_STRING;
    cap.missionData = reinterpret_cast<uintptr_t>(missionData);
    cap.captureTime = GetTickCount64();
    cap.valid       = true;

    if (g_state.pEntityData) {
        uintptr_t edPtr = 0;
        if (SafeReadable(reinterpret_cast<void*>(g_state.pEntityData), sizeof(uintptr_t)))
            edPtr = *reinterpret_cast<uintptr_t*>(g_state.pEntityData);
        if (edPtr && SafeReadable(reinterpret_cast<void*>(edPtr + 0x10), sizeof(uintptr_t)))
            cap.entityDataVal = *reinterpret_cast<uintptr_t*>(edPtr + 0x10);

        if (cap.entityDataVal && SafeReadable(reinterpret_cast<void*>(cap.entityDataVal), sizeof(uintptr_t)))
            cap.entityVtable = *reinterpret_cast<uintptr_t*>(cap.entityDataVal);
    }

    if (cap.entityDeepCopy)     { VirtualFree(cap.entityDeepCopy, 0, MEM_RELEASE);     cap.entityDeepCopy = nullptr; }
    if (cap.entityDataDeepCopy) { VirtualFree(cap.entityDataDeepCopy, 0, MEM_RELEASE); cap.entityDataDeepCopy = nullptr; }
    cap.entityDeepCopySize = 0;
    cap.entityDataDeepCopySize = 0;

    if (cap.entityPtr) {
        constexpr size_t kMinEntitySize = GS::kEFS + 0x1000;
        constexpr size_t kMaxEntityCopy = 0x400000;
        MEMORY_BASIC_INFORMATION mbi{};
        if (SafeReadable(reinterpret_cast<void*>(cap.entityPtr), 8) &&
            VirtualQuery(reinterpret_cast<void*>(cap.entityPtr), &mbi, sizeof(mbi)) &&
            mbi.State == MEM_COMMIT)
        {
            uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            size_t avail = (regionEnd > cap.entityPtr) ? (size_t)(regionEnd - cap.entityPtr) : 0;
            size_t toCopy = (std::min)(avail, kMaxEntityCopy);
            if (toCopy >= kMinEntitySize) {
                void* buf = VirtualAlloc(nullptr, toCopy, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (buf) {
                    memcpy(buf, reinterpret_cast<void*>(cap.entityPtr), toCopy);
                    cap.entityDeepCopy = buf;
                    cap.entityDeepCopySize = toCopy;
                }
            }
        }
    }

    if (cap.entityDataVal) {
        constexpr size_t kMaxEntityDataCopy = 0x10000;
        MEMORY_BASIC_INFORMATION mbi{};
        if (SafeReadable(reinterpret_cast<void*>(cap.entityDataVal), 8) &&
            VirtualQuery(reinterpret_cast<void*>(cap.entityDataVal), &mbi, sizeof(mbi)) &&
            mbi.State == MEM_COMMIT)
        {
            uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            size_t avail = (regionEnd > cap.entityDataVal) ? (size_t)(regionEnd - cap.entityDataVal) : 0;
            size_t toCopy = (std::min)(avail, kMaxEntityDataCopy);
            if (toCopy >= 64) {
                void* buf = VirtualAlloc(nullptr, toCopy, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (buf) {
                    memcpy(buf, reinterpret_cast<void*>(cap.entityDataVal), toCopy);
                    cap.entityDataDeepCopy = buf;
                    cap.entityDataDeepCopySize = toCopy;
                }
            }
        }
    }

    memcpy(cap.slotData, slot, GS::RING_SLOT_SIZE);
    strncpy(cap.missionStr, missionStr, sizeof(cap.missionStr) - 1);

    const char* urlSrc = reinterpret_cast<const char*>(
        reinterpret_cast<uint8_t*>(slot) + GS::SLOT_URL);
    if (SafeReadable(urlSrc, 1))
        strncpy(cap.url, urlSrc, sizeof(cap.url) - 1);

    if (missionData && SafeReadable(missionData, 8)) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(missionData, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) {
            uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            uintptr_t mdAddr    = reinterpret_cast<uintptr_t>(missionData);
            size_t readable = (regionEnd > mdAddr) ? (size_t)(regionEnd - mdAddr) : 0;
            size_t toCopy = (std::min)(readable, (size_t)0x4000);
            if (toCopy > 0) {
                cap.missionDataSnapshot.resize(toCopy);
                memcpy(cap.missionDataSnapshot.data(), missionData, toCopy);
            }
        }
    }

    {
        uintptr_t serObjPtr = 0;
        memcpy(&serObjPtr,
               reinterpret_cast<uint8_t*>(slot) + GS::SLOT_SERIAL_OBJ,
               sizeof(uintptr_t));

        if (serObjPtr && SafeReadable(reinterpret_cast<void*>(serObjPtr), 64)) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<void*>(serObjPtr), &mbi, sizeof(mbi)) &&
                mbi.State == MEM_COMMIT)
            {
                uintptr_t regionEnd =
                    reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                size_t available = (regionEnd > serObjPtr)
                                   ? (size_t)(regionEnd - serObjPtr) : 0;
                size_t toCopy = (std::min)(available, (size_t)0x10000);
                if (toCopy > 0) {
                    cap.serObjSnapshot.resize(toCopy);
                    memcpy(cap.serObjSnapshot.data(),
                           reinterpret_cast<void*>(serObjPtr), toCopy);
                    cap.serObjOrigAddr = serObjPtr;
                }
            }
        }
    }

    if (cap.missionDataSnapshot.size() >= 0x3C) {
        memcpy(&g_state.capturedWarTime, cap.missionDataSnapshot.data() + 0x38, 4);
        g_state.captureTickCount = GetTickCount64();
    }

    {
        std::lock_guard<std::mutex> lk(g_state.captureMutex);

        if (g_state.captures.empty())
            g_state.captures.push_back(std::move(cap));
        else
            g_state.captures[0] = std::move(cap);
    }

    g_state.probeArmed.store(false);
    g_probeEnabled = false;

    g_state.AddLog("[P] Capture complete");

    SaveCapture(g_state);

    char pidStr[128] = {};
    if (g_state.captures.back().missionDataSnapshot.size() >= 0x0068 + 2*0x30) {
        const auto& snap = g_state.captures.back().missionDataSnapshot;
        int pcnt = 0;
        char* ps = pidStr;
        for (int i = 0; i < 4; i++) {
            uint64_t pid = 0;
            memcpy(&pid, snap.data() + 0x0068 + i*0x30, 8);
            if (pid == 0) continue;
            if (pcnt) { *ps++ = ','; *ps++ = ' '; }
            snprintf(ps, 20, "...%08X", (uint32_t)(pid & 0xFFFFFFFF));
            ps += strlen(ps);
            pcnt++;
        }
    }
    g_state.AddLog("Probe data saved");
}

bool Probe::Install(uintptr_t gameBase) {
    if (!License::IsUnlocked()) return false;

    if (gameBase < 0x10000000ULL) {
        g_state.AddLog("Probe aborted: module not found", true);
        return false;
    }

    uintptr_t testBP = gameBase + GS::rv_fn0 - 0x10;
    if (testBP < 0x100000000ULL || testBP > 0x7FFFFFFF0000ULL) {
        g_state.AddLog("Probe aborted: BP address out of valid range", true);
        return false;
    }

    g_state.gameBase     = gameBase;
    g_state.pServerInfo  = gameBase + GS::rv_gp4;
    g_state.pWarData     = gameBase + GS::rv_gp7;
    g_state.pEntityData  = gameBase + GS::rv_gp6;

    if (!SafeReadable(reinterpret_cast<void*>(g_state.pServerInfo), sizeof(uintptr_t))) {
        g_state.AddLog("ServerInfo global not readable!", true);
        return false;
    }

    uint8_t* enqAddr = reinterpret_cast<uint8_t*>(gameBase + GS::rv_fn5);
    if (SafeReadable(enqAddr, sizeof(GS::ENQUEUE_SIG))) {
        if (memcmp(enqAddr, GS::ENQUEUE_SIG, sizeof(GS::ENQUEUE_SIG)) != 0) {
            g_state.AddLog("WARNING: Hook mismatch — update may be needed", true);
        } else {
            g_state.AddLog("Hook verified");
        }
    }

    g_vehHandle = AddVectoredExceptionHandler(1, HWBreakpointHandler);
    if (!g_vehHandle) {
        g_state.AddLog("Handler install failed!", true);
        return false;
    }

    g_breakAddr = gameBase + GS::rv_fn0 - 0x10;

    uintptr_t gameEnd = gameBase + 0x4000000;
    {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)gameBase;
        if (SafeReadable(dos, sizeof(*dos)) && dos->e_magic == IMAGE_DOS_SIGNATURE) {
            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(gameBase + dos->e_lfanew);
            if (SafeReadable(nt, sizeof(*nt)) && nt->Signature == IMAGE_NT_SIGNATURE)
                gameEnd = gameBase + nt->OptionalHeader.SizeOfImage;
        }
    }
    g_state.gameEnd = gameEnd;

    g_hookActive = true;
    if (!SetHWBreakpointAllThreads(g_breakAddr, gameBase, gameEnd)) {
        g_state.AddLog("Setup failed!", true);
        RemoveVectoredExceptionHandler(g_vehHandle);
        g_vehHandle = nullptr;
        g_hookActive = false;
        return false;
    }

    g_state.hookInstalled.store(true);
    g_state.AddLog("[P] Hook installed");

    g_rearmRunning = true;
    g_rearmThread = CreateThread(nullptr, 0, RearmWatchdog, nullptr, 0, nullptr);

    return true;
}

void Probe::Uninstall() {

    g_rearmRunning = false;
    if (g_rearmThread) {
        WaitForSingleObject(g_rearmThread, 5000);
        CloseHandle(g_rearmThread);
        g_rearmThread = nullptr;
    }
    g_hookActive = false;
    g_instActive = false;
    ClearHWBreakpointAllThreads();
    ClearDR1BreakpointAllThreads();
    if (g_vehHandle) {
        RemoveVectoredExceptionHandler(g_vehHandle);
        g_vehHandle = nullptr;
    }
    g_state.hookInstalled.store(false);
    g_state.instantMissionEnabled.store(false);
    g_state.AddLog("BP cleared");
}

void Probe::EnableInstantComplete(bool enable) {
    if (enable == g_instActive) return;

    if (enable) {
        if (!g_state.gameBase) {
            g_state.AddLog("Instant Complete: gameBase not set — run probe first!", true);
            return;
        }
        g_instBreakAddr = g_state.gameBase + GS::rv_fn6;
        g_instActive    = true;

        if (!g_vehHandle) {
            g_vehHandle = AddVectoredExceptionHandler(1, HWBreakpointHandler);
            if (!g_vehHandle) {
                g_instActive = false;
                g_state.AddLog("IC: handler failed!", true);
                return;
            }
        }
        uintptr_t gBase = g_state.gameBase;
        uintptr_t gEnd  = g_state.gameEnd ? g_state.gameEnd : gBase + 0x4000000;
        SetDR1BreakpointAllThreads(g_instBreakAddr, gBase, gEnd);
        g_state.instantMissionEnabled.store(true);
        g_state.AddLog("Instant Complete ON");
    } else {
        g_instActive   = false;
        ClearDR1BreakpointAllThreads();
        g_state.instantMissionEnabled.store(false);
        g_state.AddLog("Instant Complete OFF");
    }
}

bool Probe::IsInstantCompleteActive() {
    return g_instActive;
}

void Probe::RearmIC() {
    if (!g_instActive || !g_state.gameThreadHandle) return;
    HANDLE hThread = g_state.gameThreadHandle;
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return;
    ctx.Dr3 = 0;
    ctx.Dr7 &= ~(1ULL << 6);
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(hThread, &ctx);

    Sleep(1);
    ctx.Dr3 = g_instBreakAddr;
    ctx.Dr7 |= (1ULL << 6);
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(hThread, &ctx);
}

void Probe::GetCapturedPlayerInfo(PlayerInfo out[4], int& count) { count = 0; }

void Probe::PauseDR2() {
    HANDLE hThread = GetCurrentThread();
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx)) {
        ctx.Dr2 = 0;
        ctx.Dr7 &= ~(1ULL << 4);
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(hThread, &ctx);
    }
}

void Probe::ResumeDR2() {
    if (!g_hookActive || !g_breakAddr) return;
    HANDLE hThread = GetCurrentThread();
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx)) {
        ctx.Dr2 = g_breakAddr;
        ctx.Dr7 &= ~(0xFULL << 24);
        ctx.Dr7 |= (1ULL << 4);
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(hThread, &ctx);
    }
}
