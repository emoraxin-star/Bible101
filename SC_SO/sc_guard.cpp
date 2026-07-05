
#include "sc_guard.h"
#include <windows.h>
#include <atomic>
#include <cstring>

static uintptr_t s_gameBase    = 0;
static uintptr_t s_gameEnd     = 0;
static uintptr_t s_exeBase     = 0;
static uintptr_t s_exeEnd      = 0;

static void* s_retStub = nullptr;

#define MAX_OWN_THREADS 16
static DWORD s_ownTids[MAX_OWN_THREADS] = {};
static CRITICAL_SECTION s_tidLock;
static bool s_tidLockInit = false;

static bool IsOwnThread(DWORD tid) {
    if (!s_tidLockInit) return false;
    bool found = false;
    EnterCriticalSection(&s_tidLock);
    for (int i = 0; i < MAX_OWN_THREADS; i++) {
        if (s_ownTids[i] == tid) { found = true; break; }
    }
    LeaveCriticalSection(&s_tidLock);
    return found;
}

static std::atomic<DWORD>    s_scGameTid{0};
static std::atomic<bool>     s_scActive{false};

static std::atomic<int>  s_absorptionCount{0};
static std::atomic<bool> s_shouldBackoff{false};
static LONGLONG s_absorptionTimes[16] = {};
static int      s_absorptionIdx = 0;
static LARGE_INTEGER s_qpcFreq = {};

static bool IsInAnyModule(uintptr_t addr) {

    if (s_gameBase && addr >= s_gameBase && addr < s_gameEnd) return true;
    if (s_exeBase  && addr >= s_exeBase  && addr < s_exeEnd)  return true;

    HMODULE hMod = nullptr;
    return GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)addr, &hMod) != 0;
}

static void RecordAbsorption() {
    int count = s_absorptionCount.fetch_add(1) + 1;
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    int slot = s_absorptionIdx % 16;
    s_absorptionTimes[slot] = now.QuadPart;
    s_absorptionIdx++;

    if (count >= 3 && s_qpcFreq.QuadPart > 0) {
        int recentCount = 0;
        double windowSec = 300.0;
        for (int i = 0; i < 16; i++) {
            if (s_absorptionTimes[i] != 0) {
                double elapsed = (double)(now.QuadPart - s_absorptionTimes[i]) / s_qpcFreq.QuadPart;
                if (elapsed < windowSec) recentCount++;
            }
        }
        if (recentCount >= 3)
            s_shouldBackoff.store(true);
    }
}

static bool IsFatalScException(DWORD code) {
    return code == EXCEPTION_ACCESS_VIOLATION
        || code == 0xC0000094
        || code == 0xC0000095
        || code == 0xC000008E;
}

static LONG WINAPI ScCrashGuardVEH(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    if (code == 0xC00000FD) return EXCEPTION_CONTINUE_SEARCH;

    if (!IsFatalScException(code)) return EXCEPTION_CONTINUE_SEARCH;

    DWORD tid = GetCurrentThreadId();
    if (IsOwnThread(tid)) return EXCEPTION_CONTINUE_SEARCH;

    uintptr_t rip = (uintptr_t)ep->ContextRecord->Rip;

    if (s_gameBase && rip >= s_gameBase && rip < s_gameEnd) {
        ep->ContextRecord->Rax = 0;
        ep->ContextRecord->Rip = (uintptr_t)s_retStub;
        RecordAbsorption();
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (s_exeBase && rip >= s_exeBase && rip < s_exeEnd) {
        ep->ContextRecord->Rax = 0;
        ep->ContextRecord->Rip = (uintptr_t)s_retStub;
        RecordAbsorption();
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (s_scActive.load()) {
        if (!IsInAnyModule(rip)) {
            ep->ContextRecord->Rax = 0;
            ep->ContextRecord->Rip = (uintptr_t)s_retStub;
            RecordAbsorption();
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    if (s_scActive.load()) {
        ep->ContextRecord->Rax = 0;
        ep->ContextRecord->Rip = (uintptr_t)s_retStub;
        RecordAbsorption();
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

void ScGuard::Install(uintptr_t gameBase, size_t gameSize) {
    QueryPerformanceFrequency(&s_qpcFreq);
    s_gameBase = gameBase;
    s_gameEnd  = gameBase + gameSize;

    HMODULE hExe = GetModuleHandleA(nullptr);
    if (hExe) {
        s_exeBase = (uintptr_t)hExe;
        auto dos = (IMAGE_DOS_HEADER*)hExe;
        auto nt  = (IMAGE_NT_HEADERS64*)((uint8_t*)hExe + dos->e_lfanew);
        DWORD imgSize = nt->OptionalHeader.SizeOfImage;
        s_exeEnd = s_exeBase + (imgSize > 0 ? imgSize : 0x8000000);
    }

    InitializeCriticalSection(&s_tidLock);
    s_tidLockInit = true;
    RegisterOwnThread(GetCurrentThreadId());

    s_retStub = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (s_retStub) {
        BYTE* p = (BYTE*)s_retStub;
        p[0] = 0x48; p[1] = 0x31; p[2] = 0xC0;
        p[3] = 0xC3;
        DWORD old;
        VirtualProtect(s_retStub, 4096, PAGE_EXECUTE_READ, &old);
    }

    AddVectoredExceptionHandler(1, ScCrashGuardVEH);
}

void ScGuard::RegisterOwnThread(DWORD tid) {
    if (!s_tidLockInit) return;
    EnterCriticalSection(&s_tidLock);
    for (int i = 0; i < MAX_OWN_THREADS; i++) {
        if (s_ownTids[i] == tid || s_ownTids[i] == 0) {
            s_ownTids[i] = tid;
            break;
        }
    }
    LeaveCriticalSection(&s_tidLock);
}

void ScGuard::UnregisterOwnThread(DWORD tid) {
    if (!s_tidLockInit) return;
    EnterCriticalSection(&s_tidLock);
    for (int i = 0; i < MAX_OWN_THREADS; i++) {
        if (s_ownTids[i] == tid) { s_ownTids[i] = 0; break; }
    }
    LeaveCriticalSection(&s_tidLock);
}

void ScGuard::NotifyScApc(DWORD gameTid) {
    s_scGameTid.store(gameTid);

    s_scActive.store(true);
}

bool ScGuard::ShouldBackoff() {
    return s_shouldBackoff.load();
}

void ScGuard::ResetBackoff() {
    s_shouldBackoff.store(false);
    s_absorptionCount.store(0);
    s_absorptionIdx = 0;
    memset(s_absorptionTimes, 0, sizeof(s_absorptionTimes));
}

int ScGuard::GetAbsorptionCount() {
    return s_absorptionCount.load();
}
