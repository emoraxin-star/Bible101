
#include "replay.h"
#include "state.h"
#include "entity_protect.h"
#include "offsets.h"
#include "derived_offsets.h"
#include "http_monitor.h"
#include "sc_guard.h"
#include "sc_tracker.h"

#include "probe.h"
#include "farming.h"
#include "loadout.h"
#include "license.h"
#include "sc_present.h"
#include "sc_limit.h"
#include "sc_debug.h"

#include <cstdio>
#include <string>
#include <cstring>
#include <cstdarg>
#include <csetjmp>
#include <windows.h>
#include <psapi.h>
#include <atomic>
#include <objbase.h>
#include <thread>

typedef LONG (NTAPI *NtQueueApcThreadEx_t)(
    HANDLE ThreadHandle,
    HANDLE UserApcReserveHandle,
    PVOID  ApcRoutine,
    PVOID  Arg1,
    PVOID  Arg2,
    PVOID  Arg3
);
static NtQueueApcThreadEx_t s_ntQueueApc = nullptr;

static void openLog() {}
static void logf(const char*, ...) {}
static void closeLog() {}

static bool SafeReadable(const void* addr, size_t len) {
    if (!addr) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect & 0xFF;
    return (prot == PAGE_READONLY || prot == PAGE_READWRITE ||
            prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE ||
            prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_WRITECOPY);
}

#pragma warning(push)
#pragma warning(disable:4733)
static uintptr_t SafeReadPtr(uintptr_t addr) {
    __try { return *(uintptr_t*)addr; } __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
static bool SafeMemScan(const char* base, size_t regionSize, const char* needle, int nLen,
                         uintptr_t goldenBufAddr, uintptr_t globalPtr,
                         uintptr_t* hitOut, int* totalHits, bool isRW,
                         int maxHits) {
    int found = 0;
    __try {
        for (size_t off = 0; off <= regionSize - nLen; off++) {
            if (base[off] == needle[0] && memcmp(base + off, needle, nLen) == 0) {
                uintptr_t hitAddr = (uintptr_t)(base + off);
                (*totalHits)++;
                if (hitAddr >= goldenBufAddr && hitAddr < goldenBufAddr + 128) continue;
                if (isRW && found < maxHits) {
                    hitOut[found++] = hitAddr;
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return found > 0;
}
static bool SafeWriteUUID(uintptr_t addr, const char* uuid, int len) {
    DWORD oldProt;
    __try {
        if (VirtualProtect((void*)addr, len, PAGE_READWRITE, &oldProt)) {
            memcpy((void*)addr, uuid, len);
            VirtualProtect((void*)addr, len, oldProt, &oldProt);
            return true;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return false;
}
#pragma warning(pop)

static void GenerateUUID(char* buf) {
    GUID guid;
    CoCreateGuid(&guid);
    sprintf(buf, "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

static bool UuidToGuidLE(const char* uuid, unsigned char out[16]) {
    unsigned int d1; unsigned short d2, d3;
    unsigned int d4[8];
    if (sscanf(uuid, "%08x-%04hx-%04hx-%02x%02x-%02x%02x%02x%02x%02x%02x",
               &d1, &d2, &d3, &d4[0],&d4[1],&d4[2],&d4[3],&d4[4],&d4[5],&d4[6],&d4[7]) != 11)
        return false;
    memcpy(out, &d1, 4);
    memcpy(out+4, &d2, 2);
    memcpy(out+6, &d3, 2);
    for (int i = 0; i < 8; i++) out[8+i] = (unsigned char)d4[i];
    return true;
}

static bool UuidToRawBE(const char* uuid, unsigned char out[16]) {
    unsigned int d1; unsigned short d2, d3;
    unsigned int d4[8];
    if (sscanf(uuid, "%08x-%04hx-%04hx-%02x%02x-%02x%02x%02x%02x%02x%02x",
               &d1, &d2, &d3, &d4[0],&d4[1],&d4[2],&d4[3],&d4[4],&d4[5],&d4[6],&d4[7]) != 11)
        return false;
    out[0]=(d1>>24)&0xFF; out[1]=(d1>>16)&0xFF; out[2]=(d1>>8)&0xFF; out[3]=d1&0xFF;
    out[4]=(d2>>8)&0xFF;  out[5]=d2&0xFF;
    out[6]=(d3>>8)&0xFF;  out[7]=d3&0xFF;
    for (int i = 0; i < 8; i++) out[8+i] = (unsigned char)d4[i];
    return true;
}

static void GuidLEToUuid(const unsigned char bytes[16], char* out) {
    unsigned int d1; unsigned short d2, d3;
    memcpy(&d1, bytes, 4); memcpy(&d2, bytes+4, 2); memcpy(&d3, bytes+6, 2);
    sprintf(out, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            d1, d2, d3, bytes[8],bytes[9],bytes[10],bytes[11],
            bytes[12],bytes[13],bytes[14],bytes[15]);
}

static void midLog(const char* , ...) {  }

static constexpr int MAX_MID_HITS = 64;
struct MidHit {
    uintptr_t addr;
    bool      writable;
};
static MidHit   s_midHits[MAX_MID_HITS];
static int      s_midHitCount = 0;
static std::atomic<bool> s_midScanDone{false};
static std::atomic<bool> s_midScanRunning{false};

static constexpr int MAX_BIN_HITS = 32;
struct BinHit {
    uintptr_t addr;
    bool      isLE;
};
static BinHit s_binHits[MAX_BIN_HITS];
static int    s_binHitCount = 0;

static constexpr int MAX_CANON_BIN_HITS = 32;
static BinHit s_canonBinHits[MAX_CANON_BIN_HITS];
static int    s_canonBinHitCount = 0;

static uintptr_t s_structHitAddr = 0;
static bool      s_structHitValid = false;

__declspec(noinline) static int ReadStructFields(uintptr_t uuidAddr,
    int32_t* outType, int32_t* outSeed, int32_t* outDiff,
    int32_t* outMid, int32_t* outOpIdx) {
    __try {
        *outType  = *(int32_t*)(uuidAddr + 0x30);
        *outSeed  = *(int32_t*)(uuidAddr + 0x34);
        *outDiff  = *(int32_t*)(uuidAddr + 0x3C);
        *outMid   = *(int32_t*)(uuidAddr + 0x2C);
        *outOpIdx = *(int32_t*)(uuidAddr + 0x28);
        return 1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

__declspec(noinline) static int ReadStructPostWrite(uintptr_t uuidAddr,
    int32_t* outType, int32_t* outSeed, int32_t* outDiff) {
    __try {
        *outType = *(int32_t*)(uuidAddr + 0x30);
        *outSeed = *(int32_t*)(uuidAddr + 0x34);
        *outDiff = *(int32_t*)(uuidAddr + 0x3C);
        return 1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static bool ValidateMissionStruct(uintptr_t uuidAddr) {
    int32_t missionType, seed, difficulty, missionId, opIndex;
    if (!ReadStructFields(uuidAddr, &missionType, &seed, &difficulty, &missionId, &opIndex)) {
        midLog("[SC] STRUCT CHECK EXCEPTION at 0x%llX", (unsigned long long)uuidAddr);
        return false;
    }

    midLog("[SC] STRUCT CHECK at 0x%llX: type=%d seed=%d(0x%X) diff=%d missionId=%d opIdx=%d",
           (unsigned long long)uuidAddr, missionType, seed, seed, difficulty, missionId, opIndex);

    bool typeOK = (missionType >= 0 && missionType <= 15);
    bool diffOK = (difficulty >= 1 && difficulty <= 10);
    bool seedOK = (seed != 0);
    bool midOK  = (missionId >= 0 && missionId < 100000);
    bool opOK   = (opIndex >= 0 && opIndex < 1000);

    if (typeOK && diffOK && seedOK && midOK && opOK) {
        midLog("[SC] ★★★ STRUCT VALIDATED ★★★ at 0x%llX — type=%d diff=%d seed=0x%X mid=%d opIdx=%d",
               (unsigned long long)uuidAddr, missionType, difficulty, seed, missionId, opIndex);
        return true;
    }

    midLog("[SC] STRUCT REJECTED: typeOK=%d diffOK=%d seedOK=%d midOK=%d opOK=%d",
           typeOK, diffOK, seedOK, midOK, opOK);
    return false;
}

static void TryAutoDetectMissionId() {
    if (s_midScanDone.load()) return;
    if (s_midScanRunning.load()) return;
    if (!HasGoldenMissionId()) {
        midLog("[MID-AUTO] No golden missionId yet — skipping scan");
        return;
    }

    const char* goldenPtr = GetGoldenMissionId();
    if (!goldenPtr || !goldenPtr[0]) {
        midLog("[MID-AUTO] Golden is empty — skipping");
        return;
    }
    char golden[64] = {0};
    strncpy(golden, goldenPtr, 63);
    int gLen = (int)strlen(golden);
    if (gLen < 30) {
        midLog("[MID-AUTO] Golden too short (%d) — skipping", gLen);
        return;
    }

    s_midScanRunning.store(true);

    midLog("[MID-AUTO] === SCAN START === golden=\"%s\" len=%d", golden, gLen);

    uintptr_t gameBase = g_state.gameBase;
    uintptr_t globalPtr = 0;
    if (gameBase) {
        uintptr_t ptrAddr = gameBase + GetGameGlobalRVA();
        if (SafeReadable((void*)ptrAddr, 8))
            globalPtr = *(uintptr_t*)ptrAddr;
    }
    midLog("[MID-AUTO] gameBase=0x%llX globalPtr=0x%llX", (unsigned long long)gameBase, (unsigned long long)globalPtr);

    SYSTEM_INFO si; GetSystemInfo(&si);
    uintptr_t scanAddr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t scanEnd  = (uintptr_t)si.lpMaximumApplicationAddress;

    int pagesScanned = 0, hitsFound = 0;
    ULONGLONG scanStartTick = GetTickCount64();
    constexpr ULONGLONG SCAN_TIMEOUT_MS = 30000;

    MEMORY_BASIC_INFORMATION mbi{};
    for (uintptr_t addr = scanAddr; addr < scanEnd; ) {

        if (pagesScanned % 500 == 0 && (GetTickCount64() - scanStartTick) > SCAN_TIMEOUT_MS) {
            midLog("[MID-AUTO] SCAN TIMEOUT after %llums — pages=%d hits=%d",
                   (unsigned long long)(GetTickCount64() - scanStartTick), pagesScanned, hitsFound);
            break;
        }
        if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) {
            addr += 0x10000;
            continue;
        }
        uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State != MEM_COMMIT ||
            !(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            addr = regionEnd;
            continue;
        }
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
            addr = regionEnd;
            continue;
        }

        pagesScanned++;
        const char* base = (const char*)mbi.BaseAddress;
        size_t regionSize = mbi.RegionSize;
        if (regionSize > (size_t)gLen) {
            uintptr_t regionHits[64]; int oldTotal = hitsFound;
            if (SafeMemScan(base, regionSize, golden, gLen, 0, globalPtr, regionHits, &hitsFound, true, 64)) {
                for (int rh = 0; rh < (hitsFound - oldTotal) && rh < 64; rh++) {
                    if (regionHits[rh] && s_midHitCount < MAX_MID_HITS) {
                        s_midHits[s_midHitCount].addr     = regionHits[rh];
                        s_midHits[s_midHitCount].writable = true;
                        s_midHitCount++;
                        midLog("[MID-AUTO] HIT #%d at 0x%llX regionBase=0x%llX size=0x%llX",
                               hitsFound, (unsigned long long)regionHits[rh],
                               (unsigned long long)mbi.BaseAddress,
                               (unsigned long long)regionSize);
                    }
                }
            }
        }
        addr = regionEnd;
    }

    midLog("[MID-AUTO] === SCAN DONE === pages=%d hits=%d stored=%d", pagesScanned, hitsFound, s_midHitCount);
    s_midScanDone.store(true);
    s_midScanRunning.store(false);
}

static void LaunchMidScanAsync() {
    if (s_midScanDone.load() || s_midScanRunning.load()) return;
    std::thread([]() {
        TryAutoDetectMissionId();
    }).detach();
    midLog("[MID-AUTO] Background scan thread launched");
}

static bool WriteMidUUID() {
    if (s_midHitCount == 0) return false;

    char fresh[64];
    GenerateUUID(fresh);
    int freshLen = (int)strlen(fresh);
    int written = 0;

    for (int i = 0; i < s_midHitCount; i++) {
        uintptr_t a = s_midHits[i].addr;
        if (!SafeReadable((void*)a, 48)) {
            midLog("[WRITE-MID] hit[%d] 0x%llX not readable — skip", i, (unsigned long long)a);
            continue;
        }
        if (SafeWriteUUID(a, fresh, freshLen)) {
            written++;
        } else {
            midLog("[WRITE-MID] hit[%d] 0x%llX write failed — skip", i, (unsigned long long)a);
        }
    }

    midLog("[WRITE-MID] Wrote \"%s\" to %d/%d hits", fresh, written, s_midHitCount);
    return written > 0;
}

static CONTEXT  s_replaySavedCtx;
static std::atomic<bool> s_replayCrashed{false};
static bool     s_vehArmed   = false;
static DWORD    s_vehTid     = 0;
static DWORD    s_crashCode  = 0;
static uintptr_t s_crashIP   = 0;
static uintptr_t s_crashFault= 0;

static LONG CALLBACK VehHandler(EXCEPTION_POINTERS* ep) {
    if (!s_vehArmed) return EXCEPTION_CONTINUE_SEARCH;
    if (GetCurrentThreadId() != s_vehTid) return EXCEPTION_CONTINUE_SEARCH;

    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD exCode = ep->ExceptionRecord->ExceptionCode;
    if (exCode == EXCEPTION_ACCESS_VIOLATION || exCode == 0xC0000094
        || exCode == 0xC0000095  || exCode == 0xC000008E
        || exCode == 0xC00000FD ) {

        s_crashCode  = exCode;
        s_crashIP    = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
        s_crashFault = (ep->ExceptionRecord->NumberParameters >= 2)
                       ? ep->ExceptionRecord->ExceptionInformation[1] : 0;
        s_vehArmed = false;
        s_vehTid   = 0;
        s_replayCrashed.store(true);
        memcpy(ep->ContextRecord, &s_replaySavedCtx, sizeof(CONTEXT));
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static PVOID s_vehHandle = nullptr;

static CONTEXT  s_scSavedCtx;
static std::atomic<bool> s_scCrashed{false};
static bool     s_scVehArmed   = false;
static DWORD    s_scCallerTid  = 0;
std::atomic<bool> s_scEverFired{false};

static LONG WINAPI ScVehHandler(EXCEPTION_POINTERS* ep) {
    if (!s_scVehArmed) return EXCEPTION_CONTINUE_SEARCH;

    if (ep->ExceptionRecord->ExceptionCode == 0xC00000FD) return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)  return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)    return EXCEPTION_CONTINUE_SEARCH;
    DWORD exCode = ep->ExceptionRecord->ExceptionCode;

    if (exCode == EXCEPTION_ACCESS_VIOLATION || exCode == 0xC0000094
        || exCode == 0xC0000095  || exCode == 0xC000008E ) {
        if (GetCurrentThreadId() != s_scCallerTid) return EXCEPTION_CONTINUE_SEARCH;

        s_scVehArmed = false;
        s_scCrashed.store(true);
        memcpy(ep->ContextRecord, &s_scSavedCtx, sizeof(CONTEXT));
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static PVOID s_scVehHandle = nullptr;

bool g_offlineBoostMode = false;

static ULONG_PTR __cdecl FakeEntityNoOp(void*,void*,void*,void*) { return 0; }

static void*  s_fakeVtableMem    = nullptr;
static void*  s_fakeEntityMem    = nullptr;
static void*  s_fakeFixupMem     = nullptr;
static bool   s_fakeEntityInited = false;
static LPVOID s_scRetStub        = nullptr;
static void InitFakeEntity();

void* GetFakeEntityPtr()
{
    if (!s_fakeEntityInited) InitFakeEntity();
    return s_fakeEntityMem;
}

void* GetFakeFixupPtr()
{
    if (!s_fakeEntityInited) InitFakeEntity();
    return s_fakeFixupMem;
}

void* GetRetStubPtr()
{
    if (!s_fakeEntityInited) InitFakeEntity();
    return s_scRetStub;
}

void* GetFakeVtablePtr()
{
    if (!s_fakeEntityInited) InitFakeEntity();
    return s_fakeVtableMem;
}

void* GetScRetStub()
{
    if (!s_fakeEntityInited) InitFakeEntity();
    return s_scRetStub;
}

static void InitFakeEntity() {
    if (s_fakeEntityInited) return;

    s_scRetStub = VirtualAlloc(nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (s_scRetStub) {
        BYTE* p = (BYTE*)s_scRetStub;
        p[0] = 0x48; p[1] = 0x31; p[2] = 0xC0;
        p[3] = 0xC3;
    }

    s_fakeVtableMem = VirtualAlloc(nullptr, 2048 * sizeof(void*),
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (s_fakeVtableMem) {
        void** tbl = (void**)s_fakeVtableMem;
        for (int i = 0; i < 2048; i++) tbl[i] = (void*)FakeEntityNoOp;
    }

    s_fakeEntityMem = VirtualAlloc(nullptr, 65536,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE);
    if (s_fakeEntityMem && s_fakeVtableMem)
        *(void**)s_fakeEntityMem = s_fakeVtableMem;

    s_fakeFixupMem = VirtualAlloc(nullptr, 65536,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
    if (s_fakeFixupMem && s_fakeVtableMem)
        *(void**)s_fakeFixupMem = s_fakeVtableMem;

    s_fakeEntityInited = true;
}

static std::atomic<bool>     s_apcGuard{false};
static std::atomic<uint64_t> s_apcGuardSetAt{0};
static std::atomic<uint64_t> s_lastReplayDoneAt{0};
std::atomic<bool>  g_burstActive{false};
std::atomic<int>   g_burstSent{0};
std::atomic<int>   g_burstTotal{0};
std::atomic<bool>  g_burstDone{false};

static std::atomic<bool>     s_scStopFlag{false};
static std::atomic<bool>     s_scEnabled{false};
static bool                  s_scFirstBatchDone = false;
static int                   s_scBatchCount = 0;

static constexpr int         MAX_CANON_HITS = 64;
static uintptr_t             s_canonHits[MAX_CANON_HITS] = {};
static int                   s_canonHitCount = 0;

static std::mutex   s_scIdsMutex;
static uint64_t     s_scIds[4]  = {};
static int          s_scIdCount = 0;
static std::atomic<bool>     s_maxXpEnabled{false};
static HANDLE                s_scThread = nullptr;
static std::atomic<ULONGLONG> s_scHeartbeat{0};
static std::atomic<bool>     s_scSpawning{false};

static std::atomic<bool> s_scAutoSync{false};
static std::thread       s_scAutoSyncThread;
static std::atomic<bool> s_scAutoSyncStop{false};

static std::atomic<bool>     s_scMedalsEnabled{false};
static std::atomic<bool>     s_scMedalsOnly{false};
static std::atomic<bool>     s_medalBurst{false};
static std::atomic<ULONGLONG> s_scCdEndTick{0};

struct DeferEntry { char* ptr; ULONGLONG allocTime; };
static DeferEntry            s_deferQ[256]   = {};
static int                   s_deferHead     = 0;
static CRITICAL_SECTION      s_deferLock;
static bool                  s_deferLockInit = false;

static void DeferFree(char* ptr) {
    if (!ptr || !s_deferLockInit) { delete[] ptr; return; }
    EnterCriticalSection(&s_deferLock);
    int slot = s_deferHead % 256;
    if (s_deferQ[slot].ptr) { delete[] s_deferQ[slot].ptr; }
    s_deferQ[slot] = { ptr, GetTickCount64() };
    s_deferHead++;
    LeaveCriticalSection(&s_deferLock);
}

static DWORD WINAPI DeferFreeThread(LPVOID) {
    while (true) {
        Sleep(30000);
        if (!s_deferLockInit) continue;
        EnterCriticalSection(&s_deferLock);
        ULONGLONG now = GetTickCount64();
        for (int i = 0; i < 256; i++) {
            if (s_deferQ[i].ptr && (now - s_deferQ[i].allocTime) > 120000ULL) {
                delete[] s_deferQ[i].ptr;
                s_deferQ[i].ptr = nullptr;
            }
        }
        LeaveCriticalSection(&s_deferLock);
    }
    return 0;
}
static std::atomic<int>      s_scCallsMade{0};
static std::atomic<bool>     s_scApcPending{false};
static std::atomic<int>      s_scConsecFails{0};
static std::atomic<int>      s_scSkippedCalls{0};
static std::atomic<int>      s_scGoal{0};
static std::atomic<ULONGLONG> s_scLastCallSentAt{0};
static std::atomic<ULONGLONG> s_scTimerEndMs{0};

static uint32_t GenerateRandomObjectId() {
    GUID g; CoCreateGuid(&g);
    uint32_t v;
    memcpy(&v, &g, 4);
    return v;
}

static std::atomic<int>      s_scCooldown{0};
static std::atomic<int>      s_scIntervalMs{500};

static void NTAPI ScActivityAPC(ULONG_PTR actObjPtr, ULONG_PTR, ULONG_PTR);

void* Replay_GetScApcCallback() { return (void*)ScActivityAPC; }

struct ScDelayedCheckArgs {
    uintptr_t serverInfo;
    uint32_t  counterBefore;
    uint8_t   flagBefore;
    uint32_t  ringBefore;
    uint8_t   queueSnapshot[256];
    char      urlBefore[64];
};

static DWORD WINAPI ScDelayedMonitor(LPVOID p) {
    ScDelayedCheckArgs* a = (ScDelayedCheckArgs*)p;
    uintptr_t si = a->serverInfo;

    for (int sec = 2; sec <= 10; sec += 2) {
        Sleep(500);

        uint32_t counter = *(uint32_t*)(si + GetSICtrOff());
        uint8_t  flag    = *(uint8_t*)(si + GetSIFlagOff());
        uint32_t ringIdx = *(uint32_t*)(si + GS::OFF_RING_INDEX);

        char urlNow[64] = {};
        memcpy(urlNow, (void*)(si + GetSIUrlOff()), 60);
        urlNow[60] = 0;

        uint8_t qNow[256];
        ReadProcessMemory(GetCurrentProcess(), (void*)(si + GetSIQueueOff()), qNow, 256, nullptr);
        int qDelta = 0;
        for (int i = 0; i < 256; i++)
            if (a->queueSnapshot[i] != qNow[i]) qDelta++;

        sc_dbg("  AFTER(%ds): ctr=0x%X flag=0x%X ring=%u qDelta=%d url=\"%.40s\"",
               sec, counter, flag, ringIdx, qDelta, urlNow);
    }

    delete a;
    return 0;
}

static void NTAPI ScActivityAPC(ULONG_PTR actObjPtr, ULONG_PTR, ULONG_PTR) {
    s_scApcPending.store(false, std::memory_order_release);
    sc_dbg("=== ScActivityAPC === actObj=%p TID=%u", (void*)actObjPtr, GetCurrentThreadId());

    if (!License::IsUnlocked()) { sc_dbg("  BAIL: license"); return; }

    char* actObj = (char*)actObjPtr;
    if (!actObj) { sc_dbg("  BAIL: actObj NULL"); return; }

    uintptr_t base = g_state.gameBase;
    if (!base) { sc_dbg("  BAIL: gameBase 0"); return; }

    auto SafeRead8 = [](uintptr_t addr) -> uintptr_t {
        uintptr_t val = 0;
        SIZE_T rd = 0;
        ReadProcessMemory(GetCurrentProcess(), (void*)addr, &val, 8, &rd);
        return val;
    };
    uintptr_t sfPtr = SafeRead8(base + GS::rv_gp1);
    if (!sfPtr) { sc_dbg("  BAIL: SerFactory 0"); return; }
    if (!SafeRead8(sfPtr)) { sc_dbg("  BAIL: *SerFactory 0"); return; }

    uint32_t actId32 = 0;
    memcpy(&actId32, actObj + 0x28, 4);

    uintptr_t serverInfo = SafeRead8(base + GS::rv_gp4);
    if (!serverInfo) {
        sc_dbg("  BAIL: serverInfo NULL");
        g_scCallInFlight.store(false, std::memory_order_release);
        return;
    }

    uintptr_t actFnAddr = base + GS::rv_fn1;

    static bool s_httpHooksInstalled = false;
    if (!s_httpHooksInstalled) {
        s_httpHooksInstalled = true;
        HttpMonitor::InstallWinHttpHooks();
    }

    static bool s_actFnDumped = false;
    if (!s_actFnDumped) {
        s_actFnDumped = true;
        sc_dbg_hex("  actFn_code", (void*)actFnAddr, 256);
    }

    {
        bool sessionOK = false;
        uint8_t opCheck = *(uint8_t*)(actFnAddr + 0x91);
        if (opCheck == 0x48) {
            int32_t sessionDisp = *(int32_t*)(actFnAddr + 0x94);
            uintptr_t sessionGlobAddr = actFnAddr + 0x98 + sessionDisp;
            uintptr_t singleton = SafeRead8(sessionGlobAddr);

            if (singleton) {
                uintptr_t obj = SafeRead8(singleton + 0x10);
                if (obj) {
                    uintptr_t getSessionFuncPtr = SafeRead8(obj + GetSessionDispatch());
                    if (getSessionFuncPtr) {
                        typedef uintptr_t (__fastcall *GetActiveSessionFn)(uintptr_t, uintptr_t);
                        auto getActiveSession = (GetActiveSessionFn)getSessionFuncPtr;
                        uintptr_t session = getActiveSession(singleton, obj);

                        sc_dbg("  GetActiveSession() = 0x%llX — %s",
                               (unsigned long long)session,
                               session ? "HAS SESSION" : "NULL SESSION");

                        sessionOK = (session != 0);
                    }
                }
            }
        } else {

            sc_dbg("  session: can't decode (opcode 0x%02X) — proceeding anyway", opCheck);
            sessionOK = true;
        }

        if (!sessionOK) {
            sc_dbg("  SKIP: No active session — call would get 0 SC");
            g_state.AddReplayLog("SC skip: no session", false);
            HttpMonitor_SetCallResult(2);
            g_scCallInFlight.store(false, std::memory_order_release);
            return;
        }
    }

    {
        uint8_t opCheck2 = *(uint8_t*)(actFnAddr + 0x2A);
        if (opCheck2 == 0x48) {
            int32_t g2Disp = *(int32_t*)(actFnAddr + 0x2D);
            uintptr_t g2Addr = actFnAddr + 0x31 + g2Disp;
            uintptr_t g2Val = SafeRead8(g2Addr);
            sc_dbg("  global2(rsi): disp=%d addr=0x%llX val=0x%llX",
                   g2Disp, (unsigned long long)g2Addr, (unsigned long long)g2Val);
        }
    }

    uint32_t ctrBefore  = *(uint32_t*)(serverInfo + GetSICtrOff());
    uint8_t  flagBefore = *(uint8_t*)(serverInfo + GetSIFlagOff());
    uint32_t ringBefore = *(uint32_t*)(serverInfo + GS::OFF_RING_INDEX);
    char urlBefore[64] = {};
    memcpy(urlBefore, (void*)(serverInfo + GetSIUrlOff()), 60);
    urlBefore[60] = 0;

    uint8_t qBefore[256];
    ReadProcessMemory(GetCurrentProcess(), (void*)(serverInfo + GetSIQueueOff()), qBefore, 256, nullptr);

    sc_dbg("  BEFORE: ctr=0x%X flag=0x%X ring=%u url=\"%.40s\"",
           ctrBefore, flagBefore, ringBefore, urlBefore);
    sc_dbg_hex("  q_before[0x1050]", qBefore, 64);

    sc_dbg("  calling actFn=0x%llX  actId32=0x%08X  (NORMAL — no bypass)",
           (unsigned long long)actFnAddr, actId32);

    g_scCallInFlight.store(true, std::memory_order_release);
    s_scEverFired.store(true);
    s_scCallerTid = GetCurrentThreadId();

    s_scCrashed.store(false);
    RtlCaptureContext(&s_scSavedCtx);
    if (s_scCrashed.load()) {
        s_scVehArmed = false;
        g_scCallInFlight.store(false, std::memory_order_release);
        sc_dbg("  *** VEH recovered crash ***");
        g_state.AddLog("[SC] VEH recovered crash", true);
        return;
    }

    HMODULE hGameDll = GetModuleHandleA("game.dll");
    if (!hGameDll) {
        sc_dbg("  BAIL: game.dll not loaded");
        g_scCallInFlight.store(false, std::memory_order_release);
        return;
    }

    uintptr_t activityFnAddr = (uintptr_t)hGameDll + GetActivityFnRVA();

    uint8_t* prologueCheck = (uint8_t*)activityFnAddr;
    if (prologueCheck[0] != 0x4C || prologueCheck[1] != 0x8B || prologueCheck[2] != 0xDC) {
        sc_dbg("  BAIL: Activity func prologue mismatch! Got %02X %02X %02X",
               prologueCheck[0], prologueCheck[1], prologueCheck[2]);
        g_scCallInFlight.store(false, std::memory_order_release);
        return;
    }

    uint32_t objId = 0, playerCount = 0;
    memcpy(&objId, actObj + 0x2C, 4);
    memcpy(&playerCount, actObj + 0x24, 4);
    void* playerIdBuf = actObj + 0x30;

    sc_dbg("  Activity call: fn=0x%llX actId32=0x%08X objId=0x%08X players=%u",
           (unsigned long long)activityFnAddr, actId32, objId, playerCount);

    typedef uint64_t (*ActivityFunc_t)(void*, uint32_t, uint32_t, void*, uint32_t);
    auto activityFn = (ActivityFunc_t)activityFnAddr;

    uint64_t retVal = 0;

    s_scVehArmed = true;
    retVal = activityFn(nullptr, actId32, objId, playerIdBuf, playerCount);
    s_scVehArmed = false;
    g_scCallInFlight.store(false, std::memory_order_release);

    uint32_t ctrAfter  = *(uint32_t*)(serverInfo + GetSICtrOff());
    uint8_t  flagAfter = *(uint8_t*)(serverInfo + GetSIFlagOff());
    uint32_t ringAfter = *(uint32_t*)(serverInfo + GS::OFF_RING_INDEX);
    char urlAfter[64] = {};
    memcpy(urlAfter, (void*)(serverInfo + GetSIUrlOff()), 60);
    urlAfter[60] = 0;

    uint8_t qAfter[256];
    ReadProcessMemory(GetCurrentProcess(), (void*)(serverInfo + GetSIQueueOff()), qAfter, 256, nullptr);

    int qChanges = 0;
    for (int i = 0; i < 256; i++)
        if (qBefore[i] != qAfter[i]) qChanges++;

    sc_dbg("  AFTER(0s): ctr=0x%X flag=0x%X ring=%u rax=0x%llX url=\"%.40s\" qDelta=%d",
           ctrAfter, flagAfter, ringAfter,
           (unsigned long long)retVal, urlAfter, qChanges);
    sc_dbg_hex("  q_after[0x1050]", qAfter, 64);

    {
        uintptr_t reqBufPtr = SafeRead8(serverInfo + GetSIReqBufOff());
        sc_dbg("  req_buf_ptr=0x%llX", (unsigned long long)reqBufPtr);
        if (reqBufPtr) {

            sc_dbg_hex("  req_buf[0x000]", (void*)reqBufPtr, 128);
            sc_dbg_hex("  req_buf[0x080]", (void*)(reqBufPtr + 0x80), 128);
            sc_dbg_hex("  req_buf[0x100]", (void*)(reqBufPtr + 0x100), 64);

            sc_dbg_hex("  req_buf[0xC00]", (void*)(reqBufPtr + 0xC00), 96);
        }
    }

    sc_dbg_hex("  SI[0x440]", (void*)(serverInfo + 0x440), 128);

    ScDelayedCheckArgs* dca = new ScDelayedCheckArgs;
    dca->serverInfo = serverInfo;
    dca->counterBefore = ctrBefore;
    dca->flagBefore = flagBefore;
    dca->ringBefore = ringBefore;
    memcpy(dca->queueSnapshot, qAfter, 256);
    memcpy(dca->urlBefore, urlBefore, 64);
    CreateThread(nullptr, 0, ScDelayedMonitor, dca, 0, nullptr);

    g_state.AddLog("[SC] actFn called — monitoring 10s");
}

static DWORD WINAPI ScLoopThread(LPVOID) {

    ScGuard::RegisterOwnThread(GetCurrentThreadId());

    ULONG stackGuarantee = 128 * 1024;
    SetThreadStackGuarantee(&stackGuarantee);

    while (true) {
    s_scHeartbeat.store(GetTickCount64());
    try {
    const uint32_t ACT_ID32 = 2140130854u;
    const uint32_t MEDAL_ACT_ID32 = 170839374u;
    bool medalTurn = false;

    while (!s_scStopFlag.load()) {

        {
            int goal = s_scGoal.load();
            if (goal > 0 && HttpMonitor_GetActSCEarned() >= goal) {
                g_state.AddReplayLog("SC goal reached — stopping", false);
                midLog("[SC] Goal of %d SC reached — auto-stopping", goal);
                s_scEnabled.store(false);
                continue;
            }
        }

        if (!s_scEnabled.load()) { Sleep(500); continue; }

        if (ScGuard::ShouldBackoff()) {
            for (int i = 0; i < 60 && !s_scStopFlag.load(); i++) {
                Sleep(500);
                s_scHeartbeat.store(GetTickCount64());
            }
            ScGuard::ResetBackoff();
            continue;
        }

        char    missionId[64] = {};
        uint8_t pidBuf[32]    = {};
        int     pidCount      = 0;
        {
            std::lock_guard<std::mutex> lk(s_scIdsMutex);
            for (int pi = 0; pi < s_scIdCount && pi < 4; pi++) {
                if (s_scIds[pi] != 0) {
                    memcpy(pidBuf + pidCount * 8, &s_scIds[pi], 8);
                    pidCount++;
                }
            }
        }

        if (pidCount == 0) {
            std::lock_guard<std::mutex> capLk(g_state.captureMutex);
            if (!g_state.captures.empty() && g_state.captures[0].valid &&
                !g_state.captures[0].missionDataSnapshot.empty()) {
                const auto& md = g_state.captures[0].missionDataSnapshot;
                for (int i = 0; i < 4; i++) {
                    size_t off = 0x0068 + (size_t)i * 0x30 + 0x00;
                    if (off + 8 <= md.size()) {
                        uint64_t id = 0;
                        memcpy(&id, md.data() + off, 8);
                        if (id != 0) {
                            memcpy(pidBuf + pidCount * 8, &id, 8);
                            pidCount++;
                        }
                    }
                }
            }
        }
        if (pidCount == 0) {
            g_state.AddLog("[SC] No data", true);
            Sleep(5000);
            continue;
        }

        if (s_apcGuard.load() || g_state.replayInProgress.load()) {
            Sleep(500);
            continue;
        }

        {
            ULONGLONG endMs = s_scTimerEndMs.load();
            if (endMs != 0 && GetTickCount64() >= endMs) {
                Sleep(500);
                continue;
            }
        }

        if (!s_scFirstBatchDone) {
            s_scFirstBatchDone = true;
            s_scBatchCount = 1;
            midLog("[SC] First batch starting — in-mission mode (game provides missionId)");
        } else {
            s_scBatchCount++;
        }

        bool doMedals = s_scMedalsOnly.load() || (medalTurn && s_scMedalsEnabled.load());
        uint32_t batchActId = doMedals ? MEDAL_ACT_ID32 : ACT_ID32;
        s_medalBurst.store(doMedals);

        g_state.AddReplayLog(doMedals ? "Medal Batch Firing" : "SC Batch Firing", false);

        for (int b = 0; b < 9 && !s_scStopFlag.load() && s_scEnabled.load(); ) {

            {
                ULONGLONG endMs = s_scTimerEndMs.load();
                if (endMs != 0 && GetTickCount64() >= endMs) break;
            }

            s_scHeartbeat.store(GetTickCount64());

            int retries = 0;
            const int MAX_RETRIES = 0;

            for (;;) {
            {

                GenerateUUID(missionId);
                const size_t midLen2 = strnlen(missionId, sizeof(missionId));
                uint32_t objId = GenerateRandomObjectId();

                if (g_state.replayInProgress.load()) { s_scSkippedCalls.fetch_add(1); Sleep(500); break; }
                {
                    uint64_t lastDone = s_lastReplayDoneAt.load();
                    if (lastDone != 0 && (GetTickCount64() - lastDone) < 3000) {
                        s_scSkippedCalls.fetch_add(1);
                        Sleep(500);
                        break;
                    }
                }

                for (int w = 0; w < 40 && s_scApcPending.load(); w++) {
                    Sleep(250);
                    if (s_scStopFlag.load()) break;
                }
                if (s_scApcPending.load()) {
                    s_scApcPending.store(false);

                    break;
                }

                for (int w = 0; w < 20 && g_scCallInFlight.load(); w++) {
                    Sleep(100);
                    if (s_scStopFlag.load()) break;
                }

                char* actObj = new (std::nothrow) char[8192]();
                if (!actObj) {
                    sc_dbg("SCLoop: alloc FAILED");
                    Sleep(1000);
                    break;
                }
                memcpy(actObj + 1,    missionId, (midLen2 < 62 ? midLen2 : 62) + 1);
                uint32_t pc32 = (uint32_t)pidCount;
                memcpy(actObj + 0x24, &pc32, 4);
                memcpy(actObj + 0x28, &batchActId, 4);
                memcpy(actObj + 0x2C, &objId,    4);
                memcpy(actObj + 0x30, pidBuf, (size_t)pidCount * 8);

                sc_dbg("SCLoop[%d]: actObj=%p missionId=%s actId32=0x%08X objId=0x%08X pids=%d (retry=%d)",
                       b, actObj, missionId, batchActId, objId, pidCount, retries);
                for (int pi = 0; pi < pidCount; pi++) {
                    uint64_t pid = 0;
                    memcpy(&pid, pidBuf + pi * 8, 8);
                    sc_dbg("  pid[%d]=0x%016llX", pi, (unsigned long long)pid);
                }
                sc_dbg_hex("  actObj[0..0x7F]", actObj, 128);

                int strWrote = 0, binWrote = 0;
                {
                    const char* fresh = missionId;

                    if (s_structHitValid && s_structHitAddr) {
                        if (SafeWriteUUID(s_structHitAddr, fresh, 36)) strWrote = 1;
                    } else if (s_canonHitCount > 0) {
                        for (int h = 0; h < s_canonHitCount; h++) {
                            if (SafeWriteUUID(s_canonHits[h], fresh, 36)) strWrote++;
                        }
                        unsigned char freshLE[16], freshBE[16];
                        bool madeLE = UuidToGuidLE(fresh, freshLE);
                        bool madeBE = UuidToRawBE(fresh, freshBE);
                        for (int h = 0; h < s_canonBinHitCount; h++) {
                            const unsigned char* bytes = s_canonBinHits[h].isLE ? freshLE : freshBE;
                            if (s_canonBinHits[h].isLE ? madeLE : madeBE) {
                                if (SafeWriteUUID(s_canonBinHits[h].addr, (const char*)bytes, 16)) binWrote++;
                            }
                        }
                    } else {

                        uintptr_t ggRVA = GetGameGlobalRVA();
                        uint32_t midOff = GetMissionIdOffset();
                        if (ggRVA && midOff && g_state.gameBase) {
                            uintptr_t ggPtr = SafeReadPtr(g_state.gameBase + ggRVA);
                            if (ggPtr) {
                                uintptr_t uuidAddr = ggPtr + midOff;
                                if (SafeWriteUUID(uuidAddr, fresh, 36)) strWrote = 1;
                                midLog("[SC] MIDSWAP FALLBACK: wrote to GG+0x%X → 0x%llX",
                                       midOff, (unsigned long long)uuidAddr);
                            }
                        }
                    }
                    midLog("[SC] MIDSWAP call %d/%d: str=%d bin=%d — mid=%s",
                           b + 1, 9, strWrote, binWrote, fresh);
                }

                ScLimit::ForceUUID(missionId);

                if (strWrote == 0 && binWrote == 0) {
                    ActivatePostSwap(missionId);
                    sc_dbg("SCLoop[%d]: MIDSWAP FAILED — POST swap activated", b);
                } else {
                    DeactivatePostSwap();
                }

                HttpMonitor_ClearCallResult();

                {
                    s_scApcPending.store(true, std::memory_order_release);
                    ScGuard::NotifyScApc(g_state.gameThreadId);
                    if (ScPresent::QueueSC(actObj)) {
                        ScTracker::AddCall();
                        sc_dbg("SCLoop[%d]: QueueSC OK", b);
                    } else {
                        s_scApcPending.store(false);
                        sc_dbg("SCLoop[%d]: QueueSC FAILED", b);
                    }
                    DeferFree(actObj);
                }
                s_scCallsMade.fetch_add(1);
                s_scLastCallSentAt.store(GetTickCount64());
                s_scConsecFails.store(0);
            }

            {
                int result = 0;
                for (int w = 0; w < 50 && !s_scStopFlag.load(); w++) {
                    Sleep(100);
                    result = HttpMonitor_GetCallResult();
                    if (result != 0) break;
                }

                if (result == 1) {

                    if (retries > 0)
                        HttpMonitor_AddRetryRecovered();
                    break;
                }

                if (retries < MAX_RETRIES && !s_scStopFlag.load()) {
                    retries++;
                    const char* reason = (result == 0) ? "TIMEOUT" : "EMPTY";
                    sc_dbg("SCLoop[%d]: %s — retry #%d/%d", b, reason, retries, MAX_RETRIES);
                    if (retries == 1)
                        g_state.AddReplayLog("SC retry — recovering", false);

                    Sleep(retries > 5 ? 500 : 200);
                    continue;
                }

                if (retries > 0)
                    HttpMonitor_AddRetryFailed();
                sc_dbg("SCLoop[%d]: gave up after %d retries", b, retries);
                break;
            }

            DeactivatePostSwap();

            }

            b++;

            {
                int baseMs = s_scIntervalMs.load();
                int jitter = (int)(baseMs * 0.2);
                int totalMs = baseMs + (rand() % (2 * jitter + 1)) - jitter;
                if (totalMs < 100) totalMs = 100;
                int ticks = totalMs / 250;
                int remainder = totalMs % 250;
                for (int i = 0; i < ticks && !s_scStopFlag.load(); i++)
                    Sleep(250);
                if (remainder > 0 && !s_scStopFlag.load())
                    Sleep(remainder);
            }
        }

        s_medalBurst.store(false);
        midLog("[SC] %s batch done — cooldown starting", doMedals ? "MEDAL" : "SC");

        if (s_scMedalsEnabled.load()) medalTurn = !medalTurn;

        {
            s_scCooldown.store(1);
            s_scCdEndTick.store(GetTickCount64() + 58000);
            g_state.AddReplayLog("SC cooldown 58s", false);

            for (int cd = 0; cd < 116 && !s_scStopFlag.load() && s_scEnabled.load(); cd++) {
                Sleep(500);
                s_scHeartbeat.store(GetTickCount64());
            }

            s_scCooldown.store(0);
        }
#if 0
        {
            s_scCooldown.store(1);
            g_state.AddReplayLog("SC cooldown 45s", false);

            if (s_scBatchCount == 1 && HasGoldenMissionId()) {
                midLog("[SC] Cooldown: waiting 5s for temp buffer cleanup...");
                for (int w = 0; w < 10 && !s_scStopFlag.load(); w++) {
                    Sleep(500);
                    s_scHeartbeat.store(GetTickCount64());
                }

                const char* golden = GetGoldenMissionId();
                int gLen = (int)strlen(golden);
                midLog("[SC] === SYNC SCAN START === golden=\"%s\" len=%d", golden, gLen);

                uintptr_t gameBase = g_state.gameBase;
                uintptr_t globalPtr = 0;
                if (gameBase) {
                    globalPtr = SafeReadPtr(gameBase + GetGameGlobalRVA());
                }
                midLog("[SC] gameBase=0x%llX globalPtr=0x%llX", (unsigned long long)gameBase, (unsigned long long)globalPtr);

                uintptr_t goldenBufAddr = (uintptr_t)golden;

                SYSTEM_INFO si; GetSystemInfo(&si);
                uintptr_t scanAddr = (uintptr_t)si.lpMinimumApplicationAddress;
                uintptr_t scanEnd  = (uintptr_t)si.lpMaximumApplicationAddress;

                s_canonHitCount = 0;
                s_structHitAddr = 0;
                s_structHitValid = false;
                int totalHits = 0;
                ULONGLONG scanStart = GetTickCount64();
                constexpr ULONGLONG SCAN_TIMEOUT_MS = 30000;

                MEMORY_BASIC_INFORMATION mbi{};
                int pagesScanned = 0;
                for (uintptr_t addr = scanAddr; addr < scanEnd; ) {
                    if (pagesScanned % 500 == 0 && (GetTickCount64() - scanStart) > SCAN_TIMEOUT_MS) {
                        midLog("[SC] SCAN TIMEOUT after 30s — pages=%d hits=%d", pagesScanned, s_canonHitCount);
                        break;
                    }
                    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) {
                        addr += 0x10000;
                        continue;
                    }
                    uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

                    if (mbi.State != MEM_COMMIT ||
                        !(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                        addr = regionEnd;
                        continue;
                    }
                    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
                        addr = regionEnd;
                        continue;
                    }
                    pagesScanned++;
                    const char* base = (const char*)mbi.BaseAddress;
                    size_t regionSize = mbi.RegionSize;
                    if (regionSize > (size_t)gLen) {
                        uintptr_t regionHits[64];
                        int beforeTotal = totalHits;
                        if (SafeMemScan(base, regionSize, golden, gLen,
                                        goldenBufAddr, globalPtr,
                                        regionHits, &totalHits, true, 64)) {
                            for (int rh = 0; rh < (totalHits - beforeTotal) && rh < 64; rh++) {
                                if (regionHits[rh] && s_canonHitCount < MAX_CANON_HITS) {
                                    midLog("[SC] SYNC HIT at 0x%llX region=0x%llX size=0x%llX",
                                           (unsigned long long)regionHits[rh],
                                           (unsigned long long)mbi.BaseAddress,
                                           (unsigned long long)regionSize);
                                    s_canonHits[s_canonHitCount++] = regionHits[rh];

                                    if (!s_structHitValid && ValidateMissionStruct(regionHits[rh])) {
                                        s_structHitAddr = regionHits[rh];
                                        s_structHitValid = true;
                                    }
                                }
                            }
                        }
                    }
                    addr = regionEnd;
                }

                midLog("[SC] === STRING SCAN DONE === pages=%d total=%d cached=%d elapsed=%llums",
                       pagesScanned, totalHits, s_canonHitCount,
                       (unsigned long long)(GetTickCount64() - scanStart));

                unsigned char guidLE[16], guidBE[16];
                bool hasLE = UuidToGuidLE(golden, guidLE);
                bool hasBE = UuidToRawBE(golden, guidBE);
                s_canonBinHitCount = 0;

                if (hasLE || hasBE) {
                    midLog("[SC] === BIN SCAN START === LE=%s BE=%s", hasLE?"yes":"no", hasBE?"yes":"no");
                    if (hasLE) {
                        char hexLE[48]; for(int i=0;i<16;i++) sprintf(hexLE+i*3,"%02X ",guidLE[i]);
                        midLog("[SC] LE bytes: %s", hexLE);
                    }
                    if (hasBE) {
                        char hexBE[48]; for(int i=0;i<16;i++) sprintf(hexBE+i*3,"%02X ",guidBE[i]);
                        midLog("[SC] BE bytes: %s", hexBE);
                    }
                    int binTotalLE = 0, binTotalBE = 0;
                    int binPages = 0;
                    ULONGLONG binStart = GetTickCount64();
                    for (uintptr_t addr2 = scanAddr; addr2 < scanEnd; ) {
                        if (binPages % 500 == 0 && (GetTickCount64() - binStart) > 30000) {
                            midLog("[SC] BIN SCAN TIMEOUT — pages=%d", binPages);
                            break;
                        }
                        MEMORY_BASIC_INFORMATION mbi2{};
                        if (VirtualQuery((void*)addr2, &mbi2, sizeof(mbi2)) == 0) {
                            addr2 += 0x10000; continue;
                        }
                        uintptr_t rEnd2 = (uintptr_t)mbi2.BaseAddress + mbi2.RegionSize;
                        if (mbi2.State != MEM_COMMIT ||
                            !(mbi2.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                            addr2 = rEnd2; continue;
                        }
                        if (mbi2.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
                            addr2 = rEnd2; continue;
                        }
                        binPages++;
                        const char* base2 = (const char*)mbi2.BaseAddress;
                        size_t rSize2 = mbi2.RegionSize;
                        if (rSize2 >= 16) {

                            if (hasLE) {
                                uintptr_t rHits[32]; int bTotal = binTotalLE;
                                if (SafeMemScan(base2, rSize2, (const char*)guidLE, 16,
                                                goldenBufAddr, globalPtr, rHits, &binTotalLE, true, 32)) {
                                    for (int rh = 0; rh < (binTotalLE - bTotal) && rh < 32; rh++) {
                                        if (rHits[rh] && s_canonBinHitCount < MAX_CANON_BIN_HITS) {
                                            s_canonBinHits[s_canonBinHitCount].addr = rHits[rh];
                                            s_canonBinHits[s_canonBinHitCount].isLE = true;
                                            s_canonBinHitCount++;
                                            midLog("[SC] BIN-LE HIT at 0x%llX region=0x%llX",
                                                   (unsigned long long)rHits[rh],
                                                   (unsigned long long)mbi2.BaseAddress);
                                        }
                                    }
                                }
                            }

                            if (hasBE && memcmp(guidLE, guidBE, 16) != 0) {
                                uintptr_t rHits[32]; int bTotal = binTotalBE;
                                if (SafeMemScan(base2, rSize2, (const char*)guidBE, 16,
                                                goldenBufAddr, globalPtr, rHits, &binTotalBE, true, 32)) {
                                    for (int rh = 0; rh < (binTotalBE - bTotal) && rh < 32; rh++) {
                                        if (rHits[rh] && s_canonBinHitCount < MAX_CANON_BIN_HITS) {
                                            s_canonBinHits[s_canonBinHitCount].addr = rHits[rh];
                                            s_canonBinHits[s_canonBinHitCount].isLE = false;
                                            s_canonBinHitCount++;
                                            midLog("[SC] BIN-BE HIT at 0x%llX region=0x%llX",
                                                   (unsigned long long)rHits[rh],
                                                   (unsigned long long)mbi2.BaseAddress);
                                        }
                                    }
                                }
                            }
                        }
                        addr2 = rEnd2;
                    }
                    midLog("[SC] === BIN SCAN DONE === pages=%d LE=%d BE=%d binHits=%d elapsed=%llums",
                           binPages, binTotalLE, binTotalBE, s_canonBinHitCount,
                           (unsigned long long)(GetTickCount64() - binStart));
                }

                midLog("[SC] === ALL SCANS COMPLETE === stringHits=%d binHits=%d structValid=%s structAddr=0x%llX",
                       s_canonHitCount, s_canonBinHitCount,
                       s_structHitValid ? "YES" : "NO",
                       (unsigned long long)s_structHitAddr);

                int remainingTicks = 50;
                for (int cd = 0; cd < remainingTicks && !s_scStopFlag.load() && s_scEnabled.load(); cd++) {
                    Sleep(500);
                    s_scHeartbeat.store(GetTickCount64());
                }
            } else {

                for (int cd = 0; cd < 90 && !s_scStopFlag.load() && s_scEnabled.load(); cd++) {
                    Sleep(500);
                    s_scHeartbeat.store(GetTickCount64());
                }
            }

            s_scCooldown.store(0);
        }
#endif

        {
            ULONGLONG lastSent = s_scLastCallSentAt.load();
            if (lastSent != 0 && (GetTickCount64() - lastSent) > 300000ULL) {

                s_scLastCallSentAt.store(GetTickCount64());
            }
        }
    }

    } catch (...) {

    }
    if (!s_scStopFlag.load()) { Sleep(2000); continue; }
    break;
    }
    return 0;
}

static void SC_AutoSyncLoop() {
    while (!s_scAutoSyncStop.load()) {
        if (s_scAutoSync.load()) {

            uint64_t ids[4] = {};
            int count = 0;
            uintptr_t gameBase = (uintptr_t)GetModuleHandleA("game.dll");
            if (gameBase) {
                uintptr_t ptrAddr = gameBase + GS::rv_gp7;
                uintptr_t peerMgr = 0;
                SIZE_T rd = 0;
                if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)ptrAddr, &peerMgr, 8, &rd) && peerMgr != 0) {
                    uint32_t peerCount = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(peerMgr + GetPeerMgrCountOff()), &peerCount, 4, &rd)) {
                        if (peerCount > 4) peerCount = 4;

                        uint32_t scanMax = (peerCount < 4) ? peerCount + 1 : 4;
                        for (uint32_t i = 0; i < scanMax && count < 4; i++) {
                            uintptr_t slotAddr = peerMgr + GetPeerMgrSlotOff() + (uintptr_t)i * 0x20;
                            uint64_t pid = 0;
                            if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)slotAddr, &pid, 8, &rd) && pid != 0) {

                                bool dup = false;
                                for (int d = 0; d < count; d++) {
                                    if (ids[d] == pid) { dup = true; break; }
                                }
                                if (!dup) ids[count++] = pid;
                            }
                        }
                    }
                }
            }

            {
                std::lock_guard<std::mutex> lk(s_scIdsMutex);
                bool changed = (count != s_scIdCount);
                if (!changed) {
                    for (int i = 0; i < count; i++) {
                        if (ids[i] != s_scIds[i]) { changed = true; break; }
                    }
                }
                if (changed && count > 0) {
                    s_scIdCount = 0;
                    memset(s_scIds, 0, sizeof(s_scIds));
                    for (int i = 0; i < count; i++) s_scIds[i] = ids[i];
                    s_scIdCount = count;

                    char buf[128];
                    snprintf(buf, sizeof(buf), "[SC AutoSync] %d player(s) synced", count);
                    g_state.AddLog(buf);
                }
            }
        }

        for (int i = 0; i < 20 && !s_scAutoSyncStop.load(); i++)
            Sleep(100);
    }
}

typedef void (*BuildPayload_t)(uintptr_t serverInfo, uint8_t* slot,
                               const char* uuid, uint8_t* missionData,
                               uint32_t flag);

static void NTAPI ReplayAPC(ULONG_PTR arg1, ULONG_PTR , ULONG_PTR ) {
    if (!License::IsUnlocked()) {
        g_state.AddLog("[R] Auth failed", true);
        g_state.replayInProgress.store(false);
        return;
    }
    openLog();

    bool expected = false;
    if (!s_apcGuard.compare_exchange_strong(expected, true)) {
        g_state.AddLog("[R] Busy");
        return;
    }
    s_apcGuardSetAt.store(GetTickCount64());

    uint8_t* mdBuf = nullptr;
    size_t   mdLen = 0;
    uintptr_t capturedEntityPtr = 0;
    uint32_t capturedWarTime = 0;
    uint64_t captureTickCount = 0;

    uintptr_t origEntityDataVal = 0;
    uintptr_t origEntityVtable  = 0;
    void*  entityDataDeepCopy   = nullptr;

    FieldOverride ov_xp{}, ov_medals{}, ov_slips{};
    bool ok = false;
    {
        std::lock_guard<std::mutex> lk(g_state.captureMutex);
        if (!g_state.captures.empty()) {

            auto& cap = g_state.captures[0];
            if (cap.valid && !cap.missionDataSnapshot.empty()) {
                mdLen = cap.missionDataSnapshot.size();
                mdBuf = (uint8_t*)malloc(mdLen);
                if (mdBuf) {
                    memcpy(mdBuf, cap.missionDataSnapshot.data(), mdLen);
                    if (s_maxXpEnabled.load() && mdLen > 0x38) {
                        uint32_t maxXp = 10000;
                        memcpy(mdBuf + 0x34, &maxXp, sizeof(maxXp));
                    }
                    capturedEntityPtr = cap.entityPtr;
                    capturedWarTime = g_state.capturedWarTime;
                    captureTickCount = g_state.captureTickCount;
                    ov_xp     = cap.xpOverride;
                    ov_medals = cap.medalsOverride;
                    ov_slips  = cap.slipsOverride;

                    origEntityDataVal   = cap.entityDataVal;
                    origEntityVtable    = cap.entityVtable;
                    entityDataDeepCopy  = cap.entityDataDeepCopy;
                    ok = true;
                }
            }
        }
    }

    if (!ok) {
        g_state.AddLog("[R] No data", true);
        s_apcGuard.store(false); s_apcGuardSetAt.store(0); s_lastReplayDoneAt.store(GetTickCount64());
        g_state.replayInProgress.store(false);
        free(mdBuf);
        return;
    }

    uintptr_t base = g_state.gameBase;

    Probe::PauseDR2();

    uintptr_t serverInfo = 0;
    {
        uintptr_t pSI = base + GS::rv_gp4;
        if (SafeReadable((void*)pSI, 8)) serverInfo = *(uintptr_t*)pSI;
    }

    if (!serverInfo) {
        g_state.AddReplayLog("BAIL: no serverInfo", true);
        free(mdBuf);
        s_apcGuard.store(false); s_apcGuardSetAt.store(0); s_lastReplayDoneAt.store(GetTickCount64());
        g_state.replayInProgress.store(false);
        Probe::ResumeDR2();
        closeLog();
        return;
    }

    uint32_t* pRingIdx = (uint32_t*)(serverInfo + GS::OFF_RING_INDEX);
    if (!SafeReadable(pRingIdx, 4)) {
        g_state.AddReplayLog("BAIL: ring index unreadable", true);
        free(mdBuf);
        s_apcGuard.store(false); s_apcGuardSetAt.store(0); s_lastReplayDoneAt.store(GetTickCount64());
        g_state.replayInProgress.store(false);
        Probe::ResumeDR2();
        closeLog();
        return;
    }
    uint32_t curIdx = *pRingIdx;
    uintptr_t slotAddr = serverInfo + GS::OFF_RING_BASE + (uintptr_t)curIdx * GS::RING_SLOT_SIZE;
    *pRingIdx = (curIdx + 1) & GS::RING_SLOT_MASK;
    uint8_t* slot = (uint8_t*)slotAddr;

    *(uint32_t*)(slot + GS::SLOT_SEQUENCE)  = 0;
    *(uintptr_t*)(slot + GS::SLOT_FIXUP)    = 0;
    *(uint32_t*)(slot + GS::SLOT_FIELD_C70) = 0;
    *(uint32_t*)(slot + GS::SLOT_FIELD_C80) = 0;
    *(uint8_t*)(slot + GS::SLOT_FIELD_C84)  = 0;

    {
        uintptr_t entityForSlot = 0;

        if (origEntityDataVal && SafeReadable((void*)origEntityDataVal, sizeof(uintptr_t))) {
            uintptr_t curVtable = *(uintptr_t*)origEntityDataVal;
            if (curVtable == origEntityVtable && origEntityVtable != 0)
                entityForSlot = origEntityDataVal;
        }

        if (!entityForSlot && entityDataDeepCopy)
            entityForSlot = (uintptr_t)entityDataDeepCopy;

        if (!entityForSlot) {
            void* fakeEnt = GetFakeEntityPtr();
            if (fakeEnt)
                entityForSlot = (uintptr_t)fakeEnt;
        }
        *(uintptr_t*)(slot + GS::SLOT_ENTITY_DATA) = entityForSlot;
    }

    char uuid[64] = {};
    GenerateUUID(uuid);

    if (capturedWarTime && mdLen >= 0x3C) {
        uint32_t elapsed = (uint32_t)((GetTickCount64() - captureTickCount) / 1000);
        uint32_t newWT = capturedWarTime + elapsed;

        memcpy(mdBuf + 0x38, &newWT, 4);

        if (mdLen >= 0x28) {
            uint32_t orig24 = 0;
            memcpy(&orig24, mdBuf + 0x24, 4);
            int32_t delta = (int32_t)(orig24 - capturedWarTime);
            uint32_t new24 = newWT + (uint32_t)delta;
            memcpy(mdBuf + 0x24, &new24, 4);
        }
    }

    auto applyOverride = [&](const FieldOverride& ov) {
        if (ov.enabled && ov.offset >= 0 && (size_t)(ov.offset + 4) <= mdLen)
            memcpy(mdBuf + ov.offset, &ov.value, 4);
    };
    applyOverride(ov_xp);
    applyOverride(ov_medals);
    applyOverride(ov_slips);

    {
        auto& wo = g_weaponOverride;

        if (wo.allGunsMode) {
            wo.enabled = true;
            struct AGW { const char* n; uint32_t id; };
            static const AGW kAG[] = {
                { "AR-23 Liberator",                2852344585u },
                { "AR-23P Liberator Penetrator",    1676113140u },
                { "AR-23C Liberator Concussive",    376039023u  },
                { "AR-23A Liberator Carbine",       1160920394u },
                { "AR-48 Truth Whisperer",          2644341380u },
                { "AR-61 Tenderizer",               1920374015u },
                { "BR-14 Adjudicator",              2640366401u },
                { "StA-52 Assault Rifle",           3344526787u },
                { "AR-32 Pacifier",                 3623018063u },
                { "MA5C Assault Rifle",             2564789309u },
                { "AR-2 Coyote",                    400301984u  },
                { "R-2 Amendment",                  3757606668u },
                { "R-63 Diligence",                 2307301438u },
                { "R-63CS Diligence Counter-Sniper",924530093u  },
                { "R-2124 Constitution",            4161086429u },
                { "R-6 Deadeye",                    2104346664u },
                { "MP-98 Knight",                   2161995568u },
                { "SMG-37 Defender",                2821209932u },
                { "SMG-72 Pummeler",                942049262u  },
                { "SMG-32 Reprimand",               725205791u  },
                { "StA-11 SMG",                     1179533432u },
                { "M7S SMG",                        1246313930u },
                { "SG-8 Punisher",                  2088854385u },
                { "SG-8F Punisher Fire of Liberty", 1934208922u },
                { "SG-8S Slugger",                  2246547985u },
                { "SG-451 Cookout",                 1321109120u },
                { "SG-225 Breaker",                 1182300424u },
                { "SG-225SP Breaker Spray&Pray",    3814689025u },
                { "SG-225IE Breaker Incendiary",    3068666625u },
                { "SG-20 Halt",                     122941246u  },
                { "M90A Shotgun",                   3414013062u },
                { "CB-9 Exploding Crossbow",        1942567317u },
                { "R-36 Eruptor",                   339272294u  },
                { "PLAS-39 Accelerator Rifle",      3478892931u },
                { "SG-8P Punisher Plasma",          3955657629u },
                { "ARC-12 Blitzer",                 999487482u  },
                { "LAS-5 Scythe",                   3866352840u },
                { "LAS-16 Sickle",                  1794436168u },
                { "PLAS-1 Scorcher",                925809350u  },
                { "PLAS-101 Purifier",              2887941494u },
                { "LAS-17 Double-Edged Sickle",     309178703u  },
                { "FLAM-66 Torcher",                4108040377u },
                { "JAR-5 Dominator",                2121387072u },
                { "VG-70 Variable",                 469340936u  },
                { "AR-59 Suppressor",               2643754746u },
                { "R-72 Censor",                    838686177u  },
                { "Las-16 Trident",                 2870692210u },
                { "DBS-2 Double Freedom",           3417185725u },
                { "AR/GL-21 One-Two",               3428996225u },
                { "SG-97 Sweeper",                  931633769u  },
                { "SMG/FLAM-34 Stoker",             2011243293u },
            };
            static const int kAGCount = 51;
            int idx = wo.allGunsIndex % kAGCount;
            wo.targetId      = kAG[idx].id;
            wo.selectedIndex = idx;
            strncpy(wo.targetName, kAG[idx].n, sizeof(wo.targetName) - 1);

            wo.allGunsCounter++;
            if (wo.allGunsCounter >= wo.gunsReplaysPerWeapon) {
                wo.allGunsCounter = 0;
                wo.allGunsIndex   = (wo.allGunsIndex + 1) % kAGCount;
            }
            logf("[AllGuns] Weapon: %s (%d/%d), cycle %d/%d\n",
                 wo.targetName, idx + 1, kAGCount, wo.allGunsCounter, wo.gunsReplaysPerWeapon);
        }

        if (wo.forceNextWeapon && wo.selectedGunsMode && wo.selectedGunsCount > 0) {
            wo.forceNextWeapon     = false;
            wo.selectedGunsCounter = 0;
            wo.selectedGunsPos     = (wo.selectedGunsPos + 1) % wo.selectedGunsCount;
            logf("[SelectedGuns] Force-skipped to next weapon (pos %d)\n", wo.selectedGunsPos);
        }

        if (wo.selectedGunsMode && wo.selectedGunsCount > 0) {
            wo.enabled = true;

            struct SGW { const char* n; uint32_t id; };
            static const SGW kSG[] = {
                { "AR-23 Liberator",                2852344585u },
                { "AR-23P Liberator Penetrator",    1676113140u },
                { "AR-23C Liberator Concussive",    376039023u  },
                { "AR-23A Liberator Carbine",       1160920394u },
                { "AR-48 Truth Whisperer",          2644341380u },
                { "AR-61 Tenderizer",               1920374015u },
                { "BR-14 Adjudicator",              2640366401u },
                { "StA-52 Assault Rifle",           3344526787u },
                { "AR-32 Pacifier",                 3623018063u },
                { "MA5C Assault Rifle",             2564789309u },
                { "AR-2 Coyote",                    400301984u  },
                { "R-2 Amendment",                  3757606668u },
                { "R-63 Diligence",                 2307301438u },
                { "R-63CS Diligence Counter-Sniper",924530093u  },
                { "R-2124 Constitution",            4161086429u },
                { "R-6 Deadeye",                    2104346664u },
                { "MP-98 Knight",                   2161995568u },
                { "SMG-37 Defender",                2821209932u },
                { "SMG-72 Pummeler",                942049262u  },
                { "SMG-32 Reprimand",               725205791u  },
                { "StA-11 SMG",                     1179533432u },
                { "M7S SMG",                        1246313930u },
                { "SG-8 Punisher",                  2088854385u },
                { "SG-8F Punisher Fire of Liberty", 1934208922u },
                { "SG-8S Slugger",                  2246547985u },
                { "SG-451 Cookout",                 1321109120u },
                { "SG-225 Breaker",                 1182300424u },
                { "SG-225SP Breaker Spray&Pray",    3814689025u },
                { "SG-225IE Breaker Incendiary",    3068666625u },
                { "SG-20 Halt",                     122941246u  },
                { "M90A Shotgun",                   3414013062u },
                { "CB-9 Exploding Crossbow",        1942567317u },
                { "R-36 Eruptor",                   339272294u  },
                { "PLAS-39 Accelerator Rifle",      3478892931u },
                { "SG-8P Punisher Plasma",          3955657629u },
                { "ARC-12 Blitzer",                 999487482u  },
                { "LAS-5 Scythe",                   3866352840u },
                { "LAS-16 Sickle",                  1794436168u },
                { "PLAS-1 Scorcher",                925809350u  },
                { "PLAS-101 Purifier",              2887941494u },
                { "LAS-17 Double-Edged Sickle",     309178703u  },
                { "FLAM-66 Torcher",                4108040377u },
                { "JAR-5 Dominator",                2121387072u },
                { "VG-70 Variable",                 469340936u  },
                { "AR-59 Suppressor",               2643754746u },
                { "R-72 Censor",                    838686177u  },
                { "Las-16 Trident",                 2870692210u },
                { "DBS-2 Double Freedom",           3417185725u },
                { "AR/GL-21 One-Two",               3428996225u },
                { "SG-97 Sweeper",                  931633769u  },
                { "SMG/FLAM-34 Stoker",             2011243293u },
            };
            int pos    = wo.selectedGunsPos % wo.selectedGunsCount;
            int wIdx   = wo.selectedGunsList[pos];
            wo.targetId      = kSG[wIdx].id;
            wo.selectedIndex = wIdx;
            strncpy(wo.targetName, kSG[wIdx].n, sizeof(wo.targetName) - 1);

            wo.selectedGunsCounter++;
            if (wo.selectedGunsCounter >= wo.gunsReplaysPerWeapon) {
                wo.selectedGunsCounter = 0;
                wo.selectedGunsPos     = (wo.selectedGunsPos + 1) % wo.selectedGunsCount;
            }
            logf("[SelectedGuns] Weapon: %s (slot %d/%d), cycle %d/%d\n",
                 wo.targetName, pos + 1, wo.selectedGunsCount, wo.selectedGunsCounter, wo.gunsReplaysPerWeapon);
        }

        if (wo.enabled && wo.targetId != 0 && mdLen > 0x40) {

            static const uint32_t kPrimaryIds[] = {
                2852344585u, 1676113140u, 376039023u,  1160920394u, 2644341380u,
                1920374015u, 2640366401u, 3344526787u, 3623018063u, 2564789309u,
                400301984u,  3757606668u, 2307301438u, 924530093u,  4161086429u,
                2104346664u, 2161995568u, 2821209932u, 942049262u,  725205791u,
                1179533432u, 1246313930u, 2088854385u, 1934208922u, 2246547985u,
                1321109120u, 1182300424u, 3814689025u, 3068666625u, 122941246u,
                3414013062u, 1942567317u, 339272294u,  3478892931u, 3955657629u,
                999487482u,  3866352840u, 1794436168u, 925809350u,  2887941494u,
                309178703u,  4108040377u, 2121387072u, 469340936u,  2643754746u,
                838686177u,  2870692210u, 3417185725u, 3428996225u, 931633769u,
                2011243293u
            };
            static const int kPrimaryCount = 51;
            int reps = 0;

            for (size_t off = 0; off + 4 <= mdLen; off += 4) {
                uint32_t val;
                memcpy(&val, mdBuf + off, 4);
                if (val == 0) continue;
                for (int ki = 0; ki < kPrimaryCount; ki++) {
                    if (val == kPrimaryIds[ki]) {
                        memcpy(mdBuf + off, &wo.targetId, 4);
                        reps++;
                        break;
                    }
                }
            }
            wo.lastReplacements = reps;
            if (reps > 0) {
                logf("[WeaponOvr] Patched %d weapon slot(s) -> ID %u (%s)\n",
                     reps, (unsigned)wo.targetId, wo.targetName);
            } else {
                logf("[WeaponOvr] No known weapon IDs found in mdBuf (%zu bytes)\n", mdLen);
            }
        }
    }

    {
        uint64_t lobbyIds[4] = {};
        int lobbyCount = 0;
        {
            std::lock_guard<std::mutex> lk(s_scIdsMutex);
            lobbyCount = s_scIdCount;
            for (int i = 0; i < lobbyCount && i < 4; i++)
                lobbyIds[i] = s_scIds[i];
        }
        if (lobbyCount > 0) {
            for (int i = 0; i < 4; i++) {
                uint64_t pid = (i < lobbyCount) ? lobbyIds[i] : 0;

                size_t loopOff = 0x2C8 + (size_t)i * 0x40;
                if (loopOff + 8 <= mdLen)
                    memcpy(mdBuf + loopOff, &pid, 8);

                size_t compOff = 0x0068 + (size_t)i * 0x30;
                if (compOff + 8 <= mdLen)
                    memcpy(mdBuf + compOff, &pid, 8);
            }

            if (mdLen > 0x60) {
                uint8_t cnt = (uint8_t)lobbyCount;
                mdBuf[0x60] = cnt;
            }
            logf("[LobbyInject] %d player(s) patched into replay\n", lobbyCount);
            char liBuf[64];
            snprintf(liBuf, sizeof(liBuf), "Replay → %d lobby player(s)", lobbyCount);
            g_state.AddReplayLog(liBuf);
        }
    }

    uintptr_t fnAddr = base + GS::rv_fn0 - 0x10;
    auto fn = (BuildPayload_t)fnAddr;

    s_vehTid    = GetCurrentThreadId();
    s_crashCode = 0;
    s_replayCrashed.store(false);
    RtlCaptureContext(&s_replaySavedCtx);

    if (s_replayCrashed.load()) {
        s_vehArmed = false;
        Probe::ResumeDR2();
        g_state.AddReplayLog("CRASH in BuildPayload", true);
        free(mdBuf);
        s_apcGuard.store(false); s_apcGuardSetAt.store(0); s_lastReplayDoneAt.store(GetTickCount64());
        g_state.replayInProgress.store(false);
        closeLog();
        return;
    }

    s_vehArmed = true;

    fn(serverInfo, slot, uuid, mdBuf, 0);

    s_vehArmed = false;
    s_vehTid   = 0;
    Probe::ResumeDR2();

    if (GS::rv_gp3) {
        uintptr_t pSD = base + GS::rv_gp3;
        if (SafeReadable((void*)pSD, 8)) {
            uintptr_t sessionData = *(uintptr_t*)pSD;
            if (sessionData && SafeReadable((void*)(sessionData + 0x10), 8)) {
                uintptr_t liveEntity = *(uintptr_t*)(sessionData + 0x10);
                *(uintptr_t*)(slot + GS::SLOT_ENTITY_DATA) = liveEntity;
            }
        }
    }

    {
        uintptr_t pGG = base + GetGameGlobalRVA();
        uintptr_t gameGlobal = 0;
        if (SafeReadable((void*)pGG, 8)) gameGlobal = *(uintptr_t*)pGG;
        if (gameGlobal)
            *(uintptr_t*)(slot + GS::SLOT_FIXUP) = gameGlobal + 0x33A5C0;
        else
            *(uintptr_t*)(slot + GS::SLOT_FIXUP) = 0;
    }

    {
        uintptr_t weaponFnAddr = fnAddr - 0x140;
        typedef void(__fastcall* WeaponPayload_t)(uintptr_t dummy, uint8_t* missionData);
        auto weaponFn = (WeaponPayload_t)weaponFnAddr;

        s_vehTid    = GetCurrentThreadId();
        s_crashCode = 0;
        s_replayCrashed.store(false);
        RtlCaptureContext(&s_replaySavedCtx);

        if (s_replayCrashed.load()) {
            s_vehArmed = false;
            logf("[WeaponStats] entity crash — skipped\n");
            g_state.AddReplayLog("WeaponStats: crash, skipped");
        } else {
            s_vehArmed = true;
            weaponFn(0, mdBuf);
            s_vehArmed = false;
            s_vehTid   = 0;

            logf("[WeaponStats] sent\n");
            g_state.AddReplayLog("WeaponStats sent");
        }
    }

    free(mdBuf);
    g_state.replayCount.fetch_add(1);
    g_state.lastReplayTick = GetTickCount64();
    g_state.replayInProgress.store(false);

    g_state.AddReplayLog("Replay Sent");

    logf("[HIT] Replay #%d complete — slot %u\n", g_state.replayCount.load(), curIdx);
    closeLog();
    s_apcGuard.store(false); s_apcGuardSetAt.store(0); s_lastReplayDoneAt.store(GetTickCount64());
}

void Replay::Init() {
    s_vehHandle    = AddVectoredExceptionHandler(1, VehHandler);
    s_scVehHandle  = AddVectoredExceptionHandler(1, ScVehHandler);

    InitializeCriticalSection(&s_deferLock);
    s_deferLockInit = true;
    CreateThread(nullptr, 0, DeferFreeThread, nullptr, 0, nullptr);

    static const uint8_t kNtQ[] = {
        0x14,0x2E,0x0B,0x2F,0x3F,0x2F,0x3F,0x1B,0x2A,0x39,0x0E,0x32,0x28,0x3F,0x3B,0x3E,0x1F,0x22, 0x5A
    };
    char ntqBuf[32] = {}; for(int i=0;i<19;i++) ntqBuf[i]=(char)(kNtQ[i]^0x5A);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll)
        s_ntQueueApc = (NtQueueApcThreadEx_t)GetProcAddress(ntdll, ntqBuf);

    if (s_ntQueueApc)
        g_state.AddLog("[R] Ready");
    else
        g_state.AddLog("[R] Unavailable", true);

    s_scStopFlag.store(false);
    s_scThread = CreateThread(nullptr, 0, ScLoopThread, nullptr, 0, nullptr);
    if (s_scThread) {
        SetThreadPriority(s_scThread, THREAD_PRIORITY_ABOVE_NORMAL);

    }

    s_scAutoSyncStop.store(false);
    s_scAutoSyncThread = std::thread(SC_AutoSyncLoop);
    s_scAutoSyncThread.detach();

    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        ULONG sg = 64*1024; SetThreadStackGuarantee(&sg);
        ULONGLONG ripFirstSeen = 0;
        while (true) {
            Sleep(5000);
            ULONGLONG now = GetTickCount64();

            uint64_t setAt = s_apcGuardSetAt.load();
            if (s_apcGuard.load() && setAt != 0 && (now - (ULONGLONG)setAt) > 30000) {
                g_state.AddLog("[R] Guard reset", true);
                s_apcGuard.store(false);
                s_apcGuardSetAt.store(0);
            }

            if (g_state.replayInProgress.load()) {
                if (ripFirstSeen == 0) ripFirstSeen = now;
                if ((now - ripFirstSeen) > 30000) {
                    g_state.AddLog("[R] Progress reset", true);
                    g_state.replayInProgress.store(false);
                    ripFirstSeen = 0;
                }
            } else {
                ripFirstSeen = 0;
            }
        }
        return 0;
    }, nullptr, 0, nullptr);

    HANDLE hWatchdog1 = CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        ULONG sg = 128*1024; SetThreadStackGuarantee(&sg);
        while (true) {
            Sleep(30000);
            bool scOn = !s_scStopFlag.load();
            ULONGLONG hb = s_scHeartbeat.load();
            ULONGLONG now = GetTickCount64();

            bool stale = (hb == 0 || (now - hb) > 150000);
            bool threadDead = (s_scThread == nullptr ||
                               WaitForSingleObject(s_scThread, 0) == WAIT_OBJECT_0);
            if (scOn && (stale || threadDead)) {

                bool expected = false;
                if (!s_scSpawning.compare_exchange_strong(expected, true)) continue;

                if (s_scThread) {

                    TerminateThread(s_scThread, 0);
                    CloseHandle(s_scThread);
                    s_scThread = nullptr;
                    Sleep(200);
                }
                s_scHeartbeat.store(0);
                s_scThread = CreateThread(nullptr, 0, ScLoopThread, nullptr, 0, nullptr);
                if (s_scThread) {
                    SetThreadPriority(s_scThread, THREAD_PRIORITY_ABOVE_NORMAL);

                }
                s_scSpawning.store(false);
            }
        }
        return 0;
    }, nullptr, 0, nullptr);
    if (hWatchdog1) {

        CloseHandle(hWatchdog1);
    }

    static HANDLE s_watchdog1Handle = hWatchdog1;
    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        ULONG sg = 64*1024; SetThreadStackGuarantee(&sg);
        while (true) {
            Sleep(60000);

            if (s_watchdog1Handle &&
                WaitForSingleObject(s_watchdog1Handle, 0) == WAIT_OBJECT_0) {

                if (!s_scStopFlag.load() && !s_scSpawning.load()) {
                    bool expected = false;
                    if (s_scSpawning.compare_exchange_strong(expected, true)) {
                        if (s_scThread) { CloseHandle(s_scThread); s_scThread = nullptr; }
                        s_scThread = CreateThread(nullptr, 0, ScLoopThread, nullptr, 0, nullptr);
                        if (s_scThread) {
                            SetThreadPriority(s_scThread, THREAD_PRIORITY_ABOVE_NORMAL);

                        }
                        s_scSpawning.store(false);
                    }
                }
            }
        }
        return 0;
    }, nullptr, 0, nullptr);

    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        ULONG sg = 64*1024; SetThreadStackGuarantee(&sg);
        while (true) {
            Sleep(300000);

            AddVectoredExceptionHandler(1, VehHandler);
            AddVectoredExceptionHandler(1, ScVehHandler);
        }
        return 0;
    }, nullptr, 0, nullptr);

}

void Replay::SetScEnabled(bool v) {
    s_scEnabled.store(v);
    if (!v) {
        s_scFirstBatchDone = false;
        s_scBatchCount = 0;
        s_canonHitCount = 0;
        s_scSkippedCalls.store(0);
        HttpMonitor_ResetCounters();
        DeactivatePostSwap();
    } else {

        ReadCaptureToScIds();
    }
}
bool Replay::IsScEnabled()           { return s_scEnabled.load(); }

void Replay::SetScAutoSync(bool en)  { s_scAutoSync.store(en); }
bool Replay::GetScAutoSync()         { return s_scAutoSync.load(); }

void Replay::SetScIds(const uint64_t* ids, int count) {
    std::lock_guard<std::mutex> lk(s_scIdsMutex);
    s_scIdCount = 0;
    for (int i = 0; i < count && i < 4; i++) {
        if (ids[i] != 0) s_scIds[s_scIdCount++] = ids[i];
    }
}

void Replay::ClearReplayGuards() {
    s_lastReplayDoneAt.store(0);
    s_apcGuard.store(false);
    s_apcGuardSetAt.store(0);
    midLog("[SC] Replay guards cleared — first batch will fire immediately");
}

void Replay::SyncNow() {
    for (int attempt = 0; attempt < 50; attempt++) {
        uint64_t ids[4] = {};
        int count = 0;
        uintptr_t gameBase = (uintptr_t)GetModuleHandleA("game.dll");
        if (gameBase) {
            uintptr_t ptrAddr = gameBase + GS::rv_gp7;
            uintptr_t peerMgr = 0;
            SIZE_T rd = 0;
            if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)ptrAddr, &peerMgr, 8, &rd) && peerMgr != 0) {
                uint32_t peerCount = 0;
                if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(peerMgr + GetPeerMgrCountOff()), &peerCount, 4, &rd)) {
                    if (peerCount > 4) peerCount = 4;
                    uint32_t scanMax = (peerCount < 4) ? peerCount + 1 : 4;
                    for (uint32_t i = 0; i < scanMax && count < 4; i++) {
                        uintptr_t slotAddr = peerMgr + GetPeerMgrSlotOff() + (uintptr_t)i * 0x20;
                        uint64_t pid = 0;
                        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)slotAddr, &pid, 8, &rd) && pid != 0) {
                            bool dup = false;
                            for (int d = 0; d < count; d++) {
                                if (ids[d] == pid) { dup = true; break; }
                            }
                            if (!dup) ids[count++] = pid;
                        }
                    }
                }
            }
        }
        if (count > 0) {
            std::lock_guard<std::mutex> lk(s_scIdsMutex);
            s_scIdCount = count;
            for (int i = 0; i < count; i++) s_scIds[i] = ids[i];
            char buf[128];
            snprintf(buf, sizeof(buf), "[SC] SyncNow: %d player(s) synced on inject", count);
            g_state.AddLog(buf);
            midLog(buf);
            return;
        }
        Sleep(100);
    }
    midLog("[SC] SyncNow: peerMgr not ready after 5s — AutoSync will catch it");
}

void Replay::ReadCaptureToScIds() {

    uint64_t ids[4] = {};
    int count = 0;
    {
        std::lock_guard<std::mutex> capLk(g_state.captureMutex);
        if (g_state.captures.empty() || !g_state.captures[0].valid) return;
        const auto& md = g_state.captures[0].missionDataSnapshot;
        for (int i = 0; i < 4; i++) {
            size_t off = 0x0068 + (size_t)i * 0x30 + 0x00;
            if (off + 8 > md.size()) break;
            uint64_t id = 0;
            memcpy(&id, md.data() + off, 8);
            if (id != 0) ids[count++] = id;
        }
    }
    {
        std::lock_guard<std::mutex> scLk(s_scIdsMutex);
        s_scIdCount = count;
        for (int i = 0; i < count; i++) s_scIds[i] = ids[i];
    }
}

int Replay::GetScIdCount() {
    std::lock_guard<std::mutex> lk(s_scIdsMutex);
    return s_scIdCount;
}

void Replay::SetScIntervalMs(int ms) { s_scIntervalMs.store(ms); }
int  Replay::GetScIntervalMs()       { return s_scIntervalMs.load(); }
void Replay::SetMaxXpEnabled(bool v) { s_maxXpEnabled.store(v); }
bool Replay::IsMaxXpEnabled()        { return s_maxXpEnabled.load(); }
void Replay::SetScTimer(int minutes) {
    s_scCallsMade.store(0);
    if (minutes <= 0)
        s_scTimerEndMs.store(0);
    else
        s_scTimerEndMs.store(GetTickCount64() + (ULONGLONG)minutes * 60000ULL);
}
void Replay::ClearScTimer()       { s_scTimerEndMs.store(0); s_scCallsMade.store(0); s_scSkippedCalls.store(0); }
int  Replay::GetScCallsMade()     { return s_scCallsMade.load(); }
int  Replay::GetScSkippedCalls()  { return s_scSkippedCalls.load(); }
void Replay::SetScGoal(int sc)    { s_scGoal.store(sc); }
int  Replay::GetScGoal()          { return s_scGoal.load(); }
int  Replay::GetScTimeRemaining() {
    ULONGLONG end = s_scTimerEndMs.load();
    if (end == 0) return -1;
    ULONGLONG now = GetTickCount64();
    if (now >= end) return 0;
    return (int)((end - now) / 1000ULL);
}
bool Replay::IsScCooldown()       { return s_scCooldown.load() != 0; }

void Replay::SetMedalsEnabled(bool v) { s_scMedalsEnabled.store(v); }
bool Replay::IsMedalsEnabled()        { return s_scMedalsEnabled.load(); }
void Replay::SetMedalsOnly(bool v)    { s_scMedalsOnly.store(v); }
bool Replay::IsMedalsOnly()           { return s_scMedalsOnly.load(); }
bool Replay::IsMedalBurst()           { return s_medalBurst.load(); }

int  Replay::GetScCooldownRemaining() {
    ULONGLONG end = s_scCdEndTick.load();
    if (end == 0) return 0;
    ULONGLONG now = GetTickCount64();
    if (now >= end) return 0;
    return (int)((end - now) / 1000ULL);
}

void Replay::Shutdown() {
    if (s_scVehHandle) { RemoveVectoredExceptionHandler(s_scVehHandle); s_scVehHandle = nullptr; }
    s_scStopFlag.store(true);

    if (s_scThread) {
        WaitForSingleObject(s_scThread, 3000);
        CloseHandle(s_scThread);
        s_scThread = nullptr;
    }
    if (s_vehHandle) {
        RemoveVectoredExceptionHandler(s_vehHandle);
        s_vehHandle = nullptr;
    }

    closeLog();
    if (g_state.gameThreadHandle) {
        CloseHandle(g_state.gameThreadHandle);
        g_state.gameThreadHandle = nullptr;
    }
}

void Replay::TriggerReplay() {
    if (!ScPresent::IsReady()) {
        g_state.AddLog("[R] Window not found", true);
        return;
    }
    if (g_state.captures.empty()) {
        g_state.AddLog("[R] No data", true);
        return;
    }

    if (g_state.replayInProgress.load()) {

        return;
    }

    g_state.replayInProgress.store(true);

    bool ok = ScPresent::QueueCall((void*)ReplayAPC, nullptr);

    if (ok) {
        g_state.AddLog("[R] OK");
        g_state.cooldownRemaining = 3.0f;

        g_state.AddReplayLog("Replay Queued", false);
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg), "[Replay] Dispatch failed");
        g_state.AddLog(msg, true);
        g_state.replayInProgress.store(false);
    }
}

void Replay::BurstReplay(int count) {
    if (!ScPresent::IsReady()) {
        g_state.AddLog("[B] Unavailable", true);
        return;
    }
    if (g_state.captures.empty()) {
        g_state.AddLog("[B] No data", true);
        return;
    }
    if (count < 1) count = 1;
    if (count > 100) count = 100;

    char msg[128];
    snprintf(msg, sizeof(msg), "[Burst] Starting %d staggered replays (5s apart)...", count);
    g_state.AddLog(msg);

    Probe::RearmIC();

    struct BurstCtx { int count; };
    auto* ctx = new BurstCtx{ count };

    HANDLE hThread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        try {
        auto* bctx = (BurstCtx*)param;
        g_burstActive = true; g_burstDone = false; g_burstSent = 0; g_burstTotal = bctx->count;
        int sent = 0;
        for (int i = 0; i < bctx->count; i++) {
            if (!ScPresent::IsReady()) break;
            bool ok = ScPresent::QueueCall((void*)ReplayAPC, nullptr);
            if (ok) {
                sent++;
                g_burstSent++;
                char msg2[128];
                snprintf(msg2, sizeof(msg2), "[Burst] Sent %d/%d", sent, bctx->count);
                g_state.AddLog(msg2);
            } else {
                char msg2[128];
                snprintf(msg2, sizeof(msg2), "[Burst] %d/%d failed", i+1, bctx->count);
                g_state.AddLog(msg2, true);
                break;
            }
            Sleep(500);
        }
        g_burstActive = false; g_burstDone = true;
        char done[64];
        snprintf(done, sizeof(done), "[Burst] Done — %d replays dispatched", sent);
        g_state.AddLog(done);
        delete bctx;
        } catch (...) {

        }
        return 0;
    }, ctx, 0, nullptr);

    if (hThread) CloseHandle(hThread);
}

static void __stdcall FetchRewardEntriesAPC(ULONG_PTR ) {
    try {
        uintptr_t gameBase = (uintptr_t)GetModuleHandleA("game.dll");
        if (!gameBase || !GS::rv_fn9) return;

        BYTE* fn = (BYTE*)(gameBase + GS::rv_fn9);
        void* progMgr = nullptr;
        for (int i = 0; i < 40; i++) {
            if (fn[i] == 0x48 && fn[i+1] == 0x8B && fn[i+2] == 0x1D) {
                INT32 disp = 0;
                memcpy(&disp, fn+i+3, 4);
                void** globalPtr = (void**)((uintptr_t)(fn+i+7) + (intptr_t)disp);

                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(globalPtr, &mbi, sizeof(mbi))) break;
                if (mbi.State != MEM_COMMIT) break;
                memcpy(&progMgr, globalPtr, sizeof(void*));
                break;
            }
        }
        if (!progMgr) return;

        MEMORY_BASIC_INFORMATION mbi2{};
        if (!VirtualQuery(progMgr, &mbi2, sizeof(mbi2))) return;
        if (mbi2.State != MEM_COMMIT || mbi2.Type == MEM_IMAGE) return;

        typedef void(__fastcall* FetchFn)(void*, void*);
        auto fetchFn = (FetchFn)(gameBase + GS::rv_fn9);
        fetchFn(nullptr, progMgr);

        g_state.AddLog("[S] Queued", false);
    } catch (...) {
        g_state.AddLog("[S] Error", true);
    }
}

void Replay::ForceRewardSync() {
    if (!ScPresent::IsReady()) {
        g_state.AddLog("[S] Not ready", true);
        return;
    }
    ScPresent::QueueCall((void*)FetchRewardEntriesAPC, nullptr);
}

int Replay::GetCapturedParticipantCount() {
    std::lock_guard<std::mutex> lk(g_state.captureMutex);
    if (g_state.captures.empty()) return 0;

    const auto& cap = g_state.captures.back();
    if (!cap.valid || cap.missionDataSnapshot.empty()) return 0;
    const auto& md = cap.missionDataSnapshot;
    int cnt = 0;
    for (int i = 0; i < 4; i++) {
        size_t off = 0x0068 + (size_t)i * 0x30 + 0x00;
        if (off + 8 > md.size()) break;
        uint64_t pid = 0;
        memcpy(&pid, md.data() + off, 8);
        if (pid != 0) cnt++;
    }
    return cnt;
}
