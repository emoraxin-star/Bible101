
#include "sc_limit.h"
#include "scanner.h"
#include <windows.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

static void scLimitLog(const char* , ...) {  }

static char              g_uuid[40] = {0};
static std::atomic<bool> g_enabled{false};
static std::atomic<bool> g_installed{false};
static std::atomic<bool> g_rotateReq{false};
static std::atomic<bool> g_rotateAck{false};
static HANDLE            g_thread = nullptr;
static uintptr_t         g_hookAddr = 0;
static uint8_t           g_origBytes[10] = {0};

static void GenerateUUID(char* out) {
    static const char hex[] = "0123456789abcdef";
    int p = 0;
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23)
            out[p++] = '-';
        else
            out[p++] = hex[rand() % 16];
    }
    out[p] = '\0';
}

static DWORD WINAPI UUIDRotateThread(LPVOID) {
    srand((unsigned)time(nullptr) ^ GetCurrentThreadId());
    while (true) {
        if (g_rotateReq.load(std::memory_order_acquire)) {
            GenerateUUID(g_uuid);
            g_rotateReq.store(false, std::memory_order_release);
            g_rotateAck.store(true, std::memory_order_release);
        }

        Sleep(10);
    }
    return 0;
}

static void* AllocNear(uintptr_t target, size_t size) {
    uintptr_t lo = (target > 0x70000000) ? target - 0x70000000 : 0x10000;
    uintptr_t hi = target + 0x70000000;
    for (uintptr_t a = lo; a < hi; a += 0x10000) {
        void* p = VirtualAlloc((void*)a, size, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
        if (p) return p;
    }
    return nullptr;
}

bool ScLimit::Install() {
    if (g_installed.load()) return true;

    const char* aob =
        "4C 8B F0 4C 8B 89 ?? ?? ?? ?? 48 8B C8 "
        "41 FF 91 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? "
        "48 8D 15 ?? ?? ?? ?? 44 8B C3";

    g_hookAddr = ScanModule("game.dll", aob);
    if (!g_hookAddr) {
        scLimitLog("[SC-LIMIT] AOB not found — hook NOT installed");
        return false;
    }

    scLimitLog("[SC-LIMIT] AOB found at 0x%llX", (unsigned long long)g_hookAddr);

    memcpy(g_origBytes, (void*)g_hookAddr, 10);

    int32_t rcxDisp = *(int32_t*)(g_hookAddr + 6);

    uint8_t* cave = (uint8_t*)AllocNear(g_hookAddr, 4096);
    if (!cave) {
        scLimitLog("[SC-LIMIT] AllocNear FAILED");
        return false;
    }
    scLimitLog("[SC-LIMIT] Code cave at %p", cave);

    int off = 0;

    cave[off++] = 0x50;
    cave[off++] = 0x51;
    cave[off++] = 0x9C;

    cave[off++] = 0x48; cave[off++] = 0xB8;
    *(uintptr_t*)(cave + off) = (uintptr_t)&g_enabled;  off += 8;
    cave[off++] = 0x80; cave[off++] = 0x38; cave[off++] = 0x00;
    cave[off++] = 0x74;
    int jeFixup = off;
    cave[off++] = 0x00;

    cave[off++] = 0x4D; cave[off++] = 0x85; cave[off++] = 0xC0;

    cave[off++] = 0x74;
    int jzFixup = off;
    cave[off++] = 0x00;

    cave[off++] = 0x56;
    cave[off++] = 0x57;
    cave[off++] = 0xFC;

    cave[off++] = 0x48; cave[off++] = 0xBE;
    *(uintptr_t*)(cave + off) = (uintptr_t)g_uuid;  off += 8;

    cave[off++] = 0x4C; cave[off++] = 0x89; cave[off++] = 0xC7;
    cave[off++] = 0xB9; *(uint32_t*)(cave + off) = 36; off += 4;
    cave[off++] = 0xF3; cave[off++] = 0xA4;

    cave[off++] = 0x5F;
    cave[off++] = 0x5E;

    cave[jzFixup] = (uint8_t)(off - jzFixup - 1);

    cave[jeFixup] = (uint8_t)(off - jeFixup - 1);

    cave[off++] = 0x9D;
    cave[off++] = 0x59;
    cave[off++] = 0x58;

    cave[off++] = 0x4C; cave[off++] = 0x8B; cave[off++] = 0xF0;

    cave[off++] = 0x4C; cave[off++] = 0x8B; cave[off++] = 0x89;
    *(int32_t*)(cave + off) = rcxDisp;  off += 4;

    cave[off++] = 0xE9;
    int32_t retDisp = (int32_t)((g_hookAddr + 10) - ((uintptr_t)(cave + off) + 4));
    *(int32_t*)(cave + off) = retDisp;  off += 4;

    DWORD caveProt;
    VirtualProtect(cave, 4096, PAGE_EXECUTE_READ, &caveProt);
    FlushInstructionCache(GetCurrentProcess(), cave, off);

    DWORD oldProt;
    VirtualProtect((void*)g_hookAddr, 10, PAGE_EXECUTE_READWRITE, &oldProt);

    *(uint8_t*)(g_hookAddr)     = 0xE9;
    int32_t hookDisp = (int32_t)((uintptr_t)cave - (g_hookAddr + 5));
    *(int32_t*)(g_hookAddr + 1) = hookDisp;
    memset((void*)(g_hookAddr + 5), 0x90, 5);

    VirtualProtect((void*)g_hookAddr, 10, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)g_hookAddr, 10);

    srand((unsigned)time(nullptr));
    GenerateUUID(g_uuid);

    g_thread = CreateThread(nullptr, 0, UUIDRotateThread, nullptr, 0, nullptr);

    g_installed.store(true);
    scLimitLog("[SC-LIMIT] ✓ Hook installed — auto-enabled");
    SetEnabled(true);
    return true;
}

void ScLimit::SetEnabled(bool on)  { g_enabled.store(on); }
bool ScLimit::IsEnabled()          { return g_enabled.load(); }
bool ScLimit::IsInstalled()        { return g_installed.load(); }

void ScLimit::RotateNow() { GenerateUUID(g_uuid); }

void ScLimit::ForceUUID(const char* uuid) {
    if (!uuid) return;
    memcpy(g_uuid, uuid, 36);
    g_uuid[36] = '\0';
}

void ScLimit::RequestRotate() {
    g_rotateAck.store(false, std::memory_order_release);
    g_rotateReq.store(true, std::memory_order_release);
    for (int i = 0; i < 6; i++) {
        if (g_rotateAck.load(std::memory_order_acquire)) return;
        Sleep(10);
    }
}
