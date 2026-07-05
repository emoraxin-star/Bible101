#include "pattern_db.h"
#include "hash_resolver.h"
#include "diverse_stubs.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define JITTER_MS_MIN 5
#define JITTER_MS_MAX 50

typedef struct {
    void*   stubNtProtectVirtualMemory;
    uint32_t ssnProtectVirtualMemory;
} SyscallContext;

static SyscallContext g_SysCtx = {0};
static int g_SysCtxInitialized = 0;

uint32_t ResolveSSN(const char* functionName)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    uint8_t* funcAddr = (uint8_t*)GetProcAddress(ntdll, functionName);
    if (!funcAddr) return 0;

    if (funcAddr[0] == 0x4C && funcAddr[1] == 0x8B && funcAddr[2] == 0xD1)
    {
        return *(uint32_t*)(funcAddr + 4);
    }

    if (funcAddr[0] == 0xB8)
    {
        return *(uint32_t*)(funcAddr + 1);
    }
    if (funcAddr[0] == 0xE9)
    {
        int32_t rel = *(int32_t*)(funcAddr + 1);
        uint8_t* target = funcAddr + 5 + rel;
        while (target[0] == 0xCC) target++;
        if (target[0] == 0x4C && target[1] == 0x8B && target[2] == 0xD1)
            return *(uint32_t*)(target + 4);
        if (target[0] == 0xB8)
            return *(uint32_t*)(target + 1);
    }

    return 0;
}

int InitSyscallContext(void)
{
    uint32_t ssn = ResolveSSN("NtProtectVirtualMemory");
    if (!ssn) return 0;

    g_SysCtx.ssnProtectVirtualMemory = ssn;
    g_SysCtx.stubNtProtectVirtualMemory = BuildSyscallStubRandom(ssn);
    if (!g_SysCtx.stubNtProtectVirtualMemory) return 0;

    g_SysCtxInitialized = 1;
    return 1;
}

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect,
    PULONG OldProtect);

static void RandomJitter(void)
{
    unsigned int ms = JITTER_MS_MIN + (rand() % (JITTER_MS_MAX - JITTER_MS_MIN + 1));
    Sleep(ms);
}

static uint32_t ComputeCRC32C(const uint8_t* data, size_t len)
{
    return CRC32C(data, len);
}

static int WriteWithValidation(void* address, const uint8_t* patchBytes, size_t patchSize)
{
    SIZE_T regionSize = patchSize;
    PVOID addr = address;
    ULONG oldProtect = 0;

    NtProtectVirtualMemory_t stub = (NtProtectVirtualMemory_t)
        g_SysCtx.stubNtProtectVirtualMemory;

    NTSTATUS status = stub(GetCurrentProcess(), &addr, &regionSize,
        PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status < 0) return 0;

    memcpy(address, patchBytes, patchSize);

    ULONG dummy = 0;
    stub(GetCurrentProcess(), &addr, &regionSize, oldProtect, &dummy);

    uint32_t expectedCrc = ComputeCRC32C(patchBytes, patchSize);
    uint32_t actualCrc = ComputeCRC32C((const uint8_t*)address, patchSize);

    return (expectedCrc == actualCrc) ? 1 : 0;
}

int InstallHook(PatternEntry* entry)
{
    if (!entry || !entry->bResolved) return 0;
    if (entry->bInstalled) return 1;
    if (!g_SysCtxInitialized && !InitSyscallContext()) return 0;

    RandomJitter();

    memcpy(entry->originalBytes,
        (const void*)entry->resolvedAddr,
        min((size_t)entry->patchSize, PATCH_MAX_BYTES));

    int success = WriteWithValidation(
        (void*)entry->resolvedAddr,
        entry->patchBytes,
        min((size_t)entry->patchSize, PATCH_MAX_BYTES));

    entry->bInstalled = !!success;

    uint32_t hid = FNV1a32("HookInstaller");
    if (success)
    {
        char buf[64];
        sprintf_s(buf, sizeof(buf), "[LIBERTEA] Hook 0x%08X installed at 0x%p",
            entry->patternId, (void*)entry->resolvedAddr);
        OutputDebugStringA(buf);
    }
    else
    {
        char buf[64];
        sprintf_s(buf, sizeof(buf), "[LIBERTEA] Hook 0x%08X FAILED at 0x%p",
            entry->patternId, (void*)entry->resolvedAddr);
        OutputDebugStringA(buf);
    }

    return success;
}

int UninstallHook(PatternEntry* entry)
{
    if (!entry || !entry->bInstalled) return 0;
    if (!g_SysCtxInitialized) return 0;

    RandomJitter();

    int success = WriteWithValidation(
        (void*)entry->resolvedAddr,
        entry->originalBytes,
        min((size_t)entry->patchSize, PATCH_MAX_BYTES));

    entry->bInstalled = !success;

    char buf[64];
    sprintf_s(buf, sizeof(buf), "[LIBERTEA] Unhook 0x%08X %s",
        entry->patternId, success ? "OK" : "FAIL");
    OutputDebugStringA(buf);

    return success;
}

int InstallAllHooks(void)
{
    if (!g_SysCtxInitialized && !InitSyscallContext()) return 0;

    int successCount = 0;
    for (uint32_t i = 0; i < g_PatternCount; i++)
    {
        if (g_PatternTable[i].patchSize > 0 &&
            g_PatternTable[i].bResolved &&
            !g_PatternTable[i].bInstalled)
        {
            if (InstallHook(&g_PatternTable[i]))
                successCount++;
        }
    }

    return successCount;
}

int UninstallAllHooks(void)
{
    int successCount = 0;
    for (uint32_t i = 0; i < g_PatternCount; i++)
    {
        if (g_PatternTable[i].bInstalled)
        {
            if (UninstallHook(&g_PatternTable[i]))
                successCount++;
        }
    }

    return successCount;
}

void ShutdownHookSystem(void)
{
    UninstallAllHooks();
    FreeAllStubs();
    g_SysCtxInitialized = 0;
}
