#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <intrin.h>

#pragma section(".packer", read, execute)
#pragma code_seg(".packer")

#define PEB_OFFSET_BEINGDEBUGGED 0x02
#define PEB_OFFSET_NT_GLOBAL_FLAG 0xBC

extern NTSTATUS NTAPI NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

static __forceinline ULONG_PTR packer_read_peb(void)
{
    return __readgsqword(0x60);
}

static __forceinline ULONGLONG packer_rdtsc(void)
{
    return __rdtsc();
}

static __forceinline void packer_zero_memory(volatile void* ptr, SIZE_T size)
{
    volatile BYTE* p = (volatile BYTE*)ptr;
    for (SIZE_T i = 0; i < size; i++) {
        p[i] = 0;
    }
}

static __forceinline void packer_exit_process(void)
{
    __fastfail(0xDEAD);
}

static BOOL packer_check_peb(void)
{
    ULONG_PTR peb = packer_read_peb();
    if (!peb) return FALSE;

    BYTE beingDebugged = *(volatile BYTE*)(peb + PEB_OFFSET_BEINGDEBUGGED);
    if (beingDebugged) {
        return TRUE;
    }
    return FALSE;
}

static BOOL packer_check_nt_global_flag(void)
{
    ULONG_PTR peb = packer_read_peb();
    if (!peb) return FALSE;

    ULONG ntGlobalFlag = *(volatile ULONG*)(peb + PEB_OFFSET_NT_GLOBAL_FLAG);
    if (ntGlobalFlag & 0x00000070) {
        return TRUE;
    }
    return FALSE;
}

static BOOL packer_check_debug_port(void)
{
    HANDLE hProcess = (HANDLE)-1;
    DWORD debugPort = 0;
    ULONG returnLen = 0;

    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessDebugPort,
        &debugPort,
        sizeof(debugPort),
        &returnLen
    );

    if (NT_SUCCESS(status) && debugPort != 0) {
        return TRUE;
    }
    return FALSE;
}

static BOOL packer_check_debug_flags(void)
{
    HANDLE hProcess = (HANDLE)-1;
    DWORD debugFlags = 0;
    ULONG returnLen = 0;

    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessDebugFlags,
        &debugFlags,
        sizeof(debugFlags),
        &returnLen
    );

    if (NT_SUCCESS(status) && debugFlags == 0) {
        return TRUE;
    }
    return FALSE;
}

static BOOL packer_check_rdtsc_timing(void)
{
    ULONGLONG start = packer_rdtsc();
    volatile int dummy = 0;
    for (int i = 0; i < 100000; i++) {
        dummy += i;
    }
    ULONGLONG end = packer_rdtsc();
    ULONGLONG elapsed = end - start;

    ULONGLONG start2 = packer_rdtsc();
    for (int i = 0; i < 100000; i++) {
        dummy += i;
    }
    ULONGLONG end2 = packer_rdtsc();
    ULONGLONG elapsed2 = end2 - start2;

    if (elapsed2 > elapsed * 2 && elapsed > 0) {
        return TRUE;
    }
    return FALSE;
}

__declspec(dllexport) BOOL Packer_AntiDebug_Check(void)
{
    if (packer_check_peb()) return TRUE;
    if (packer_check_nt_global_flag()) return TRUE;
    if (packer_check_debug_port()) return TRUE;
    if (packer_check_debug_flags()) return TRUE;
    if (packer_check_rdtsc_timing()) return TRUE;
    return FALSE;
}

__declspec(dllexport) void Packer_DestroyAndExit(void* compressedData, SIZE_T compressedSize)
{
    packer_zero_memory(compressedData, compressedSize);
    packer_exit_process();
}

#pragma code_seg()
