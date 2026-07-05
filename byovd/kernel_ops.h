#pragma once
#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// High-level kernel operations using the BYOVD interface.
// These functions abstract away the IOCTL details and provide
// cheat-focused primitives.
//

//
// EPROCESS field offsets (Windows 10 22H2 / 11 23H2 x64)
// These are version-specific and must be resolved at runtime.
//
typedef struct _EPROCESS_OFFSETS {
    DWORD ActiveProcessLinks;    // LIST_ENTRY offset
    DWORD ImageFileName;         // Image name (15 chars)
    DWORD Protection;            // PS_PROTECTION byte (PsIsProtectedProcess)
    DWORD UniqueProcessId;       // PID
    DWORD ObjectTable;           // HANDLE_TABLE
    DWORD VadRoot;               // MM_AVL_TABLE
    DWORD Peb;                   // PEB pointer
    DWORD Wow64Process;          // WoW64 state
    DWORD SeDebugPrivilege;      // Token privileges
} EPROCESS_OFFSETS, *PEPROCESS_OFFSETS;

//
// PEB module list offsets
//
typedef struct _PEB_OFFSETS {
    DWORD Ldr;                   // PEB.Ldr -> PEB_LDR_DATA
    DWORD InLoadOrderModuleList;
    DWORD InMemoryOrderModuleList;
    DWORD InInitializationOrderModuleList;
    DWORD DllBase;
    DWORD SizeOfImage;
    DWORD FullDllName;
    DWORD BaseDllName;
} PEB_OFFSETS, *PPEB_OFFSETS;

//
// Process hiding and protection
//
BOOL
HideProcess(
    _In_ DWORD ProcessId
    );

BOOL
HideModule(
    _In_ DWORD ProcessId,
    _In_ DWORD64 ModuleBase
    );

BOOL
ProtectProcess(
    _In_ DWORD ProcessId
    );

BOOL
UnprotectProcess(
    _In_ DWORD ProcessId
    );

//
// GameGuard bypass
//
BOOL
BypassGameGuard(VOID);

//
// Kernel-level memory operations
//
BOOL
ReadProcessMemoryKernel(
    _In_ DWORD DestProcessId,
    _In_ DWORD64 Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    );

BOOL
WriteProcessMemoryKernel(
    _In_ DWORD DestProcessId,
    _In_ DWORD64 Address,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    );

BOOL
SetMemoryProtectionKernel(
    _In_ DWORD ProcessId,
    _In_ DWORD64 Address,
    _In_ SIZE_T Size,
    _In_ DWORD NewProtect,
    _Out_ PDWORD OldProtect
    );

//
// EPROCESS helpers
//
BOOL
GetEprocessOffsets(
    _Out_ PEPROCESS_OFFSETS Offsets
    );

DWORD64
GetEprocessAddress(
    _In_ DWORD ProcessId
    );

BOOL
ReadEprocessField(
    _In_ DWORD64 EprocessAddress,
    _In_ DWORD Offset,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ DWORD Size
    );

BOOL
WriteEprocessField(
    _In_ DWORD64 EprocessAddress,
    _In_ DWORD Offset,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ DWORD Size
    );

#ifdef __cplusplus
}
#endif
