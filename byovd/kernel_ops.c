#include "kernel_ops.h"
#include "driver_loader.h"

//
// External references from memory_interface.c
//
extern BOOL ReadProcessPhysicalMemory(DWORD, DWORD64, PVOID, DWORD);
extern BOOL WriteProcessPhysicalMemory(DWORD, DWORD64, PVOID, DWORD);
extern BOOL VirtualToPhysical(DWORD64, DWORD, PDWORD64);

//
// EPROCESS offsets for Windows 10 22H2 (build 19045)
// These are auto-detected via signature scanning in production;
// hardcoded here as fallback defaults.
//
static EPROCESS_OFFSETS g_EprocessOffsets = {
    0x2F0,   // ActiveProcessLinks
    0x2A8,   // ImageFileName
    0x87A,   // Protection (PsProtectedProcess -> PS_PROTECTION)
    0x2E0,   // UniqueProcessId
    0x418,   // ObjectTable
    0x7D0,   // VadRoot (sparse VAD)
    0x3E8,   // Peb
    0x3F0,   // Wow64Process
    0x4D0    // SeDebugPrivilege (Token + offset)
};

static BOOL   g_OffsetsResolved = FALSE;
static HANDLE g_MemDeviceHandle = INVALID_HANDLE_VALUE;

//
// Dynamically resolve EPROCESS field offsets by scanning the kernel image.
// For simplicity, this stub returns hardcoded defaults.
// In production, you would read ntoskrnl.exe from disk and signature-scan.
//
BOOL
GetEprocessOffsets(
    _Out_ PEPROCESS_OFFSETS Offsets
    )
{
    if (Offsets == NULL) {
        return FALSE;
    }

    if (!g_OffsetsResolved) {
        //
        // TODO: Implement runtime offset resolution:
        //   1. Read ntoskrnl.exe base via NtQuerySystemInformation
        //   2. Find EPROCESS structure layout via signature matching
        //   3. Update g_EprocessOffsets for current build
        //
        g_OffsetsResolved = TRUE;
    }

    *Offsets = g_EprocessOffsets;
    return TRUE;
}

//
// Get the physical address of the EPROCESS structure for a given PID.
// Walks the kernel's active process list to find the matching process.
//
DWORD64
GetEprocessAddress(
    _In_ DWORD ProcessId
    )
{
    //
    // Approach: Read the kernel's PsActiveProcessHead list via physical memory.
    // On x64, we need to find the kernel base first, then locate the list head.
    //
    // For simplicity, this uses an alternative approach:
    // NtQuerySystemInformation(SystemProcessInformation) + EPROCESS lookup.
    //
    // This is a stub — full implementation requires kernel base discovery.
    //
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

//
// Read a field from an EPROCESS structure given its physical address.
//
BOOL
ReadEprocessField(
    _In_ DWORD64 EprocessAddress,
    _In_ DWORD Offset,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ DWORD Size
    )
{
    return ReadPhysicalMemory(
        EprocessAddress + Offset,
        Buffer,
        Size
    );
}

//
// Write a field in an EPROCESS structure given its physical address.
//
BOOL
WriteEprocessField(
    _In_ DWORD64 EprocessAddress,
    _In_ DWORD Offset,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ DWORD Size
    )
{
    //
    // Read-modify-write the EPROCESS page to preserve adjacent fields
    //
    DWORD64 pageBase = EprocessAddress & ~0xFFF;
    DWORD   pageOffset = (DWORD)(EprocessAddress & 0xFFF) + Offset;
    BYTE    pageBuffer[0x1000];

    if (!ReadPhysicalMemory(pageBase, pageBuffer, sizeof(pageBuffer))) {
        return FALSE;
    }

    CopyMemory(pageBuffer + pageOffset, Buffer, Size);

    return WritePhysicalMemory(pageBase, pageBuffer, sizeof(pageBuffer));
}

//
// Remove a process from the kernel's active process list.
// This hides the process from Toolhelp32Snapshot, NtQuerySystemInformation, etc.
//
BOOL
HideProcess(
    _In_ DWORD ProcessId
    )
{
    DWORD64 eprocessAddr = GetEprocessAddress(ProcessId);
    DWORD64 flink, blink;

    if (eprocessAddr == 0) {
        return FALSE;
    }

    //
    // Read the current process's LIST_ENTRY (Flink + Blink)
    //
    if (!ReadEprocessField(eprocessAddr, g_EprocessOffsets.ActiveProcessLinks,
            &flink, sizeof(flink)))
    {
        return FALSE;
    }

    if (!ReadEprocessField(eprocessAddr,
            g_EprocessOffsets.ActiveProcessLinks + sizeof(DWORD64),
            &blink, sizeof(blink)))
    {
        return FALSE;
    }

    //
    // Unlink: Flink->Blink = Blink, Blink->Flink = Flink
    //
    if (!WriteEprocessField(flink - g_EprocessOffsets.ActiveProcessLinks,
            g_EprocessOffsets.ActiveProcessLinks + sizeof(DWORD64),
            &blink, sizeof(blink)))
    {
        return FALSE;
    }

    if (!WriteEprocessField(blink - g_EprocessOffsets.ActiveProcessLinks,
            g_EprocessOffsets.ActiveProcessLinks,
            &flink, sizeof(flink)))
    {
        return FALSE;
    }

    //
    // Zero out our own links to prevent traversal back to us
    //
    ZeroMemory(&flink, sizeof(flink));
    WriteEprocessField(eprocessAddr, g_EprocessOffsets.ActiveProcessLinks,
        &flink, sizeof(flink));

    return TRUE;
}

//
// Hide a module from the PEB module list of a target process.
// Removes the LDR_DATA_TABLE_ENTRY from all three linked lists.
// Done by walking the PEB through physical memory.
//
BOOL
HideModule(
    _In_ DWORD ProcessId,
    _In_ DWORD64 ModuleBase
    )
{
    DWORD64 eprocessAddr;
    DWORD64 pebAddr;
    DWORD64 ldrAddr;
    DWORD64 entryAddr;
    DWORD64 currentEntry;

    BYTE    inLoadOrder[2 * sizeof(DWORD64)];    // Flink + Blink
    BYTE    inMemoryOrder[2 * sizeof(DWORD64)];
    BYTE    inInitOrder[2 * sizeof(DWORD64)];

    LIST_ENTRY64 *flink;
    LIST_ENTRY64 *blink;

    eprocessAddr = GetEprocessAddress(ProcessId);
    if (eprocessAddr == 0) {
        return FALSE;
    }

    //
    // Read PEB pointer from EPROCESS
    //
    if (!ReadEprocessField(eprocessAddr, g_EprocessOffsets.Peb,
            &pebAddr, sizeof(pebAddr)))
    {
        return FALSE;
    }

    //
    // Read PEB->Ldr
    //
    if (!ReadProcessPhysicalMemory(ProcessId, pebAddr + 0x18,
            &ldrAddr, sizeof(ldrAddr)))
    {
        return FALSE;
    }

    //
    // Walk the InLoadOrderModuleList to find our module
    //
    if (!ReadProcessPhysicalMemory(ProcessId, ldrAddr + 0x10,
            inLoadOrder, sizeof(inLoadOrder)))
    {
        return FALSE;
    }

    flink = (LIST_ENTRY64 *)(inLoadOrder);
    currentEntry = (DWORD64)flink->Flink;

    while (currentEntry != ldrAddr + 0x10) {
        DWORD64 entryDllBase;

        if (!ReadProcessPhysicalMemory(ProcessId, currentEntry + 0x30,
                &entryDllBase, sizeof(entryDllBase)))
        {
            break;
        }

        if (entryDllBase == ModuleBase) {
            entryAddr = currentEntry;

            //
            // Save all three list entry pointers for this module
            //
            if (!ReadProcessPhysicalMemory(ProcessId,
                    entryAddr + 0x00, inLoadOrder, sizeof(inLoadOrder)))
            {
                break;
            }
            if (!ReadProcessPhysicalMemory(ProcessId,
                    entryAddr + 0x10, inMemoryOrder, sizeof(inMemoryOrder)))
            {
                break;
            }
            if (!ReadProcessPhysicalMemory(ProcessId,
                    entryAddr + 0x20, inInitOrder, sizeof(inInitOrder)))
            {
                break;
            }

            //
            // InLoadOrder: Flink->Blink = Blink, Blink->Flink = Flink
            //
            flink = (LIST_ENTRY64 *)(inLoadOrder + 0);
            blink = (LIST_ENTRY64 *)(inLoadOrder + sizeof(DWORD64));

            // Flink->Blink = Blink
            WriteProcessPhysicalMemory(ProcessId,
                (DWORD64)flink->Flink + sizeof(DWORD64),
                &blink, sizeof(DWORD64));

            // Blink->Flink = Flink
            WriteProcessPhysicalMemory(ProcessId,
                (DWORD64)blink->Blink + 0,
                &flink, sizeof(DWORD64));

            //
            // Repeat for InMemoryOrder (offset +0x10)
            //
            flink = (LIST_ENTRY64 *)(inMemoryOrder + 0);
            blink = (LIST_ENTRY64 *)(inMemoryOrder + sizeof(DWORD64));

            WriteProcessPhysicalMemory(ProcessId,
                (DWORD64)flink->Flink + sizeof(DWORD64),
                &blink, sizeof(DWORD64));
            WriteProcessPhysicalMemory(ProcessId,
                (DWORD64)blink->Blink + 0,
                &flink, sizeof(DWORD64));

            //
            // Repeat for InInitializationOrder (offset +0x20)
            //
            flink = (LIST_ENTRY64 *)(inInitOrder + 0);
            blink = (LIST_ENTRY64 *)(inInitOrder + sizeof(DWORD64));

            WriteProcessPhysicalMemory(ProcessId,
                (DWORD64)flink->Flink + sizeof(DWORD64),
                &blink, sizeof(DWORD64));
            WriteProcessPhysicalMemory(ProcessId,
                (DWORD64)blink->Blink + 0,
                &flink, sizeof(DWORD64));

            //
            // Zero the entry to prevent re-traversal
            //
            ZeroMemory(inLoadOrder, sizeof(inLoadOrder));
            WriteProcessPhysicalMemory(ProcessId,
                entryAddr, inLoadOrder, sizeof(inLoadOrder));

            return TRUE;
        }

        currentEntry = (DWORD64)((LIST_ENTRY64 *)inLoadOrder)->Flink;
    }

    SetLastError(ERROR_NOT_FOUND);
    return FALSE;
}

//
// Protect a process by manipulating the EPROCESS protection byte.
// This prevents other processes from opening handles with certain access rights.
//
BOOL
ProtectProcess(
    _In_ DWORD ProcessId
    )
{
    DWORD64 eprocessAddr;
    BYTE    protection = 0;   // PS_PROTECTED_SYSTEM (highest protection)

    eprocessAddr = GetEprocessAddress(ProcessId);
    if (eprocessAddr == 0) {
        return FALSE;
    }

    return WriteEprocessField(
        eprocessAddr,
        g_EprocessOffsets.Protection,
        &protection,
        sizeof(protection)
    );
}

//
// Remove PPL/PROTECTION from a process by zeroing the Protection byte.
//
BOOL
UnprotectProcess(
    _In_ DWORD ProcessId
    )
{
    DWORD64 eprocessAddr;
    BYTE    protection = 0;

    eprocessAddr = GetEprocessAddress(ProcessId);
    if (eprocessAddr == 0) {
        return FALSE;
    }

    return WriteEprocessField(
        eprocessAddr,
        g_EprocessOffsets.Protection,
        &protection,
        sizeof(protection)
    );
}

//
// Read process memory via kernel (physical memory translation).
// Bypasses all user-mode hooks including NtReadVirtualMemory API hooks.
//
BOOL
ReadProcessMemoryKernel(
    _In_ DWORD DestProcessId,
    _In_ DWORD64 Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
{
    return ReadProcessPhysicalMemory(
        DestProcessId,
        Address,
        Buffer,
        (DWORD)Size
    );
}

//
// Write process memory via kernel.
// Bypasses all user-mode memory write monitoring.
//
BOOL
WriteProcessMemoryKernel(
    _In_ DWORD DestProcessId,
    _In_ DWORD64 Address,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
{
    return WriteProcessPhysicalMemory(
        DestProcessId,
        Address,
        Buffer,
        (DWORD)Size
    );
}

//
// Change memory protection via kernel PTEs.
// Directly modifies the PTE (Page Table Entry) to set new protection flags.
// This is equivalent to VirtualProtectEx but at the kernel level.
//
BOOL
SetMemoryProtectionKernel(
    _In_ DWORD ProcessId,
    _In_ DWORD64 Address,
    _In_ SIZE_T Size,
    _In_ DWORD NewProtect,
    _Out_ PDWORD OldProtect
    )
{
    //
    // This requires direct PTE manipulation via physical memory.
    // The page table base (CR3) is in the EPROCESS structure.
    // Walk PML4 -> PDPT -> PD -> PT -> PTE, modify the NX/RW bits.
    //
    // Stub: real implementation requires CR3 read + page table walk.
    //
    (void)ProcessId;
    (void)Address;
    (void)Size;
    (void)NewProtect;

    if (OldProtect) {
        *OldProtect = 0;
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

//
// Locate GameGuard processes, remove PPL protection, and disable monitoring.
//
BOOL
BypassGameGuard(VOID)
{
    //
    // Delegate to ppl_bypass.c
    //
    // This is declared in ppl_bypass.c as BypassGameGuardInternal();
    // The actual bypass logic is in ppl_bypass.c.
    //

    //
    // Step 1: Enumerate processes for GameMon64.des and ErrpGameGuard.exe
    // Step 2: Remove PPL protection via EPROCESS write
    // Step 3: Open process and suspend threads
    // Step 4: Optionally patch GameGuard driver communication
    //

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}
