#pragma once
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Known vulnerable driver registry entries
// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<Name>
//
typedef struct _VULNERABLE_DRIVER {
    PCSTR  ServiceName;      // e.g. "RTCore64"
    PCSTR  DisplayName;      // Display name
    PCSTR  DeviceName;       // \\.\DeviceName
    PCSTR  FileName;         // Driver .sys filename
    DWORD  KnownIoctlCount;  // Number of known IOCTL codes
    DWORD  IoctlCodes[16];   // Known IOCTL codes (max 16)
} VULNERABLE_DRIVER, *PVULNERABLE_DRIVER;

//
// Available capability flags from a loaded driver
//
typedef struct _DRIVER_CAPABILITIES {
    BOOLEAN CanReadMsr;
    BOOLEAN CanWriteMsr;
    BOOLEAN CanReadPhysicalMemory;
    BOOLEAN CanWritePhysicalMemory;
    BOOLEAN CanReadVirtualMemory;
    BOOLEAN CanWriteVirtualMemory;
    BOOLEAN CanMapPhysicalMemory;
} DRIVER_CAPABILITIES, *PDRIVER_CAPABILITIES;

//
// Active driver context (what we have loaded)
//
typedef struct _ACTIVE_DRIVER {
    PVULNERABLE_DRIVER DriverInfo;
    HANDLE             DeviceHandle;   // Handle from CreateFile
    SC_HANDLE          ScmHandle;      // SCM handle for cleanup
    SC_HANDLE          ServiceHandle;  // Service handle
    CHAR               SysFilePath[MAX_PATH];
} ACTIVE_DRIVER, *PACTIVE_DRIVER;

//
// Driver detection and loading
//
BOOL
FindVulnerableDriver(
    _Out_writes_(*Count) PVULNERABLE_DRIVER Drivers,
    _Inout_ PDWORD Count
    );

BOOL
LoadVulnerableDriver(
    _In_ PCSTR DriverName,
    _In_ PCSTR SysFilePath,
    _Out_ PACTIVE_DRIVER Context
    );

HANDLE
GetDriverDeviceHandle(
    _In_ PCSTR DeviceName
    );

BOOL
UnloadDriver(
    _Inout_ PACTIVE_DRIVER Context
    );

//
// Driver enumeration helper
//
BOOL
IsDriverLoaded(
    _In_ PCSTR ServiceName
    );

PVULNERABLE_DRIVER
GetDriverInfo(
    _In_ PCSTR DriverName
    );

#ifdef __cplusplus
}
#endif
