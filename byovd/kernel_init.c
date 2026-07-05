#include "driver_loader.h"
#include "kernel_ops.h"

//
// Forward declarations from other modules
//
extern BOOL MsrInit(VOID);
extern VOID MsrCleanup(VOID);
extern BOOL MemInit(VOID);
extern VOID MemCleanup(VOID);

extern BOOL BypassGameGuard(VOID);
extern BOOL RestoreGameGuardProtection(VOID);

//
// Active driver state
//
typedef struct _KERNEL_CONTEXT {
    BOOLEAN        Initialized;
    ACTIVE_DRIVER  ActiveDriver;
    DRIVER_CAPABILITIES Capabilities;
    HANDLE         MonitorThread;
    volatile LONG  ShutdownFlag;
} KERNEL_CONTEXT, *PKERNEL_CONTEXT;

static KERNEL_CONTEXT g_KernelContext;

//
// Known .sys file names bundled with the cheat
//
static const PCSTR g_DriverBundles[] = {
    "RTCore64.sys",
    "GLCKIO2.sys",
    "gdrv.sys",
    NULL
};

//
// Resolve the path where drivers are bundled.
// In production, drivers would be extracted from the cheat's embedded resources.
//
static BOOL
GetDriverBundlePath(
    _Out_writes_(MAX_PATH) PCHAR OutputPath,
    _In_ PCSTR DriverFileName
    )
{
    //
    // Drivers could be in the same directory as the cheat, or embedded as
    // resources. Here we check the current directory and a known subfolder.
    //
    CHAR modulePath[MAX_PATH];
    CHAR *sep;

    if (GetModuleFileNameA(NULL, modulePath, MAX_PATH) == 0) {
        return FALSE;
    }

    //
    // Strip executable name to get directory
    //
    sep = strrchr(modulePath, '\\');
    if (sep == NULL) {
        return FALSE;
    }
    *(sep + 1) = '\0';

    //
    // Check: <module_dir>\drivers\<DriverFileName>
    //
    (void)snprintf(OutputPath, MAX_PATH, "%sdrivers\\%s",
        modulePath, DriverFileName);

    if (GetFileAttributesA(OutputPath) != INVALID_FILE_ATTRIBUTES) {
        return TRUE;
    }

    //
    // Fallback: <module_dir>\<DriverFileName>
    //
    (void)snprintf(OutputPath, MAX_PATH, "%s%s",
        modulePath, DriverFileName);

    if (GetFileAttributesA(OutputPath) != INVALID_FILE_ATTRIBUTES) {
        return TRUE;
    }

    //
    // Fallback: %TEMP%\<DriverFileName>
    //
    if (GetTempPathA(MAX_PATH, OutputPath) > 0) {
        CHAR temp[MAX_PATH];
        (void)snprintf(temp, MAX_PATH, "%s%s", OutputPath, DriverFileName);
        if (GetFileAttributesA(temp) != INVALID_FILE_ATTRIBUTES) {
            (void)strncpy(OutputPath, temp, MAX_PATH - 1);
            return TRUE;
        }
    }

    return FALSE;
}

//
// Determine driver capabilities from known driver info.
//
static void
GetDriverCapabilities(
    _In_ PVULNERABLE_DRIVER DriverInfo,
    _Out_ PDRIVER_CAPABILITIES Caps
    )
{
    ZeroMemory(Caps, sizeof(*Caps));

    if (DriverInfo == NULL) return;

    if (_stricmp(DriverInfo->ServiceName, "RTCore64") == 0) {
        Caps->CanReadMsr  = TRUE;
        Caps->CanWriteMsr = TRUE;
    } else if (_stricmp(DriverInfo->ServiceName, "GLCKIO2") == 0) {
        Caps->CanReadPhysicalMemory  = TRUE;
        Caps->CanWritePhysicalMemory = TRUE;
        Caps->CanMapPhysicalMemory   = TRUE;
        Caps->CanReadVirtualMemory   = TRUE;
        Caps->CanWriteVirtualMemory  = TRUE;
    } else if (_stricmp(DriverInfo->ServiceName, "gdrv") == 0) {
        Caps->CanReadPhysicalMemory  = TRUE;
        Caps->CanWritePhysicalMemory = TRUE;
        Caps->CanReadVirtualMemory   = TRUE;
        Caps->CanWriteVirtualMemory  = TRUE;
    }
}

//
// Initialization priority order:
//   1. GLCKIO2 (best — physical memory access for EPROCESS manipulation)
//   2. RTCore64 (MSR access — useful but less capable for our needs)
//   3. gdrv (fallback)
//
static PCSTR
SelectBestDriver(VOID)
{
    DWORD           count = 4;
    VULNERABLE_DRIVER drivers[4];
    DWORD           i;

    //
    // Check which drivers are already on the system
    //
    if (FindVulnerableDriver(drivers, &count)) {
        //
        // Prefer GLCKIO2 for physical memory access
        //
        for (i = 0; i < count; i++) {
            if (_stricmp(drivers[i].ServiceName, "GLCKIO2") == 0) {
                return drivers[i].ServiceName;
            }
        }

        //
        // Fall back to RTCore64
        //
        for (i = 0; i < count; i++) {
            if (_stricmp(drivers[i].ServiceName, "RTCore64") == 0) {
                return drivers[i].ServiceName;
            }
        }

        //
        // Use any available driver
        //
        return drivers[0].ServiceName;
    }

    return NULL;
}

//
// Kernel monitor thread: runs while cheat is active to:
//   - Monitor GameGuard resurrection (if it restarts, bypass again)
//   - Periodically verify our driver is still loaded
//   - Keep the cheat's kernel state alive
//
static DWORD WINAPI
KernelMonitorThread(
    _In_ LPVOID Parameter
    )
{
    PKERNEL_CONTEXT ctx = (PKERNEL_CONTEXT)Parameter;

    while (!ctx->ShutdownFlag) {
        //
        // Check every 5 seconds
        //
        Sleep(5000);

        if (ctx->ShutdownFlag) break;

        //
        // Check if GameGuard has reappeared (new process)
        //
        if (IsGameGuardRunning()) {
            BypassGameGuard();
        }

        //
        // Verify driver device handle is still valid
        //
        if (ctx->ActiveDriver.DeviceHandle == INVALID_HANDLE_VALUE ||
            ctx->ActiveDriver.DeviceHandle == NULL)
        {
            //
            // Driver may have been unloaded — attempt reload
            //
            // (Production code would attempt reload here)
            //
            break;
        }
    }

    return 0;
}

//
// Primary initialization entry point.
// Call this once after injection to set up kernel access.
//
BOOL
KernelInitialize(VOID)
{
    PCSTR driverName;
    CHAR  driverPath[MAX_PATH];
    DWORD i;

    if (g_KernelContext.Initialized) {
        return TRUE;   // Already initialized
    }

    ZeroMemory(&g_KernelContext, sizeof(g_KernelContext));
    g_KernelContext.ActiveDriver.DeviceHandle = INVALID_HANDLE_VALUE;

    //
    // Step 1: Scan for already-loaded vulnerable drivers
    //
    driverName = SelectBestDriver();
    if (driverName != NULL) {
        //
        // Driver already loaded on system — just open device handle
        //
        PVULNERABLE_DRIVER info = GetDriverInfo(driverName);
        if (info != NULL) {
            g_KernelContext.ActiveDriver.DeviceHandle =
                GetDriverDeviceHandle(info->DeviceName);

            if (g_KernelContext.ActiveDriver.DeviceHandle == INVALID_HANDLE_VALUE) {
                //
                // Try \\.\DriverName directly
                //
                CHAR devPath[64];
                (void)snprintf(devPath, sizeof(devPath), "\\\\.\\%s", driverName);
                g_KernelContext.ActiveDriver.DeviceHandle =
                    CreateFileA(devPath, GENERIC_READ | GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING, 0, NULL);
            }

            if (g_KernelContext.ActiveDriver.DeviceHandle != INVALID_HANDLE_VALUE)
            {
                g_KernelContext.ActiveDriver.DriverInfo = info;
                GetDriverCapabilities(info, &g_KernelContext.Capabilities);
            }
        }
    }

    //
    // Step 2: If no existing driver found, try loading one from bundle
    //
    if (g_KernelContext.ActiveDriver.DeviceHandle == INVALID_HANDLE_VALUE) {
        for (i = 0; g_DriverBundles[i] != NULL; i++) {
            if (!GetDriverBundlePath(driverPath, g_DriverBundles[i])) {
                continue;
            }

            if (LoadVulnerableDriver(
                    g_DriverBundles[i],
                    driverPath,
                    &g_KernelContext.ActiveDriver))
            {
                GetDriverCapabilities(
                    g_KernelContext.ActiveDriver.DriverInfo,
                    &g_KernelContext.Capabilities
                );
                break;
            }
        }
    }

    //
    // Check if we have any driver access
    //
    if (g_KernelContext.ActiveDriver.DeviceHandle == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_DRIVER_UNABLE_TO_LOAD);
        return FALSE;
    }

    //
    // Step 3: Initialize sub-systems based on capabilities
    //
    if (g_KernelContext.Capabilities.CanReadMsr ||
        g_KernelContext.Capabilities.CanWriteMsr)
    {
        MsrInit();
    }

    if (g_KernelContext.Capabilities.CanReadPhysicalMemory ||
        g_KernelContext.Capabilities.CanWritePhysicalMemory)
    {
        MemInit();
    }

    //
    // Step 4: Bypass GameGuard
    //
    if (g_KernelContext.Capabilities.CanReadPhysicalMemory &&
        g_KernelContext.Capabilities.CanWritePhysicalMemory)
    {
        BypassGameGuard();
    }

    //
    // Step 5: Start kernel monitor thread
    //
    g_KernelContext.MonitorThread = CreateThread(
        NULL,
        0,
        KernelMonitorThread,
        &g_KernelContext,
        0,
        NULL
    );

    g_KernelContext.Initialized = TRUE;
    return TRUE;
}

//
// Clean up kernel access.
// Call before exiting to unload the driver and restore system state.
//
VOID
KernelShutdown(VOID)
{
    if (!g_KernelContext.Initialized) {
        return;
    }

    //
    // Signal monitor thread to exit
    //
    InterlockedExchange(&g_KernelContext.ShutdownFlag, 1);

    if (g_KernelContext.MonitorThread != NULL) {
        if (WaitForSingleObject(g_KernelContext.MonitorThread, 3000) ==
            WAIT_TIMEOUT)
        {
            TerminateThread(g_KernelContext.MonitorThread, 0);
        }
        CloseHandle(g_KernelContext.MonitorThread);
    }

    //
    // Restore GameGuard PPL protection
    //
    RestoreGameGuardProtection();

    //
    // Cleanup sub-systems
    //
    MsrCleanup();
    MemCleanup();

    //
    // Unload the vulnerable driver if we loaded it
    //
    if (g_KernelContext.ActiveDriver.ServiceHandle != NULL) {
        UnloadDriver(&g_KernelContext.ActiveDriver);
    } else if (g_KernelContext.ActiveDriver.DeviceHandle != INVALID_HANDLE_VALUE &&
               g_KernelContext.ActiveDriver.DeviceHandle != NULL)
    {
        CloseHandle(g_KernelContext.ActiveDriver.DeviceHandle);
    }

    ZeroMemory(&g_KernelContext, sizeof(g_KernelContext));
}
