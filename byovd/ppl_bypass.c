#include "driver_loader.h"
#include "kernel_ops.h"
#include <tlhelp32.h>
#include <psapi.h>

//
// PPL (Protected Process Light) Bypass
//
// GameGuard (GameMon64.des) runs as a PPL-protected process.
// PPL prevents:
//   - OpenProcess(PROCESS_ALL_ACCESS) from non-PPL processes
//   - TerminateProcess / SuspendThread from user-mode
//   - ReadProcessMemory / WriteProcessMemory
//   - Setting debug privileges on the process
//
// Bypass technique:
//   1. Use vulnerable driver to read/write physical memory
//   2. Locate GameGuard's EPROCESS structure
//   3. Zero the Protection field (offset varies by Windows build)
//   4. Now we can open the process with full access
//   5. Suspend all threads to disable AC scans
//

//
// Known GameGuard process names
//
static const PCSTR g_GameGuardProcesses[] = {
    "GameMon64.des",
    "ErrpGameGuard.exe",
    "GameGuard.des",
    NULL
};

//
// Target process identifiers
//
typedef struct _GG_PROCESS {
    DWORD   ProcessId;
    CHAR    ProcessName[32];
    DWORD64 EprocessAddr;
    HANDLE  ProcessHandle;
    BYTE    OriginalProtection;
    BOOLEAN ProtectionModified;
} GG_PROCESS, *PGG_PROCESS;

static GG_PROCESS g_GgTargets[8];
static DWORD      g_GgTargetCount = 0;
static BOOL       g_BypassActive = FALSE;

//
// Enumerate running processes to find GameGuard instances.
//
static BOOL
FindGameGuardProcesses(VOID)
{
    HANDLE         snapshot;
    PROCESSENTRY32 pe;
    DWORD          found = 0;
    DWORD          i, j;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    pe.dwSize = sizeof(pe);
    if (!Process32First(snapshot, &pe)) {
        CloseHandle(snapshot);
        return FALSE;
    }

    do {
        for (i = 0; g_GameGuardProcesses[i] != NULL; i++) {
            if (_stricmp(pe.szExeFile, g_GameGuardProcesses[i]) == 0 &&
                found < ARRAYSIZE(g_GgTargets))
            {
                //
                // Check for duplicates
                //
                BOOL duplicate = FALSE;
                for (j = 0; j < found; j++) {
                    if (g_GgTargets[j].ProcessId == pe.th32ProcessID) {
                        duplicate = TRUE;
                        break;
                    }
                }

                if (!duplicate) {
                    g_GgTargets[found].ProcessId = pe.th32ProcessID;
                    (void)strncpy(g_GgTargets[found].ProcessName,
                        pe.szExeFile, sizeof(g_GgTargets[found].ProcessName) - 1);
                    g_GgTargets[found].EprocessAddr = 0;
                    g_GgTargets[found].ProcessHandle = NULL;
                    g_GgTargets[found].OriginalProtection = 0;
                    g_GgTargets[found].ProtectionModified = FALSE;
                    found++;
                }
                break;
            }
        }
    } while (Process32Next(snapshot, &pe));

    CloseHandle(snapshot);
    g_GgTargetCount = found;
    return (found > 0);
}

//
// Open a GameGuard process handle.
// Before PPL bypass, the handle may have limited access.
//
static HANDLE
OpenGameGuardProcess(
    _In_ DWORD ProcessId,
    _In_ DWORD DesiredAccess
    )
{
    HANDLE handle;

    handle = OpenProcess(DesiredAccess, FALSE, ProcessId);

    //
    // If PPL blocks this, try with PROCESS_QUERY_INFORMATION first
    //
    if (handle == NULL) {
        handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    }

    return handle;
}

//
// Read the PS_PROTECTION byte from a process via EPROCESS physical memory.
// Returns the protection level (0 = unprotected, 0x01 = PS_PROTECTED_LIGHT, etc.)
//
static BYTE
ReadProcessProtection(
    _In_ DWORD64 EprocessAddr
    )
{
    EPROCESS_OFFSETS offsets;
    BYTE             protection = 0;

    if (!GetEprocessOffsets(&offsets)) {
        return 0;
    }

    if (!ReadPhysicalMemory(
            EprocessAddr + offsets.Protection,
            &protection,
            sizeof(protection)))
    {
        return 0;
    }

    return protection;
}

//
// Write a new protection value to the EPROCESS Protection field.
//
static BOOL
WriteProcessProtection(
    _In_ DWORD64 EprocessAddr,
    _In_ BYTE NewProtection
    )
{
    EPROCESS_OFFSETS offsets;

    if (!GetEprocessOffsets(&offsets)) {
        return FALSE;
    }

    return WritePhysicalMemory(
        EprocessAddr + offsets.Protection,
        &NewProtection,
        sizeof(NewProtection)
    );
}

//
// Suspend all threads in a target process.
//
static BOOL
SuspendProcessThreads(
    _In_ DWORD ProcessId
    )
{
    HANDLE snapshot;
    THREADENTRY32 te;
    HANDLE threadHandle;
    DWORD  suspended = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    te.dwSize = sizeof(te);
    if (!Thread32First(snapshot, &te)) {
        CloseHandle(snapshot);
        return FALSE;
    }

    do {
        if (te.th32OwnerProcessID == ProcessId &&
            te.th32ThreadID != GetCurrentThreadId())
        {
            threadHandle = OpenThread(
                THREAD_SUSPEND_RESUME,
                FALSE,
                te.th32ThreadID
            );

            if (threadHandle != NULL) {
                if (SuspendThread(threadHandle) != (DWORD)-1) {
                    suspended++;
                }
                CloseHandle(threadHandle);
            }
        }
    } while (Thread32Next(snapshot, &te));

    CloseHandle(snapshot);
    return (suspended > 0);
}

//
// Resume all threads in a target process.
//
static BOOL
ResumeProcessThreads(
    _In_ DWORD ProcessId
    )
{
    HANDLE snapshot;
    THREADENTRY32 te;
    HANDLE threadHandle;
    DWORD  resumed = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    te.dwSize = sizeof(te);
    if (!Thread32First(snapshot, &te)) {
        CloseHandle(snapshot);
        return FALSE;
    }

    do {
        if (te.th32OwnerProcessID == ProcessId &&
            te.th32ThreadID != GetCurrentThreadId())
        {
            threadHandle = OpenThread(
                THREAD_SUSPEND_RESUME,
                FALSE,
                te.th32ThreadID
            );

            if (threadHandle != NULL) {
                if (ResumeThread(threadHandle) != (DWORD)-1) {
                    resumed++;
                }
                CloseHandle(threadHandle);
            }
        }
    } while (Thread32Next(snapshot, &te));

    CloseHandle(snapshot);
    return (resumed > 0);
}

//
// Main PPL bypass routine.
// 1. Find GameGuard processes
// 2. Read their EPROCESS Protection byte
// 3. Clear it (remove PPL)
// 4. Open process with full access
// 5. Suspend threads
//
BOOL
BypassGameGuard(VOID)
{
    DWORD i;
    BOOL  success = FALSE;

    if (g_BypassActive) {
        return TRUE;   // Already bypassed
    }

    //
    // Step 1: Find GameGuard processes
    //
    if (!FindGameGuardProcesses()) {
        SetLastError(ERROR_NOT_FOUND);
        return FALSE;
    }

    //
    // Step 2-4: For each GameGuard process, bypass PPL
    //
    for (i = 0; i < g_GgTargetCount; i++) {
        PGG_PROCESS target = &g_GgTargets[i];

        //
        // Get EPROCESS physical address
        //
        target->EprocessAddr = GetEprocessAddress(target->ProcessId);
        if (target->EprocessAddr == 0) {
            //
            // Fallback: try to open with limited access first
            //
            target->ProcessHandle = OpenGameGuardProcess(
                target->ProcessId,
                PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME
            );

            if (target->ProcessHandle == NULL) {
                continue;
            }

            //
            // We have limited access only — need kernel EPROCESS write
            // to remove PPL before we can do more.
            //
            continue;
        }

        //
        // Save and clear the Protection byte
        //
        target->OriginalProtection = ReadProcessProtection(
            target->EprocessAddr
        );

        if (target->OriginalProtection != 0) {
            if (WriteProcessProtection(target->EprocessAddr, 0)) {
                target->ProtectionModified = TRUE;
            }
        }

        //
        // Now try to open with full access
        //
        target->ProcessHandle = OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            target->ProcessId
        );

        if (target->ProcessHandle == NULL) {
            //
            // Might need PROCESS_TERMINATE + PROCESS_SUSPEND_RESUME
            //
            target->ProcessHandle = OpenProcess(
                PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME |
                PROCESS_VM_READ | PROCESS_VM_WRITE |
                PROCESS_QUERY_INFORMATION,
                FALSE,
                target->ProcessId
            );
        }

        if (target->ProcessHandle != NULL) {
            //
            // Suspend all threads to disable AC scanning
            //
            SuspendProcessThreads(target->ProcessId);
            success = TRUE;
        }
    }

    g_BypassActive = success;
    return success;
}

//
// Restore original PPL protection on all GameGuard targets.
// Called during cleanup to leave the system in a clean state.
//
BOOL
RestoreGameGuardProtection(VOID)
{
    DWORD i;
    BOOL  result = TRUE;

    for (i = 0; i < g_GgTargetCount; i++) {
        PGG_PROCESS target = &g_GgTargets[i];

        if (target->ProcessHandle != NULL) {
            //
            // Resume threads first
            //
            ResumeProcessThreads(target->ProcessId);

            //
            // Restore protection byte
            //
            if (target->ProtectionModified &&
                target->EprocessAddr != 0)
            {
                WriteProcessProtection(
                    target->EprocessAddr,
                    target->OriginalProtection
                );
            }

            CloseHandle(target->ProcessHandle);
        }
    }

    g_GgTargetCount = 0;
    g_BypassActive = FALSE;

    return result;
}

//
// Terminate GameGuard process entirely (destructive — may trigger detection).
//
BOOL
TerminateGameGuard(VOID)
{
    DWORD i;

    if (!BypassGameGuard()) {
        return FALSE;
    }

    for (i = 0; i < g_GgTargetCount; i++) {
        if (g_GgTargets[i].ProcessHandle != NULL) {
            TerminateProcess(g_GgTargets[i].ProcessHandle, 0);
        }
    }

    return TRUE;
}

//
// Check if any GameGuard process is currently running.
//
BOOL
IsGameGuardRunning(VOID)
{
    return FindGameGuardProcesses();
}
