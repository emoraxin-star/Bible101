#include "indirect_syscall.h"
#include "hades_gate.h"
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>

//
// Forward declaration of bootstrap function from indirect_syscall.c
//
extern BOOL BootstrapNtFunctions(void);

//
// Complete syscall stub table: 64 NT functions.
// Functions are grouped by category for readability.
//

// -----------------------------------------------------------------
// Typedefs for all NT syscall wrappers
// -----------------------------------------------------------------

// Memory
typedef NTSTATUS (NTAPI* TNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI* TNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI* TNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI* TNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI* TNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI* TNtQueryVirtualMemory)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI* TNtFlushVirtualMemory)(HANDLE, PVOID*, PSIZE_T, PIO_STATUS_BLOCK);

// Process / Thread
typedef NTSTATUS (NTAPI* TNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI* TNtClose)(HANDLE);
typedef NTSTATUS (NTAPI* TNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI* TNtOpenThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI* TNtSuspendProcess)(HANDLE);
typedef NTSTATUS (NTAPI* TNtResumeProcess)(HANDLE);
typedef NTSTATUS (NTAPI* TNtSuspendThread)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI* TNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI* TNtGetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI* TNtSetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI* TNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* TNtSetInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
typedef NTSTATUS (NTAPI* TNtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* TNtSetInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
typedef NTSTATUS (NTAPI* TNtTerminateProcess)(HANDLE, NTSTATUS);
typedef NTSTATUS (NTAPI* TNtTerminateThread)(HANDLE, NTSTATUS);

// File I/O
typedef NTSTATUS (NTAPI* TNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI* TNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS (NTAPI* TNtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, LONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS (NTAPI* TNtSetInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, LONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS (NTAPI* TNtQueryDirectoryFile)(HANDLE, HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PVOID, BOOLEAN);
typedef NTSTATUS (NTAPI* TNtDeviceIoControlFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI* TNtFsControlFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI* TNtCancelIoFileEx)(HANDLE, PIO_STATUS_BLOCK);

// Registry
typedef NTSTATUS (NTAPI* TNtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI* TNtCreateKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS (NTAPI* TNtQueryValueKey)(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* TNtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI* TNtDeleteKey)(HANDLE);
typedef NTSTATUS (NTAPI* TNtDeleteValueKey)(HANDLE, PUNICODE_STRING);
typedef NTSTATUS (NTAPI* TNtEnumerateKey)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* TNtEnumerateValueKey)(HANDLE, ULONG, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* TNtFlushKey)(HANDLE);
typedef NTSTATUS (NTAPI* TNtQueryKey)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* TNtRenameKey)(HANDLE, PUNICODE_STRING);

// Synchronization
typedef NTSTATUS (NTAPI* TNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI* TNtWaitForMultipleObjects)(ULONG, PHANDLE, WAIT_TYPE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI* TNtSignalAndWaitForSingleObject)(HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI* TNtCreateEvent)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE, BOOLEAN);
typedef NTSTATUS (NTAPI* TNtOpenEvent)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI* TNtSetEvent)(HANDLE, PLONG);
typedef NTSTATUS (NTAPI* TNtResetEvent)(HANDLE, PLONG);
typedef NTSTATUS (NTAPI* TNtCreateMutant)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN);
typedef NTSTATUS (NTAPI* TNtReleaseMutant)(HANDLE, PLONG);
typedef NTSTATUS (NTAPI* TNtCreateSemaphore)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG);
typedef NTSTATUS (NTAPI* TNtReleaseSemaphore)(HANDLE, LONG, PLONG);
typedef NTSTATUS (NTAPI* TNtCreateTimer)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, TIMER_TYPE);
typedef NTSTATUS (NTAPI* TNtSetTimer)(HANDLE, PLARGE_INTEGER, PVOID, PVOID, BOOLEAN, PLONG);

// Object / Handle
typedef NTSTATUS (NTAPI* TNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* TNtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);

// Token
typedef NTSTATUS (NTAPI* TNtOpenProcessToken)(HANDLE, ACCESS_MASK, PHANDLE);
typedef NTSTATUS (NTAPI* TNtOpenThreadToken)(HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE);
typedef NTSTATUS (NTAPI* TNtQueryInformationToken)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* TNtAdjustPrivilegesToken)(HANDLE, BOOLEAN, PVOID, ULONG, PVOID, PULONG);

// Section / Mapping
typedef NTSTATUS (NTAPI* TNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI* TNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI* TNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS (NTAPI* TNtUnmapViewOfSection)(HANDLE, PVOID);

// Time / Execution
typedef NTSTATUS (NTAPI* TNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI* TNtYieldExecution)(void);
typedef NTSTATUS (NTAPI* TNtQuerySystemTime)(PLARGE_INTEGER);
typedef NTSTATUS (NTAPI* TNtSetSystemTime)(PLARGE_INTEGER, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI* TNtQueryPerformanceCounter)(PLARGE_INTEGER, PLARGE_INTEGER);

// System / Info
typedef NTSTATUS (NTAPI* TNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* TNtSetSystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS (NTAPI* TNtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, HARDERROR_RESPONSE_OPTION, PHARDERROR_RESPONSE);

// -----------------------------------------------------------------
// Master table of all 64 functions with their names
// -----------------------------------------------------------------

typedef struct _NT_FUNCTION_DEF {
    PCSTR Name;
} NT_FUNCTION_DEF;

#define NT_FUNCTION_COUNT 64

static const NT_FUNCTION_DEF g_NtFunctions[NT_FUNCTION_COUNT] =
{
    // Memory (7)
    { "NtAllocateVirtualMemory"     },
    { "NtFreeVirtualMemory"         },
    { "NtProtectVirtualMemory"      },
    { "NtReadVirtualMemory"         },
    { "NtWriteVirtualMemory"        },
    { "NtQueryVirtualMemory"        },
    { "NtFlushVirtualMemory"        },

    // Process / Thread (16)
    { "NtOpenProcess"               },
    { "NtClose"                     },
    { "NtCreateThreadEx"            },
    { "NtOpenThread"                },
    { "NtSuspendProcess"            },
    { "NtResumeProcess"             },
    { "NtSuspendThread"             },
    { "NtResumeThread"              },
    { "NtGetContextThread"          },
    { "NtSetContextThread"          },
    { "NtQueryInformationProcess"   },
    { "NtSetInformationProcess"     },
    { "NtQueryInformationThread"    },
    { "NtSetInformationThread"      },
    { "NtTerminateProcess"          },
    { "NtTerminateThread"           },

    // File I/O (8)
    { "NtCreateFile"                },
    { "NtOpenFile"                  },
    { "NtQueryInformationFile"      },
    { "NtSetInformationFile"        },
    { "NtQueryDirectoryFile"        },
    { "NtDeviceIoControlFile"       },
    { "NtFsControlFile"             },
    { "NtCancelIoFileEx"            },

    // Registry (11)
    { "NtOpenKey"                   },
    { "NtCreateKey"                 },
    { "NtQueryValueKey"             },
    { "NtSetValueKey"               },
    { "NtDeleteKey"                 },
    { "NtDeleteValueKey"            },
    { "NtEnumerateKey"              },
    { "NtEnumerateValueKey"         },
    { "NtFlushKey"                  },
    { "NtQueryKey"                  },
    { "NtRenameKey"                 },

    // Synchronization (12)
    { "NtWaitForSingleObject"       },
    { "NtWaitForMultipleObjects"    },
    { "NtSignalAndWaitForSingleObject" },
    { "NtCreateEvent"               },
    { "NtOpenEvent"                 },
    { "NtSetEvent"                  },
    { "NtResetEvent"                },
    { "NtCreateMutant"              },
    { "NtReleaseMutant"             },
    { "NtCreateSemaphore"           },
    { "NtReleaseSemaphore"          },
    { "NtCreateTimer"               },

    // Object / Handle (2)
    { "NtQueryObject"               },
    { "NtDuplicateObject"           },

    // Token (4)
    { "NtOpenProcessToken"          },
    { "NtOpenThreadToken"           },
    { "NtQueryInformationToken"     },
    { "NtAdjustPrivilegesToken"     },

    // Section / Mapping (4)
    { "NtCreateSection"             },
    { "NtOpenSection"               },
    { "NtMapViewOfSection"          },
    { "NtUnmapViewOfSection"        },

    // Time / Execution (4)
    { "NtDelayExecution"            },
    { "NtYieldExecution"            },
    { "NtQuerySystemTime"           },
    { "NtQueryPerformanceCounter"   },
};

// -----------------------------------------------------------------
// Global registry for all stub entries
// -----------------------------------------------------------------

static SYSCALL_REGISTRY g_StubRegistry;
static SYSCALL_STUB_ENTRY g_StubEntries[NT_FUNCTION_COUNT];
static BOOL g_StubsInitialized = FALSE;

//
// Extract stub pointers as callable function pointers for each function.
// These are populated after BuildAllStubs().
//
static PVOID g_StubPointers[NtMaximumProcessInformation + 1]; // indexed by SSN?

//
// Build all stubs from the master function table.
// Returns the number of stubs successfully built.
//
ULONG BuildAllStubs(void)
{
    PVOID NtdllBase;
    PVOID RetGadget;
    ULONG Built = 0;
    ULONG Seed;
    ULONG i;

    if (g_StubsInitialized)
        return g_StubRegistry.Count;

    //
    // Bootstrap: resolve addresses for page allocation/protection from in-memory ntdll
    //
    if (!BootstrapNtFunctions())
        return 0;

    NtdllBase = HadesGetNtdllBase();
    if (!NtdllBase)
        return 0;

    //
    // Seed RDTSC
    //
    Seed = (ULONG)__rdtsc();

    //
    // Find a RET gadget in ntdll's .text section for stack spoofing
    //
    RetGadget = FindRetGadgetInNtdll(NtdllBase);
    if (!RetGadget)
        return 0;

    SyscallRegistryInit(&g_StubRegistry);

    for (i = 0; i < NT_FUNCTION_COUNT; i++)
    {
        ULONG ssn;
        ULONG stubSize = 0;
        PVOID stubAddr;

        //
        // Resolve SSN via Hades Gate (PEB walk, no disk read)
        //
        ssn = HadesGetSSN(NtdllBase, g_NtFunctions[i].Name);
        if (ssn == 0)
            continue;

        //
        // Build diverse stub with stack spoofing
        //
        Seed = LCGNext(&Seed);
        stubAddr = BuildIndirectSyscallStubDiverse(ssn, RetGadget, Seed, &stubSize);
        if (!stubAddr)
            continue;

        //
        // Flip page to RX (W^X compliance)
        //
        if (!MakeStubExecutableReadOnly(stubAddr, stubSize))
        {
            DestroyStub(stubAddr, stubSize);
            continue;
        }

        //
        // Populate stub entry
        //
        ZeroMemory(&g_StubEntries[Built], sizeof(SYSCALL_STUB_ENTRY));
        strcpy_s(g_StubEntries[Built].FunctionName, sizeof(g_StubEntries[Built].FunctionName), g_NtFunctions[i].Name);
        g_StubEntries[Built].SSN = ssn;
        g_StubEntries[Built].StubAddress = stubAddr;
        g_StubEntries[Built].StubSize = stubSize;
        g_StubEntries[Built].NtdllRetGadget = RetGadget;

        SyscallRegistryInsert(&g_StubRegistry, &g_StubEntries[Built]);
        Built++;
    }

    g_StubsInitialized = TRUE;
    return Built;
}

//
// Get the global stub registry
//
PSYSCALL_REGISTRY GetStubRegistry(void)
{
    if (!g_StubsInitialized)
        return NULL;
    return &g_StubRegistry;
}

//
// Get the initialized flag
//
BOOL AreStubsInitialized(void)
{
    return g_StubsInitialized;
}

//
// Destroy all stubs (cleanup)
//
void DestroyAllStubs(void)
{
    ULONG i;

    for (i = 0; i < g_StubRegistry.Count; i++)
    {
        if (g_StubEntries[i].StubAddress)
        {
            DestroyStub(g_StubEntries[i].StubAddress, g_StubEntries[i].StubSize);
            g_StubEntries[i].StubAddress = NULL;
            g_StubEntries[i].StubSize = 0;
            g_StubEntries[i].SSN = 0;
            ZeroMemory(g_StubEntries[i].FunctionName, sizeof(g_StubEntries[i].FunctionName));
        }
    }

    g_StubsInitialized = FALSE;
}
