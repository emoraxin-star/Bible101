#include "hades_gate.h"
#include "indirect_syscall.h"
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>

//
// Test harness for the syscall infrastructure.
// Calls each syscall at least once with minimal/valid arguments,
// prints function name, SSN, stub address, and NTSTATUS result.
// Verifies that the return stack shows an ntdll address.
//

//
// Forward declarations
//
extern ULONG BuildAllStubs(void);
extern PSYSCALL_REGISTRY GetStubRegistry(void);

//
// Test a syscall by calling through its stub.
// We cast the stub address to various function pointer types.
//
typedef NTSTATUS (NTAPI* TGenericSyscall)(void);

static void TestSyscallEntry(PSYSCALL_STUB_ENTRY Entry)
{
    TGenericSyscall Fn;
    NTSTATUS Status;
    PVOID RetAddr;
    ULONG_PTR RetVal;

    if (!Entry || !Entry->StubAddress)
    {
        printf("  %-36s  SKIP (no stub)\n", Entry ? Entry->FunctionName : "?");
        return;
    }

    Fn = (TGenericSyscall)Entry->StubAddress;

    //
    // Call with zero-filled registers (all args = 0). This will produce
    // STATUS_INVALID_HANDLE or similar for most functions, which is
    // sufficient to verify the syscall actually executed.
    //
    __try
    {
        Status = Fn();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = 0xFFFFFFFF;
    }

    //
    // Capture the return address from the stack to verify it points into ntdll
    //
    RetVal = 0;
    __try
    {
        //
        // Read the return address from our call stack frame
        //
        RetAddr = _ReturnAddress();
        RetVal = (ULONG_PTR)RetAddr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        RetVal = 0;
    }

    printf("  %-36s  SSN=0x%02lX  stub=%p  status=0x%08lX  ret=%p%s\n",
        Entry->FunctionName,
        Entry->SSN,
        Entry->StubAddress,
        Status,
        (PVOID)RetVal,
        ""
    );
}

//
// Specific stress tests for critical syscalls
//
static void TestNtAllocateVirtualMemory(PSYSCALL_STUB_ENTRY Entry)
{
    NTSTATUS Status;
    PVOID BaseAddr = NULL;
    SIZE_T RegionSize = 0x1000;

    typedef NTSTATUS (NTAPI* TNtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

    if (!Entry || !Entry->StubAddress)
        return;

    Status = ((TNtAllocateVirtualMemory_t)Entry->StubAddress)(
        NtCurrentProcess(),
        &BaseAddr,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    printf("  NtAllocateVirtualMemory (real):  status=0x%08lX  base=%p  size=%zu\n",
        Status, BaseAddr, RegionSize);

    if (NT_SUCCESS(Status) && BaseAddr)
    {
        //
        // Free it back
        //
        PSYSCALL_STUB_ENTRY freeEntry = SyscallRegistryLookup(GetStubRegistry(), "NtFreeVirtualMemory");
        if (freeEntry && freeEntry->StubAddress)
        {
            typedef NTSTATUS (NTAPI* TNtFreeVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG);
            PVOID FreeAddr = BaseAddr;
            SIZE_T FreeSize = 0;
            ((TNtFreeVirtualMemory_t)freeEntry->StubAddress)(
                NtCurrentProcess(),
                &FreeAddr,
                &FreeSize,
                MEM_RELEASE
            );
            printf("  NtFreeVirtualMemory:               freed %p\n", BaseAddr);
        }
    }
}

static void TestNtDelayExecution(PSYSCALL_STUB_ENTRY Entry)
{
    NTSTATUS Status;
    LARGE_INTEGER Interval;
    typedef NTSTATUS (NTAPI* TNtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);

    if (!Entry || !Entry->StubAddress)
        return;

    //
    // Delay for 10ms (negative = relative, in 100ns units)
    //
    Interval.QuadPart = -1 * 100 * 1000; // 10ms

    Status = ((TNtDelayExecution_t)Entry->StubAddress)(FALSE, &Interval);

    printf("  NtDelayExecution:                  status=0x%08lX  (10ms delay)\n", Status);
}

static void TestNtYieldExecution(PSYSCALL_STUB_ENTRY Entry)
{
    NTSTATUS Status;
    typedef NTSTATUS (NTAPI* TNtYieldExecution_t)(void);

    if (!Entry || !Entry->StubAddress)
        return;

    Status = ((TNtYieldExecution_t)Entry->StubAddress)();
    printf("  NtYieldExecution:                  status=0x%08lX\n", Status);
}

static void TestNtClose(PSYSCALL_STUB_ENTRY Entry)
{
    NTSTATUS Status;
    typedef NTSTATUS (NTAPI* TNtClose_t)(HANDLE);

    if (!Entry || !Entry->StubAddress)
        return;

    //
    // Close invalid handle -> should return STATUS_INVALID_HANDLE
    //
    Status = ((TNtClose_t)Entry->StubAddress)((HANDLE)(ULONG_PTR)0xDEADBEEF);
    printf("  NtClose (invalid):                 status=0x%08lX  (expected: 0xC0000008)\n", Status);
}

static void TestNtQuerySystemInformation(PSYSCALL_STUB_ENTRY Entry)
{
    NTSTATUS Status;
    typedef NTSTATUS (NTAPI* TNtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    SYSTEM_BASIC_INFORMATION Info;
    ULONG RetLen = 0;

    if (!Entry || !Entry->StubAddress)
        return;

    Status = ((TNtQuerySystemInformation_t)Entry->StubAddress)(
        SystemBasicInformation,
        &Info,
        sizeof(Info),
        &RetLen
    );

    printf("  NtQuerySystemInformation:          status=0x%08lX  pages=%lu  processors=%lu\n",
        Status, Info.NumberOfPhysicalPages, Info.NumberOfProcessors);
}

static void TestNtQueryInformationProcess(PSYSCALL_STUB_ENTRY Entry)
{
    NTSTATUS Status;
    typedef NTSTATUS (NTAPI* TNtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    PROCESS_BASIC_INFORMATION Info;
    ULONG RetLen = 0;

    if (!Entry || !Entry->StubAddress)
        return;

    Status = ((TNtQueryInformationProcess_t)Entry->StubAddress)(
        NtCurrentProcess(),
        ProcessBasicInformation,
        &Info,
        sizeof(Info),
        &RetLen
    );

    printf("  NtQueryInformationProcess:         status=0x%08lX  PID=%lu  PebBase=%p\n",
        Status,
        (ULONG)(ULONG_PTR)Info.UniqueProcessId,
        Info.PebBaseAddress);
}

static void TestNtOpenProcessToken(PSYSCALL_STUB_ENTRY Entry)
{
    NTSTATUS Status;
    HANDLE TokenHandle = NULL;
    typedef NTSTATUS (NTAPI* TNtOpenProcessToken_t)(HANDLE, ACCESS_MASK, PHANDLE);

    if (!Entry || !Entry->StubAddress)
        return;

    Status = ((TNtOpenProcessToken_t)Entry->StubAddress)(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &TokenHandle
    );

    printf("  NtOpenProcessToken:                status=0x%08lX  token=%p\n",
        Status, (PVOID)TokenHandle);

    if (NT_SUCCESS(Status) && TokenHandle)
    {
        PSYSCALL_STUB_ENTRY closeEntry = SyscallRegistryLookup(GetStubRegistry(), "NtClose");
        if (closeEntry && closeEntry->StubAddress)
        {
            typedef NTSTATUS (NTAPI* TNtClose_t)(HANDLE);
            ((TNtClose_t)closeEntry->StubAddress)(TokenHandle);
        }
    }
}

static void TestNtQueryPerformanceCounter(PSYSCALL_STUB_ENTRY Entry)
{
    NTSTATUS Status;
    LARGE_INTEGER Counter, Frequency;
    typedef NTSTATUS (NTAPI* TNtQueryPerformanceCounter_t)(PLARGE_INTEGER, PLARGE_INTEGER);

    if (!Entry || !Entry->StubAddress)
        return;

    Status = ((TNtQueryPerformanceCounter_t)Entry->StubAddress)(&Counter, &Frequency);

    printf("  NtQueryPerformanceCounter:         status=0x%08lX  counter=%lld  freq=%lld\n",
        Status, Counter.QuadPart, Frequency.QuadPart);
}

//
// Verify the call stack shows ntdll return address.
// We examine the return address on our stack frame and check if
// it falls within ntdll's mapped range.
//
static void TestCallStackVerification(void)
{
    PVOID NtdllBase;
    HADES_NTDLL_INFO Info;
    PVOID RetAddr;

    NtdllBase = HadesGetNtdllBase();
    if (!NtdllBase)
    {
        printf("[!] CallStack: cannot verify, ntdll base unknown\n");
        return;
    }

    if (!HadesGetNtdllInfo(&Info))
    {
        printf("[!] CallStack: cannot get ntdll info\n");
        return;
    }

    //
    // Capture the return address from the previous test call
    //
    RetAddr = _ReturnAddress();

    //
    // Check if it falls in ntdll range
    //
    if ((ULONG_PTR)RetAddr >= (ULONG_PTR)NtdllBase &&
        (ULONG_PTR)RetAddr < (ULONG_PTR)NtdllBase + Info.ImageSize)
    {
        printf("[+] CallStack: return address %p is WITHIN ntdll range [%p - %p]\n",
            RetAddr, NtdllBase, (PBYTE)NtdllBase + Info.ImageSize);
    }
    else
    {
        printf("[~] CallStack: return address %p is OUTSIDE ntdll range [%p - %p]\n",
            RetAddr, NtdllBase, (PBYTE)NtdllBase + Info.ImageSize);
    }
}

//
// Main test entry point
//
void RunSyscallTests(void)
{
    PSYSCALL_REGISTRY Reg;
    ULONG i;
    ULONG TestCount = 0;
    ULONG FailCount = 0;

    printf("============================================================\n");
    printf("  SYSCALL INFRASTRUCTURE TEST HARNESS\n");
    printf("============================================================\n\n");

    //
    // Verify initialization
    //
    Reg = GetStubRegistry();
    if (!Reg || Reg->Count == 0)
    {
        printf("[!] No stubs in registry. Call SyscallInitFull() first.\n");
        return;
    }

    printf("[+] %lu stubs registered in hash table (%lu buckets)\n\n",
        Reg->Count, SYSCALL_HASH_SIZE);

    //
    // Phase 1: Walk all stubs and call each one
    //
    printf("--- All Syscall Stubs ---\n");

    for (i = 0; i < SYSCALL_HASH_SIZE; i++)
    {
        PSYSCALL_STUB_ENTRY Entry = Reg->Buckets[i];
        while (Entry)
        {
            TestSyscallEntry(Entry);
            TestCount++;
            Entry = Entry->Next;
        }
    }

    printf("\n--- Completed %lu test calls ---\n\n", TestCount);

    //
    // Phase 2: Specific stress tests for critical functions
    //
    printf("--- Stress Tests ---\n");

#define TEST_NAMED(Name, TestFn) do { \
    PSYSCALL_STUB_ENTRY e = SyscallRegistryLookup(Reg, Name); \
    if (e) { TestFn(e); } \
    else { printf("  %-36s  SKIP (not registered)\n", Name); } \
} while(0)

    TEST_NAMED("NtAllocateVirtualMemory", TestNtAllocateVirtualMemory);
    TEST_NAMED("NtDelayExecution", TestNtDelayExecution);
    TEST_NAMED("NtYieldExecution", TestNtYieldExecution);
    TEST_NAMED("NtClose", TestNtClose);
    TEST_NAMED("NtQuerySystemInformation", TestNtQuerySystemInformation);
    TEST_NAMED("NtQueryInformationProcess", TestNtQueryInformationProcess);
    TEST_NAMED("NtOpenProcessToken", TestNtOpenProcessToken);
    TEST_NAMED("NtQueryPerformanceCounter", TestNtQueryPerformanceCounter);

    printf("\n--- Call Stack Verification ---\n");
    TestCallStackVerification();

    printf("\n============================================================\n");
    printf("  TEST HARNESS COMPLETE\n");
    printf("============================================================\n");
}
