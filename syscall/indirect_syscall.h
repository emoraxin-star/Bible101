#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _SYSCALL_STUB_ENTRY {
    CHAR   FunctionName[64];
    ULONG  SSN;
    PVOID  StubAddress;
    ULONG  StubSize;
    PVOID  NtdllRetGadget;
    struct _SYSCALL_STUB_ENTRY* Next;
} SYSCALL_STUB_ENTRY, *PSYSCALL_STUB_ENTRY;

//
// Registry of all syscall stubs (hash-table-based)
//
#define SYSCALL_HASH_SIZE 64

typedef struct _SYSCALL_REGISTRY {
    SYSCALL_STUB_ENTRY* Buckets[SYSCALL_HASH_SIZE];
    ULONG               Count;
} SYSCALL_REGISTRY, *PSYSCALL_REGISTRY;

//
// Find a RET (0xC3) gadget inside ntdll's .text section
//
PVOID FindRetGadgetInNtdll(PVOID NtdllBase);

//
// Find a RET gadget for use by a specific ntdll function's prologue range
// (prefers gadgets inside the function to maximize stack spoofing credibility)
//
PVOID FindRetGadgetInFunction(PVOID NtdllBase, PCSTR FunctionName);

//
// Build an indirect syscall stub with call-stack spoofing
//
// The stub pushes a return address pointing into ntdll's .text
// section before executing syscall, so stack traces show ntdll
// as the caller instead of heap-allocated stub memory.
//
PVOID BuildIndirectSyscallStub(
    ULONG  SSN,
    PVOID  RetGadget,
    PULONG OutSize
);

//
// Build a stub with random NOP/junk inserts for byte-level diversity
// between stubs. Uses an LCG seeded by the caller.
//
PVOID BuildIndirectSyscallStubDiverse(
    ULONG  SSN,
    PVOID  RetGadget,
    ULONG  Seed,
    PULONG OutSize
);

//
// W^X: change page protection to RX after building
//
BOOL MakeStubExecutableReadOnly(PVOID StubAddress, ULONG StubSize);

//
// Destroy a stub: zero memory, restore RW, free
//
void DestroyStub(PVOID StubAddress, ULONG StubSize);

//
// Initialize a syscall registry
//
void SyscallRegistryInit(PSYSCALL_REGISTRY Reg);

//
// Insert a stub into the registry
//
BOOL SyscallRegistryInsert(PSYSCALL_REGISTRY Reg, PSYSCALL_STUB_ENTRY Entry);

//
// Lookup a stub by function name
//
PSYSCALL_STUB_ENTRY SyscallRegistryLookup(PSYSCALL_REGISTRY Reg, PCSTR FunctionName);

//
// LCG: classic glibc `rand()` linear congruential generator
//   x_{n+1} = (1103515245 * x_n + 12345) & 0x7FFFFFFF
//
ULONG LCGNext(ULONG* Seed);
ULONG LCGNextRange(ULONG* Seed, ULONG Min, ULONG Max);

#ifdef __cplusplus
}
#endif
