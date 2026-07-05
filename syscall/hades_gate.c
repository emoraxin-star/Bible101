#include "hades_gate.h"
#include <winternl.h>

//
// PEB-based ntdll resolution
// Walks PEB->Ldr->InMemoryOrderModuleList to find ntdll base.
// No disk reads, no CreateFile, no GetModuleHandle, no LdrLoadDll.
//

__declspec(noinline) PVOID HadesGetNtdllBase(void)
{
    PPEB Peb;
    PLDR_DATA_TABLE_ENTRY Entry;
    LIST_ENTRY* Head;
    LIST_ENTRY* Current;

#ifdef _WIN64
    Peb = (PPEB)__readgsqword(0x60);
#else
    Peb = (PPEB)__readfsdword(0x30);
#endif

    if (!Peb || !Peb->Ldr)
        return NULL;

    Head = &Peb->Ldr->InMemoryOrderModuleList;
    Current = Head->Flink;

    while (Current != Head)
    {
        Entry = CONTAINING_RECORD(Current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (Entry->DllBase != NULL)
        {
            WCHAR* BaseName = NULL;
            if (Entry->BaseDllName.Buffer != NULL)
            {
                BaseName = Entry->BaseDllName.Buffer;
                ULONG Len = Entry->BaseDllName.Length / sizeof(WCHAR);

                if (Len >= 8 && Len <= 12)
                {
                    //
                    // Match "ntdll.dll" (case-insensitive)
                    //
                    if ((BaseName[0] == L'n' || BaseName[0] == L'N') &&
                        (BaseName[1] == L't' || BaseName[1] == L'T') &&
                        (BaseName[2] == L'd' || BaseName[2] == L'D') &&
                        (BaseName[3] == L'l' || BaseName[3] == L'L') &&
                        (BaseName[4] == L'l' || BaseName[4] == L'L') &&
                        (BaseName[5] == L'.') &&
                        (BaseName[6] == L'd' || BaseName[6] == L'D') &&
                        (BaseName[7] == L'l' || BaseName[7] == L'L') &&
                        (BaseName[8] == L'l' || BaseName[8] == L'L'))
                    {
                        return Entry->DllBase;
                    }
                }
            }
        }

        Current = Current->Flink;
    }

    return NULL;
}

BOOL HadesGetNtdllInfo(PHADES_NTDLL_INFO Info)
{
    PVOID Base;
    PIMAGE_DOS_HEADER Dos;
    PIMAGE_NT_HEADERS64 NtHdr;
    PIMAGE_SECTION_HEADER Sec;
    ULONG i;

    if (!Info)
        return FALSE;

    Base = HadesGetNtdllBase();
    if (!Base)
        return FALSE;

    Dos = (PIMAGE_DOS_HEADER)Base;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    NtHdr = (PIMAGE_NT_HEADERS64)((ULONG_PTR)Base + Dos->e_lfanew);
    if (NtHdr->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    if (NtHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return FALSE;

    Info->DllBase = Base;
    Info->ImageSize = NtHdr->OptionalHeader.SizeOfImage;
    Info->TextStart = NULL;
    Info->TextSize = 0;

    Sec = IMAGE_FIRST_SECTION(NtHdr);
    for (i = 0; i < NtHdr->FileHeader.NumberOfSections; i++)
    {
        if (*(ULONG*)Sec[i].Name == *(ULONG*)".tex")
        {
            Info->TextStart = (PBYTE)Base + Sec[i].VirtualAddress;
            Info->TextSize = Sec[i].Misc.VirtualSize;
            break;
        }
    }

    return TRUE;
}

//
// Extract SSN from a function prologue.
// Supports both:
//   Pattern A: 4C 8B D1 B8 XX XX XX XX  (mov r10, rcx; mov eax, SSN)
//   Pattern B: B8 XX XX XX XX            (mov eax, SSN at function start)
//
ULONG HadesExtractSsnFromProc(PVOID NtdllBase, PVOID ProcAddress)
{
    PBYTE Code = (PBYTE)ProcAddress;
    ULONG_PTR BaseAddr = (ULONG_PTR)NtdllBase;
    ULONG_PTR MaxOffset;

    if (!Code)
        return 0;

    //
    // Compute max bytes to scan. 32 bytes should be sufficient.
    //
    MaxOffset = 32;

    //
    // Pattern A: 4C 8B D1 B8 XX XX XX XX
    //
    if (Code[0] == 0x4C && Code[1] == 0x8B && Code[2] == 0xD1 && Code[3] == 0xB8)
    {
        return *(ULONG*)(Code + 4);
    }

    //
    // Pattern A variant: sometimes there's 4C 8B D1 but then null bytes (int2e path)
    // followed by B8 elsewhere. Scan forward from offset 3 for B8.
    //
    for (ULONG i = 3; i < MaxOffset - 4; i++)
    {
        if (Code[i] == 0xB8 && Code[i - 1] != 0x0F)
        {
            ULONG candidate = *(ULONG*)(Code + i + 1);
            if (candidate < 0x200)
            {
                return candidate;
            }
        }
    }

    //
    // Pattern B: B8 XX XX XX XX at function start (no mov r10, rcx preamble).
    // Rare in modern ntdll but present in some edge-case exports.
    //
    if (Code[0] == 0xB8)
    {
        ULONG candidate = *(ULONG*)(Code + 1);
        if (candidate < 0x200)
        {
            return candidate;
        }
    }

    //
    // Fallback: scan all bytes for the first B8 XX XX XX XX where XX < 0x200
    //
    for (ULONG i = 0; i < MaxOffset - 4; i++)
    {
        if (Code[i] == 0xB8)
        {
            ULONG candidate = *(ULONG*)(Code + i + 1);
            if (candidate < 0x200)
            {
                return candidate;
            }
            i += 4;
        }
    }

    return 0;
}

//
// Resolve SSN for a given function name by parsing ntdll's PE export table
// from the in-memory copy (already mapped by the loader).
//
ULONG HadesGetSSN(PVOID NtdllBase, PCSTR FunctionName)
{
    PIMAGE_DOS_HEADER Dos;
    PIMAGE_NT_HEADERS64 NtHdr;
    PIMAGE_EXPORT_DIRECTORY ExportDir;
    ULONG DirSize;
    PDWORD AddressOfFunctions;
    PDWORD AddressOfNames;
    PWORD AddressOfNameOrdinals;
    ULONG i;

    if (!NtdllBase || !FunctionName)
        return 0;

    Dos = (PIMAGE_DOS_HEADER)NtdllBase;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    NtHdr = (PIMAGE_NT_HEADERS64)((ULONG_PTR)NtdllBase + Dos->e_lfanew);
    if (NtHdr->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    ExportDir = (PIMAGE_EXPORT_DIRECTORY)
        ((ULONG_PTR)NtdllBase + NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DirSize = NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (!ExportDir)
        return 0;

    AddressOfFunctions = (PDWORD)((ULONG_PTR)NtdllBase + ExportDir->AddressOfFunctions);
    AddressOfNames = (PDWORD)((ULONG_PTR)NtdllBase + ExportDir->AddressOfNames);
    AddressOfNameOrdinals = (PWORD)((ULONG_PTR)NtdllBase + ExportDir->AddressOfNameOrdinals);

    for (i = 0; i < ExportDir->NumberOfNames; i++)
    {
        PCSTR Name = (PCSTR)((ULONG_PTR)NtdllBase + AddressOfNames[i]);
        if (Name == NULL)
            continue;

        if (strcmp(Name, FunctionName) == 0)
        {
            WORD Ordinal = AddressOfNameOrdinals[i];
            ULONG FuncRva = AddressOfFunctions[Ordinal];
            PVOID FuncAddr = (PVOID)((ULONG_PTR)NtdllBase + FuncRva);

            return HadesExtractSsnFromProc(NtdllBase, FuncAddr);
        }
    }

    return 0;
}

//
// Combined: find ntdll base and resolve SSN
//
ULONG HadesResolveSSN(PCSTR FunctionName)
{
    PVOID NtdllBase = HadesGetNtdllBase();
    if (!NtdllBase)
        return 0;
    return HadesGetSSN(NtdllBase, FunctionName);
}

//
// Get in-memory RVAs address of an ntdll export (for cleanup / zeroing)
//
PVOID HadesGetProcR(PVOID NtdllBase, PCSTR FunctionName)
{
    PIMAGE_DOS_HEADER Dos;
    PIMAGE_NT_HEADERS64 NtHdr;
    PIMAGE_EXPORT_DIRECTORY ExportDir;
    PDWORD AddressOfFunctions;
    PDWORD AddressOfNames;
    PWORD AddressOfNameOrdinals;
    ULONG i;

    if (!NtdllBase || !FunctionName)
        return NULL;

    Dos = (PIMAGE_DOS_HEADER)NtdllBase;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    NtHdr = (PIMAGE_NT_HEADERS64)((ULONG_PTR)NtdllBase + Dos->e_lfanew);
    if (NtHdr->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    ExportDir = (PIMAGE_EXPORT_DIRECTORY)
        ((ULONG_PTR)NtdllBase + NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    AddressOfFunctions = (PDWORD)((ULONG_PTR)NtdllBase + ExportDir->AddressOfFunctions);
    AddressOfNames = (PDWORD)((ULONG_PTR)NtdllBase + ExportDir->AddressOfNames);
    AddressOfNameOrdinals = (PWORD)((ULONG_PTR)NtdllBase + ExportDir->AddressOfNameOrdinals);

    for (i = 0; i < ExportDir->NumberOfNames; i++)
    {
        PCSTR Name = (PCSTR)((ULONG_PTR)NtdllBase + AddressOfNames[i]);
        if (Name == NULL)
            continue;

        if (strcmp(Name, FunctionName) == 0)
        {
            WORD Ordinal = AddressOfNameOrdinals[i];
            ULONG FuncRva = AddressOfFunctions[Ordinal];
            return (PVOID)((ULONG_PTR)NtdllBase + FuncRva);
        }
    }

    return NULL;
}
