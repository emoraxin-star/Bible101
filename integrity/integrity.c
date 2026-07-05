#include "integrity.h"
#include <stdint.h>
#include <strsafe.h>
#include <intrin.h>

#define CRC32C_POLY 0x82F63B78
#define TEXT_BLOCK_SAMPLES 16

static const uint32_t g_CRCTable[256] = {
    0x00000000,0xF26B8303,0xE13B70F7,0x1350F3F4,0xC79A971F,0x35F1141C,
    0x26A1E7E8,0xD4CA64EB,0x8AD958CF,0x78B2DBCC,0x6BE22838,0x9989AB3B,
    0x4F43CFD0,0xBD284CD3,0xAE78BF27,0x5C133C24,0x105EC76F,0xE235446C,
    0xF165B798,0x030E349B,0xD7C45070,0x25AFD373,0x36FF2087,0xC494A384,
    0x9A879FA0,0x68EC1CA3,0x7BBCEF57,0x89D76C54,0x5D1D08BF,0xAF768BBC,
    0xBC267848,0x4E4DFB4B,0x20BD8EDE,0xD2D60DDD,0xC186FE29,0x33ED7D2A,
    0xE72719C1,0x154C9AC2,0x061C6936,0xF477EA35,0xAA64D611,0x580F5512,
    0x4B5FA6E6,0xB93425E5,0x6DFE410E,0x9F95C20D,0x8CC531F9,0x7EAEB2FA,
    0x32E349B1,0xC088CAB2,0xD3D83946,0x21B3BA45,0xF579DEAE,0x07125DAD,
    0x1442AE59,0xE6292D5A,0xB83A117E,0x4A51927D,0x59016189,0xAB6AE28A,
    0x7FA08661,0x8DCB0562,0x9E9BF696,0x6CF07595,0x417B1DBC,0xB3109EBF,
    0xA0406D4B,0x522BEE48,0x86E18AA3,0x748A09A0,0x67DAFA54,0x95B17957,
    0xCBA24573,0x39C9C670,0x2A993584,0xD8F2B687,0x0C38D26C,0xFE53516F,
    0xED03A29B,0x1F682198,0x5325DAD3,0xA14E59D0,0xB21EAA24,0x40752927,
    0x94BF4DCC,0x66D4CECF,0x75843D3B,0x87EFBE38,0xD9FC821C,0x2B97011F,
    0x38C7F2EB,0xCAAC71E8,0x1E661503,0xEC0D9600,0xFF5D65F4,0x0D36E6F7,
    0x63C69362,0x91AD1061,0x82FDE395,0x70966096,0xA45C047D,0x5637877E,
    0x4567748A,0xB70CF789,0xE91FCBAD,0x1B7448AE,0x0824BB5A,0xFA4F3859,
    0x2E855CB2,0xDCEE1DB1,0xCFBEEE45,0x3DD56D46,0x7198960D,0x83F3150E,
    0x90A3E6FA,0x62C865F9,0xB6020112,0x44698211,0x573971E5,0xA552F2E6,
    0xFB41CEC2,0x092A4DC1,0x1A7ABE35,0xE8113D36,0x3CDB59DD,0xCEB0DADE,
    0xDDE0292A,0x2F8BAA29,0x82F63B78,0x709DB87B,0x63CD4B8F,0x91A6C88C,
    0x456CAC67,0xB7072F64,0xA457DC90,0x563C5F93,0x082F63B7,0xFA44E0B4,
    0xE9141340,0x1B7F9043,0xCFB5F4A8,0x3DDE77AB,0x2E8E845F,0xDCE5075C,
    0x90A8FC17,0x62C37F14,0x71938CE0,0x83F80FE3,0x57326B08,0xA559E80B,
    0xB6091BFF,0x446298FC,0x1A71A4D8,0xE81A27DB,0xFB4AD42F,0x0921572C,
    0xDDEB33C7,0x2F80B0C4,0x3CD04330,0xCEBBC033,0xA04BB5A6,0x522036A5,
    0x4170C551,0xB31B4652,0x67D122B9,0x95BAA1BA,0x86EA524E,0x7481D14D,
    0x2A92ED69,0xD8F96E6A,0xCBA99D9E,0x39C21E9D,0xED087A76,0x1F63F975,
    0x0C330A81,0xFE588982,0xB21572C9,0x407EF1CA,0x532E023E,0xA145813D,
    0x758FE5D6,0x87E466D5,0x94B49521,0x66DF1622,0x38CC2A06,0xCAA7A905,
    0xD9F75AF1,0x2B9CD9F2,0xFF56BD19,0x0D3D3E1A,0x1E6DCDEE,0xEC064EED,
    0xC38D26C4,0x31E6A5C7,0x22B65633,0xD0DDD530,0x0417B1DB,0xF67C32D8,
    0xE52CC12C,0x1747422F,0x49547E0B,0xBB3FFD08,0xA86F0EFC,0x5A048DFF,
    0x8ECEE914,0x7CA56A17,0x6FF599E3,0x9D9E1AE0,0xD1D3E1AB,0x23B862A8,
    0x30E8915C,0xC283125F,0x164976B4,0xE422F5B7,0xF7720643,0x05198540,
    0x5B0AB964,0xA9613A67,0xBA31C993,0x485A4A90,0x9C902E7B,0x6EFBAD78,
    0x7DAB5E8C,0x8FC0DD8F,0xE130A81A,0x135B2B19,0x000BD8ED,0xF2605BEE,
    0x26AA3F05,0xD4C1BC06,0xC7914FF2,0x35FACCF1,0x6BE9F0D5,0x998273D6,
    0x8AD28022,0x78B90321,0xAC7367CA,0x5E18E4C9,0x4D48173D,0xBF23943E,
    0xF36E6F75,0x0105EC76,0x12551F82,0xE03E9C81,0x34F4F86A,0xC69F7B69,
    0xD5CF889D,0x27A40B9E,0x79B737BA,0x8BDCB4B9,0x988C474D,0x6AE7C44E,
    0xBE2DA0A5,0x4C4623A6,0x5F16D052,0xAD7D5351
};

static HANDLE g_IntegrityThread  = NULL;
static HANDLE g_HardErrorEvent   = NULL;
static BOOL   g_ShutdownFlag     = FALSE;

uint32_t g_IntegrityHashes[INTEGRITY_MAX_BLOCKS] = {0};
SIZE_T   g_IntegrityHashCount = 0;

INTEGRITY_CRITICAL_FUNC g_CriticalFunctions[INTEGRITY_NUM_CRITICAL] = {
    { "PatternScanner",       NULL, 0, 0 },
    { "HookInstaller",        NULL, 0, 0 },
    { "SyscallBuilder",       NULL, 0, 0 },
    { "AuthValidator",        NULL, 0, 0 },
    { "Decompressor",         NULL, 0, 0 },
    { "NetworkSend",          NULL, 0, 0 },
    { "OverlayRender",        NULL, 0, 0 },
    { "ConfigParser",         NULL, 0, 0 },
    { "ReplayEngine",         NULL, 0, 0 },
    { "ChallengeResponder",   NULL, 0, 0 },
};
const SIZE_T g_CriticalFunctionCount = INTEGRITY_NUM_CRITICAL;

extern NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
extern NTSTATUS NTAPI NtRaiseHardError(LONG, ULONG, ULONG, PULONG_PTR, HARDERROR_RESPONSE_OPTION, PULONG);
extern NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
extern NTSTATUS NTAPI NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
extern NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);

static uint32_t integrity_crc32c_block(const void* data, SIZE_T length)
{
    return Integrity_CRC32C(data, length);
}

uint32_t Integrity_CRC32C(const void* data, SIZE_T length)
{
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFF;
    for (SIZE_T i = 0; i < length; i++) {
        crc = g_CRCTable[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

static LARGE_INTEGER integrity_get_jitter(DWORD baseMs, DWORD jitterMax)
{
    LARGE_INTEGER delay;
    DWORD jitter = (DWORD)(__rdtsc() % jitterMax);
    DWORD totalMs = baseMs + jitter;
    delay.QuadPart = -(LONGLONG)totalMs * 10000;
    return delay;
}

VOID Integrity_LogViolation(INTEGRITY_LAYER layer, const char* details)
{
    char buffer[512];
    const char* layerNames[] = {
        "UNKNOWN",
        "SECTION_HASH",
        "CRITICAL_FUNC",
        "IAT",
        "STACK",
        "SERVER_CHALLENGE"
    };
    LPCSTR layerName = (layer >= 1 && layer <= 5) ? layerNames[layer] : "UNKNOWN";
    StringCbPrintfA(buffer, sizeof(buffer), INTEGRITY_VIOLATION_LOG, layerName, details);
    OutputDebugStringA(buffer);
}

VOID Integrity_FatalError(void)
{
    ULONG_PTR response = 0;
    ULONG responseState = 0;
    NtRaiseHardError(STATUS_UNSUCCESSFUL, 0, 0, NULL, OptionShutdownSystem, &responseState);
    __fastfail(1);
}

static BOOL integrity_read_own_mem(PVOID address, PVOID buffer, SIZE_T size)
{
    NTSTATUS status;
    SIZE_T bytesRead = 0;
    status = NtReadVirtualMemory(GetCurrentProcess(), address, buffer, size, &bytesRead);
    return NT_SUCCESS(status) && bytesRead == size;
}

BOOL Integrity_CheckLayer1(void)
{
    if (g_IntegrityHashCount == 0) return TRUE;

    uint8_t buffer[INTEGRITY_BLOCK_SIZE];
    uint8_t localBuffer[INTEGRITY_BLOCK_SIZE];
    SIZE_T  blockCount = g_IntegrityHashCount;
    uint32_t sampleCount = (blockCount < TEXT_BLOCK_SAMPLES) ? blockCount : TEXT_BLOCK_SAMPLES;

    uint32_t indices[TEXT_BLOCK_SAMPLES];
    for (uint32_t i = 0; i < sampleCount; i++) {
        indices[i] = (uint32_t)(__rdtsc() % blockCount);
    }

    for (uint32_t i = 0; i < sampleCount; i++) {
        uint32_t idx = indices[i];
        PVOID blockAddr = (PVOID)((ULONG_PTR)GetModuleHandleA(NULL) + idx * INTEGRITY_BLOCK_SIZE);

        if (!integrity_read_own_mem(blockAddr, buffer, INTEGRITY_BLOCK_SIZE)) {
            Integrity_LogViolation(LAYER_SECTION_HASH, "NtReadVirtualMemory failed");
            Integrity_FatalError();
            return FALSE;
        }

        uint32_t computed = Integrity_CRC32C(buffer, INTEGRITY_BLOCK_SIZE);
        if (computed != g_IntegrityHashes[idx]) {
            char details[128];
            StringCbPrintfA(details, sizeof(details),
                "Block %u hash mismatch: expected 0x%08X, computed 0x%08X",
                idx, g_IntegrityHashes[idx], computed);
            Integrity_LogViolation(LAYER_SECTION_HASH, details);
            Integrity_FatalError();
            return FALSE;
        }
    }
    return TRUE;
}

static uint32_t integrity_checksum_func(PVOID address, SIZE_T size)
{
    uint8_t* buf = (uint8_t*)VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) return 0;
    uint32_t hash = 0;
    if (integrity_read_own_mem(address, buf, size)) {
        hash = Integrity_CRC32C(buf, size);
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    return hash;
}

BOOL Integrity_CheckLayer2(void)
{
    for (SIZE_T i = 0; i < g_CriticalFunctionCount; i++) {
        INTEGRITY_CRITICAL_FUNC* func = &g_CriticalFunctions[i];
        if (!func->Address || func->Size == 0) continue;

        uint32_t currentHash = integrity_checksum_func(func->Address, func->Size);
        if (currentHash != func->ExpectedHash) {
            char details[256];
            StringCbPrintfA(details, sizeof(details),
                "Function '%s' hash mismatch: expected 0x%08X, got 0x%08X",
                func->Name, func->ExpectedHash, currentHash);
            Integrity_LogViolation(LAYER_CRITICAL_FUNC, details);
            Integrity_FatalError();
            return FALSE;
        }
    }
    return TRUE;
}

BOOL Integrity_CheckLayer3(void)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)GetModuleHandleA(NULL);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        Integrity_LogViolation(LAYER_IAT, "Invalid DOS header");
        return FALSE;
    }
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dos + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        Integrity_LogViolation(LAYER_IAT, "Invalid NT header");
        return FALSE;
    }

    IMAGE_DATA_DIRECTORY* importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir->Size) {
        Integrity_LogViolation(LAYER_IAT, "No import directory");
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR impDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)dos + importDir->VirtualAddress);
    if (!impDesc) return FALSE;

    static const struct {
        const char* Module;
        const char* Func;
    } knownThunks[] = {
        { "kernel32.dll", "GetProcAddress" },
        { "ntdll.dll",    "NtProtectVirtualMemory" },
        { "kernel32.dll", "VirtualProtect" },
        { "ntdll.dll",    "NtOpenProcess" },
        { NULL, NULL }
    };

    for (; impDesc->Name; impDesc++) {
        const char* moduleName = (const char*)dos + impDesc->Name;
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)dos + impDesc->FirstThunk);
        for (; thunk->u1.Function; thunk++) {
            PVOID funcPtr = (PVOID)thunk->u1.Function;
            for (int k = 0; knownThunks[k].Module; k++) {
                if (lstrcmpiA(moduleName, knownThunks[k].Module) == 0) {
                    HMODULE hMod = GetModuleHandleA(knownThunks[k].Module);
                    if (hMod) {
                        FARPROC expected = GetProcAddress(hMod, knownThunks[k].Func);
                        if (expected && funcPtr != expected) {
                            char details[256];
                            StringCbPrintfA(details, sizeof(details),
                                "IAT thunk mismatch: %s!%s at 0x%p (expected 0x%p)",
                                moduleName, knownThunks[k].Func, funcPtr, expected);
                            Integrity_LogViolation(LAYER_IAT, details);
                            Integrity_FatalError();
                            return FALSE;
                        }
                    }
                    break;
                }
            }
        }
    }
    return TRUE;
}

BOOL Integrity_CheckLayer4(void)
{
    CONTEXT context;
    RtlSecureZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_CONTROL;

    HANDLE hThread = GetCurrentThread();
    NTSTATUS status = NtGetContextThread(hThread, &context);
    if (!NT_SUCCESS(status)) {
        Integrity_LogViolation(LAYER_STACK, "NtGetContextThread failed");
        return FALSE;
    }

    ULONG_PTR currentRip = context.Rip;
    ULONG_PTR currentRsp = context.Rsp;

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return FALSE;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    ULONG_PTR textStart = (ULONG_PTR)hMod + nt->OptionalHeader.BaseOfCode;
    ULONG_PTR textEnd   = textStart + nt->OptionalHeader.SizeOfCode;

    BOOL ripInText = (currentRip >= textStart && currentRip < textEnd);
    if (!ripInText) {
        char details[128];
        StringCbPrintfA(details, sizeof(details),
            "RIP (0x%p) outside .text region [0x%p, 0x%p)",
            (void*)currentRip, (void*)textStart, (void*)textEnd);
        Integrity_LogViolation(LAYER_STACK, details);
        Integrity_FatalError();
        return FALSE;
    }

    ULONG_PTR* stackFrame = (ULONG_PTR*)currentRsp;
    for (int i = 0; i < 32; i++) {
        ULONG_PTR retAddr;
        if (!integrity_read_own_mem(&stackFrame[i], &retAddr, sizeof(retAddr))) break;

        if (retAddr >= textStart && retAddr < textEnd) continue;

        HMODULE sysMods[] = {
            GetModuleHandleA("ntdll.dll"),
            GetModuleHandleA("kernel32.dll"),
            GetModuleHandleA("kernelbase.dll"),
        };
        BOOL inSystemDll = FALSE;
        for (int m = 0; m < 3; m++) {
            if (!sysMods[m]) continue;
            PIMAGE_DOS_HEADER mDOS = (PIMAGE_DOS_HEADER)sysMods[m];
            PIMAGE_NT_HEADERS mNT = (PIMAGE_NT_HEADERS)((BYTE*)sysMods[m] + mDOS->e_lfanew);
            ULONG_PTR modStart = (ULONG_PTR)sysMods[m];
            ULONG_PTR modEnd   = modStart + mNT->OptionalHeader.SizeOfImage;
            if (retAddr >= modStart && retAddr < modEnd) {
                inSystemDll = TRUE;
                break;
            }
        }
        if (!inSystemDll) {
            char details[128];
            StringCbPrintfA(details, sizeof(details),
                "Return address 0x%p at stack offset %d outside known regions", (void*)retAddr, i);
            Integrity_LogViolation(LAYER_STACK, details);
            Integrity_FatalError();
            return FALSE;
        }
    }
    return TRUE;
}

BOOL Integrity_CheckLayer5(void)
{
    if (g_IntegrityHashCount == 0) return TRUE;

    uint32_t randomIdx = (uint32_t)(__rdtsc() % g_IntegrityHashCount);
    uint8_t blockBuffer[INTEGRITY_BLOCK_SIZE];
    PVOID blockAddr = (PVOID)((ULONG_PTR)GetModuleHandleA(NULL) + randomIdx * INTEGRITY_BLOCK_SIZE);

    if (!integrity_read_own_mem(blockAddr, blockBuffer, INTEGRITY_BLOCK_SIZE)) {
        Integrity_LogViolation(LAYER_SERVER_CHALLENGE, "Failed to read block for heartbeat");
        return FALSE;
    }

    uint32_t blockHash = Integrity_CRC32C(blockBuffer, INTEGRITY_BLOCK_SIZE);
    uint32_t expectedHash = g_IntegrityHashes[randomIdx];

    if (blockHash != expectedHash) {
        char details[128];
        StringCbPrintfA(details, sizeof(details),
            "Heartbeat block %u mismatch: local 0x%08X != expected 0x%08X",
            randomIdx, blockHash, expectedHash);
        Integrity_LogViolation(LAYER_SERVER_CHALLENGE, details);
        Integrity_FatalError();
        return FALSE;
    }

    return TRUE;
}

static DWORD WINAPI integrity_monitor_thread(LPVOID param)
{
    (void)param;
    while (!g_ShutdownFlag) {
        LARGE_INTEGER delay = integrity_get_jitter(5000, INTEGRITY_JITTER_MAX);
        NtDelayExecution(FALSE, &delay);
        if (g_ShutdownFlag) break;

        Integrity_CheckLayer1();

        delay = integrity_get_jitter(30000, INTEGRITY_JITTER_MAX);
        NtDelayExecution(FALSE, &delay);
        if (g_ShutdownFlag) break;

        Integrity_CheckLayer2();

        delay = integrity_get_jitter(120000, INTEGRITY_JITTER_MAX);
        NtDelayExecution(FALSE, &delay);
        if (g_ShutdownFlag) break;

        Integrity_CheckLayer3();

        delay = integrity_get_jitter(60000, INTEGRITY_JITTER_MAX);
        NtDelayExecution(FALSE, &delay);
        if (g_ShutdownFlag) break;

        Integrity_CheckLayer4();
    }
    return 0;
}

BOOL Integrity_Initialize(void)
{
    g_ShutdownFlag = FALSE;

    Integrity_CheckLayer1();
    Integrity_CheckLayer2();
    Integrity_CheckLayer3();
    Integrity_CheckLayer4();

    g_IntegrityThread = CreateThread(NULL, 0, integrity_monitor_thread, NULL, 0, NULL);
    if (!g_IntegrityThread) return FALSE;

    return TRUE;
}

VOID Integrity_Shutdown(void)
{
    g_ShutdownFlag = TRUE;
    if (g_IntegrityThread) {
        WaitForSingleObject(g_IntegrityThread, 5000);
        CloseHandle(g_IntegrityThread);
        g_IntegrityThread = NULL;
    }
}
