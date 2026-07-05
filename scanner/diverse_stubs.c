#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define STUB_COUNT      8
#define STUB_SIZE_MAX   32
#define SSN_XOR_KEY     0x5A7B3C1D

typedef enum {
    STUB_VANILLA           = 0,
    STUB_SWAPPED           = 1,
    STUB_STACK_SHUFFLE     = 2,
    STUB_XOR_OBFUSCATED    = 3,
    STUB_NOP_PADDED        = 4,
    STUB_REG_INIT          = 5,
    STUB_LEA_VARIANT       = 6,
    STUB_REG_SWAP          = 7
} StubVariant;

typedef struct {
    uint8_t  code[STUB_SIZE_MAX];
    uint32_t codeSize;
    StubVariant variant;
    uint32_t ssn;
    void*    trampolineBase;
} StubInfo;

static StubInfo g_Stubs[STUB_COUNT];
static int      g_StubInitialized = 0;

static void BuildStubVanilla(uint8_t* buf, uint32_t* size, uint32_t ssn)
{
    buf[0] = 0x4C; buf[1] = 0x8B; buf[2] = 0xD1;
    buf[3] = 0xB8;
    buf[4] = (uint8_t)(ssn & 0xFF);
    buf[5] = (uint8_t)((ssn >> 8) & 0xFF);
    buf[6] = (uint8_t)((ssn >> 16) & 0xFF);
    buf[7] = (uint8_t)((ssn >> 24) & 0xFF);
    buf[8] = 0x0F; buf[9] = 0x05;
    buf[10] = 0xC3;
    *size = 11;
}

static void BuildStubSwapped(uint8_t* buf, uint32_t* size, uint32_t ssn)
{
    buf[0] = 0xB8;
    buf[1] = (uint8_t)(ssn & 0xFF);
    buf[2] = (uint8_t)((ssn >> 8) & 0xFF);
    buf[3] = (uint8_t)((ssn >> 16) & 0xFF);
    buf[4] = (uint8_t)((ssn >> 24) & 0xFF);
    buf[5] = 0x4C; buf[6] = 0x8B; buf[7] = 0xD1;
    buf[8] = 0x0F; buf[9] = 0x05;
    buf[10] = 0xC3;
    *size = 11;
}

static void BuildStubStackShuffle(uint8_t* buf, uint32_t* size, uint32_t ssn)
{
    buf[0] = 0x50;
    buf[1] = 0x4C; buf[2] = 0x8B; buf[3] = 0xD1;
    buf[4] = 0xB8;
    buf[5] = (uint8_t)(ssn & 0xFF);
    buf[6] = (uint8_t)((ssn >> 8) & 0xFF);
    buf[7] = (uint8_t)((ssn >> 16) & 0xFF);
    buf[8] = (uint8_t)((ssn >> 24) & 0xFF);
    buf[9] = 0x41; buf[10] = 0x58;
    buf[11] = 0x4C; buf[12] = 0x8B; buf[13] = 0xD1;
    buf[14] = 0x0F; buf[15] = 0x05;
    buf[16] = 0xC3;
    *size = 17;
}

static void BuildStubXorObfuscated(uint8_t* buf, uint32_t* size, uint32_t ssn)
{
    uint32_t xored = ssn ^ SSN_XOR_KEY;
    buf[0] = 0x4C; buf[1] = 0x8B; buf[2] = 0xD1;
    buf[3] = 0xB8;
    buf[4] = (uint8_t)(xored & 0xFF);
    buf[5] = (uint8_t)((xored >> 8) & 0xFF);
    buf[6] = (uint8_t)((xored >> 16) & 0xFF);
    buf[7] = (uint8_t)((xored >> 24) & 0xFF);
    buf[8] = 0x35;
    buf[9] = (uint8_t)(SSN_XOR_KEY & 0xFF);
    buf[10] = (uint8_t)((SSN_XOR_KEY >> 8) & 0xFF);
    buf[11] = (uint8_t)((SSN_XOR_KEY >> 16) & 0xFF);
    buf[12] = (uint8_t)((SSN_XOR_KEY >> 24) & 0xFF);
    buf[13] = 0x0F; buf[14] = 0x05;
    buf[15] = 0xC3;
    *size = 16;
}

static void BuildStubNopPadded(uint8_t* buf, uint32_t* size, uint32_t ssn)
{
    buf[0] = 0x4C; buf[1] = 0x8B; buf[2] = 0xD1;
    buf[3] = 0xB8;
    buf[4] = (uint8_t)(ssn & 0xFF);
    buf[5] = (uint8_t)((ssn >> 8) & 0xFF);
    buf[6] = (uint8_t)((ssn >> 16) & 0xFF);
    buf[7] = (uint8_t)((ssn >> 24) & 0xFF);
    buf[8] = 0x90; buf[9] = 0x90;
    buf[10] = 0x0F; buf[11] = 0x05;
    buf[12] = 0xC3;
    *size = 13;
}

static void BuildStubRegInit(uint8_t* buf, uint32_t* size, uint32_t ssn)
{
    buf[0] = 0x4D; buf[1] = 0x31; buf[2] = 0xD2;
    buf[3] = 0x49; buf[4] = 0x01; buf[5] = 0xCA;
    buf[6] = 0xB8;
    buf[7] = (uint8_t)(ssn & 0xFF);
    buf[8] = (uint8_t)((ssn >> 8) & 0xFF);
    buf[9] = (uint8_t)((ssn >> 16) & 0xFF);
    buf[10] = (uint8_t)((ssn >> 24) & 0xFF);
    buf[11] = 0x0F; buf[12] = 0x05;
    buf[13] = 0xC3;
    *size = 14;
}

static void BuildStubLeaVariant(uint8_t* buf, uint32_t* size, uint32_t ssn)
{
    buf[0] = 0x4C; buf[1] = 0x8D; buf[2] = 0x51; buf[3] = 0x00;
    buf[4] = 0xB8;
    buf[5] = (uint8_t)(ssn & 0xFF);
    buf[6] = (uint8_t)((ssn >> 8) & 0xFF);
    buf[7] = (uint8_t)((ssn >> 16) & 0xFF);
    buf[8] = (uint8_t)((ssn >> 24) & 0xFF);
    buf[9] = 0x0F; buf[10] = 0x05;
    buf[11] = 0xC3;
    *size = 12;
}

static void BuildStubRegSwap(uint8_t* buf, uint32_t* size, uint32_t ssn)
{
    buf[0] = 0x4C; buf[1] = 0x8B; buf[2] = 0xD1;
    buf[3] = 0xB8;
    buf[4] = (uint8_t)(ssn & 0xFF);
    buf[5] = (uint8_t)((ssn >> 8) & 0xFF);
    buf[6] = (uint8_t)((ssn >> 16) & 0xFF);
    buf[7] = (uint8_t)((ssn >> 24) & 0xFF);
    buf[8] = 0x0F; buf[9] = 0x05;
    buf[10] = 0x48; buf[11] = 0x89; buf[12] = 0xC1;
    buf[13] = 0x48; buf[14] = 0x89; buf[15] = 0xC8;
    buf[16] = 0xC3;
    *size = 17;
}

static void (*const g_StubBuilders[STUB_COUNT])(uint8_t*, uint32_t*, uint32_t) = {
    BuildStubVanilla,
    BuildStubSwapped,
    BuildStubStackShuffle,
    BuildStubXorObfuscated,
    BuildStubNopPadded,
    BuildStubRegInit,
    BuildStubLeaVariant,
    BuildStubRegSwap
};

void* BuildSyscallStub(uint32_t ssn, StubVariant preferredVariant)
{
    StubVariant variant = preferredVariant;

    if (variant >= STUB_COUNT)
        variant = (StubVariant)(rand() % STUB_COUNT);

    uint8_t code[STUB_SIZE_MAX] = {0};
    uint32_t codeSize = 0;

    g_StubBuilders[variant](code, &codeSize, ssn);

    SIZE_T allocSize = codeSize;
    void* stub = VirtualAlloc(NULL, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stub) return NULL;

    memcpy(stub, code, codeSize);

    DWORD oldProtect = 0;
    VirtualProtect(stub, allocSize, PAGE_EXECUTE_READ, &oldProtect);

    return stub;
}

void* BuildSyscallStubRandom(uint32_t ssn)
{
    StubVariant v = (StubVariant)(rand() % STUB_COUNT);
    return BuildSyscallStub(ssn, v);
}

void FreeSyscallStub(void* stub)
{
    if (stub)
    {
        MEMORY_BASIC_INFORMATION mbi = {0};
        if (VirtualQuery(stub, &mbi, sizeof(mbi)))
        {
            VirtualFree(mbi.AllocationBase, 0, MEM_RELEASE);
        }
    }
}

void BuildAllStubs(const uint32_t* ssns, uint32_t count)
{
    for (uint32_t i = 0; i < count && i < STUB_COUNT; i++)
    {
        StubVariant v = (StubVariant)(i % STUB_COUNT);
        uint8_t code[STUB_SIZE_MAX] = {0};
        uint32_t codeSize = 0;

        g_StubBuilders[v](code, &codeSize, ssns[i]);

        g_Stubs[i].variant = v;
        g_Stubs[i].ssn = ssns[i];
        g_Stubs[i].codeSize = codeSize;
        memcpy(g_Stubs[i].code, code, codeSize);

        SIZE_T allocSize = codeSize;
        g_Stubs[i].trampolineBase = VirtualAlloc(NULL, allocSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (g_Stubs[i].trampolineBase)
        {
            memcpy(g_Stubs[i].trampolineBase, code, codeSize);
            DWORD oldProtect = 0;
            VirtualProtect(g_Stubs[i].trampolineBase, allocSize,
                PAGE_EXECUTE_READ, &oldProtect);
        }
    }

    g_StubInitialized = 1;
}

void* GetStubAddress(uint32_t index)
{
    if (index >= STUB_COUNT) return NULL;
    return g_Stubs[index].trampolineBase;
}

StubVariant GetStubVariant(uint32_t index)
{
    if (index >= STUB_COUNT) return STUB_VANILLA;
    return g_Stubs[index].variant;
}

void FreeAllStubs(void)
{
    for (uint32_t i = 0; i < STUB_COUNT; i++)
    {
        if (g_Stubs[i].trampolineBase)
        {
            VirtualFree(g_Stubs[i].trampolineBase, 0, MEM_RELEASE);
            g_Stubs[i].trampolineBase = NULL;
        }
    }
    g_StubInitialized = 0;
}
