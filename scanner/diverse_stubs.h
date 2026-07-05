#pragma once
#include <windows.h>
#include <stdint.h>

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

void* BuildSyscallStub(uint32_t ssn, StubVariant preferredVariant);
void* BuildSyscallStubRandom(uint32_t ssn);
void  FreeSyscallStub(void* stub);
void  BuildAllStubs(const uint32_t* ssns, uint32_t count);
void* GetStubAddress(uint32_t index);
StubVariant GetStubVariant(uint32_t index);
void  FreeAllStubs(void);
