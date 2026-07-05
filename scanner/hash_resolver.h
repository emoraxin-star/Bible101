#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#define HASH_SEED_FNV1a  0x811C9DC5
#define HASH_SEED_CRC32C 0xFFFFFFFF
#define HASH_SEED_JENKINS 0xDEADBEEF

#define XORMASK_KEY 0xA5B6C7D8

uint32_t FNV1a32(const char* str);
uint32_t CRC32C(const uint8_t* data, size_t len);
uint32_t CRC32C_HW(const uint8_t* data, size_t len);
uint32_t CRC32C_SW(const uint8_t* data, size_t len);
uint32_t JenkinsOAAT(const char* str);
uint32_t JenkinsOAATBuf(const uint8_t* data, size_t len);
bool     IsPCLMULQDQAvailable(void);

HMODULE ResolveModuleByHash(uint32_t targetHash, uint32_t (*hashFunc)(const char*));
void*   ResolveExportByHash(HMODULE moduleBase, uint32_t functionHash);

typedef struct {
    uint32_t hash;
    uintptr_t address;
    HMODULE   module;
} ModuleResolution;

uint32_t HashModuleName(const wchar_t* modulePath);
uint32_t HashAnsi(const char* str);
uint32_t XorTransform(uint32_t value, uint32_t key);
