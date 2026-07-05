#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#define PATTERN_MAX_BYTES    32
#define PATCH_MAX_BYTES      8
#define MODULE_NAME_MAX      16
#define FEATURE_NAME_MAX     16
#define MAX_PATTERNS         73
#define PATTERN_TABLE_ENCRYPT_KEY 0xA5

#define PATTERN_MAX_BYTES_W 32

typedef enum {
    HOOK_NOP_PATCH          = 0,
    HOOK_CODE_PATCH         = 1,
    HOOK_FUNCTION_PROLOGUE  = 2,
    HOOK_POINTER_RESOLVE    = 3,
    HOOK_FUNCTION_RETURN    = 4,
    HOOK_CONDITIONAL_INVERT = 5
} HookType;

typedef struct {
    uint32_t patternId;
    HookType hookType;
    uint32_t moduleHash;
    uint32_t featureHash;
    uint8_t  bytes[PATTERN_MAX_BYTES];
    uint8_t  mask[PATTERN_MAX_BYTES];
    int32_t  offset;
    int32_t  patchSize;
    uint8_t  patchBytes[PATCH_MAX_BYTES];
    uintptr_t resolvedAddr;
    uint8_t  originalBytes[PATCH_MAX_BYTES];
    bool     bResolved;
    bool     bInstalled;
} PatternEntry;

extern PatternEntry g_PatternTable[MAX_PATTERNS];
extern uint32_t     g_PatternCount;

void DecryptPatternTable(void);
void EncryptPatternTable(void);
bool ResolvePattern(PatternEntry* entry, HMODULE moduleBase);
bool ResolveAllPatterns(void);
PatternEntry* FindPatternById(uint32_t patternId);
PatternEntry* FindPatternByFeature(uint32_t featureHash);
uint32_t GetPatternCount(void);
uint32_t GetResolvedCount(void);
void LogPatternStatus(void);

typedef struct {
    uint32_t moduleHash;
    uint32_t featureHash;
    uint32_t count;
    uint32_t resolved;
} PatternSummary;
void GetPatternSummary(PatternSummary* summary, uint32_t* count);
