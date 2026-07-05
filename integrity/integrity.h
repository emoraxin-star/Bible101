#pragma once
#include <windows.h>
#include <stdint.h>

#define INTEGRITY_BLOCK_SIZE     0x1000
#define INTEGRITY_MAX_BLOCKS     2048
#define INTEGRITY_NUM_CRITICAL  10
#define INTEGRITY_HB_INTERVAL  60000
#define INTEGRITY_JITTER_MAX   15000

#define INTEGRITY_VIOLATION_LOG "INTEGRITY_VIOLATION: %s: %s"

typedef struct _INTEGRITY_CRITICAL_FUNC {
    const char* Name;
    PVOID       Address;
    SIZE_T      Size;
    uint32_t    ExpectedHash;
} INTEGRITY_CRITICAL_FUNC;

typedef enum _INTEGRITY_LAYER {
    LAYER_SECTION_HASH   = 1,
    LAYER_CRITICAL_FUNC  = 2,
    LAYER_IAT            = 3,
    LAYER_STACK          = 4,
    LAYER_SERVER_CHALLENGE = 5
} INTEGRITY_LAYER;

extern uint32_t g_IntegrityHashes[];
extern SIZE_T   g_IntegrityHashCount;
extern INTEGRITY_CRITICAL_FUNC g_CriticalFunctions[];
extern const SIZE_T g_CriticalFunctionCount;

BOOL   Integrity_Initialize(void);
VOID   Integrity_Shutdown(void);
BOOL   Integrity_CheckLayer1(void);
BOOL   Integrity_CheckLayer2(void);
BOOL   Integrity_CheckLayer3(void);
BOOL   Integrity_CheckLayer4(void);
BOOL   Integrity_CheckLayer5(void);
uint32_t Integrity_CRC32C(const void* data, SIZE_T length);
VOID   Integrity_LogViolation(INTEGRITY_LAYER layer, const char* details);
VOID   Integrity_FatalError(void);

typedef struct _INTEGRITY_IAT_ENTRY {
    PVOID* ThunkAddress;
    const char* ModuleName;
    const char* FunctionName;
} INTEGRITY_IAT_ENTRY;
