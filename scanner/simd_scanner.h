#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __AVX2__
#define SIMD_SCANNER_AVX2 1
#include <immintrin.h>
#else
#define SIMD_SCANNER_AVX2 0
#include <emmintrin.h>
#endif

typedef struct {
    uintptr_t address;
    uint32_t  patternId;
    int32_t   offset;
} ScanResult;

typedef struct {
    ScanResult* results;
    uint32_t    count;
    uint32_t    capacity;
} ScanResultSet;

uintptr_t ScanSIMD(const uint8_t* haystack, size_t haystackLen,
                   const uint8_t* pattern, const uint8_t* mask, size_t patternLen);

#if SIMD_SCANNER_AVX2
uintptr_t ScanAVX2(const uint8_t* haystack, size_t haystackLen,
                   const uint8_t* pattern, const uint8_t* mask, size_t patternLen);
#endif

uintptr_t ScanByteByByte(const uint8_t* haystack, size_t haystackLen,
                         const uint8_t* pattern, const uint8_t* mask, size_t patternLen);

ScanResultSet* ScanPatternSet(const uint8_t* haystack, size_t haystackLen,
                              const uint8_t* patterns, const uint8_t* masks,
                              const uint32_t* patternIds, const int32_t* offsets,
                              uint32_t numPatterns, size_t patternLen);

void FreeScanResults(ScanResultSet* set);
