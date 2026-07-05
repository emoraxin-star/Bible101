#include "simd_scanner.h"
#include <stdlib.h>
#include <string.h>

uintptr_t ScanSIMD(const uint8_t* haystack, size_t haystackLen,
                   const uint8_t* pattern, const uint8_t* mask, size_t patternLen)
{
    if (!haystack || !pattern || !mask || patternLen == 0 || haystackLen < patternLen)
        return 0;

    size_t end = haystackLen - patternLen;

    for (size_t i = 0; i <= end; i++)
    {
        size_t j = 0;

        while (j + 16 <= patternLen)
        {
            __m128i h = _mm_loadu_si128((const __m128i*)(haystack + i + j));
            __m128i p = _mm_loadu_si128((const __m128i*)(pattern + j));
            __m128i m = _mm_loadu_si128((const __m128i*)(mask + j));

            __m128i eq = _mm_cmpeq_epi8(h, p);
            __m128i maskEq = _mm_cmpeq_epi8(m, _mm_set1_epi8((char)0xFF));
            __m128i orMask = _mm_or_si128(eq, _mm_xor_si128(maskEq, _mm_set1_epi8((char)0xFF)));
            __m128i result = _mm_and_si128(orMask, _mm_set1_epi8((char)0xFF));

            int cmp = _mm_movemask_epi8(result);
            if (cmp != 0xFFFF)
                break;

            j += 16;
        }

        if (j >= patternLen)
            return (uintptr_t)(haystack + i);

        for (; j < patternLen; j++)
        {
            if (mask[j] == 0xFF && haystack[i + j] != pattern[j])
                break;
        }

        if (j == patternLen)
            return (uintptr_t)(haystack + i);
    }

    return 0;
}

#if SIMD_SCANNER_AVX2
uintptr_t ScanAVX2(const uint8_t* haystack, size_t haystackLen,
                   const uint8_t* pattern, const uint8_t* mask, size_t patternLen)
{
    if (!haystack || !pattern || !mask || patternLen == 0 || haystackLen < patternLen)
        return 0;

    size_t end = haystackLen - patternLen;

    for (size_t i = 0; i <= end; i++)
    {
        size_t j = 0;

        while (j + 32 <= patternLen)
        {
            __m256i h = _mm256_loadu_si256((const __m256i*)(haystack + i + j));
            __m256i p = _mm256_loadu_si256((const __m256i*)(pattern + j));
            __m256i m = _mm256_loadu_si256((const __m256i*)(mask + j));

            __m256i eq = _mm256_cmpeq_epi8(h, p);
            __m256i maskEq = _mm256_cmpeq_epi8(m, _mm256_set1_epi8((char)0xFF));
            __m256i orMask = _mm256_or_si256(eq, _mm256_xor_si256(maskEq, _mm256_set1_epi8((char)0xFF)));
            __m256i result = _mm256_and_si256(orMask, _mm256_set1_epi8((char)0xFF));

            int cmp = _mm256_movemask_epi8(result);
            if (cmp != 0xFFFFFFFF)
                break;

            j += 32;
        }

        if (j >= patternLen)
            return (uintptr_t)(haystack + i);

        for (; j < patternLen; j++)
        {
            if (mask[j] == 0xFF && haystack[i + j] != pattern[j])
                break;
        }

        if (j == patternLen)
            return (uintptr_t)(haystack + i);
    }

    return 0;
}
#endif

uintptr_t ScanByteByByte(const uint8_t* haystack, size_t haystackLen,
                         const uint8_t* pattern, const uint8_t* mask, size_t patternLen)
{
    if (!haystack || !pattern || !mask || patternLen == 0 || haystackLen < patternLen)
        return 0;

    size_t end = haystackLen - patternLen;

    for (size_t i = 0; i <= end; i++)
    {
        size_t j = 0;
        for (; j < patternLen; j++)
        {
            if (mask[j] == 0xFF && haystack[i + j] != pattern[j])
                break;
        }
        if (j == patternLen)
            return (uintptr_t)(haystack + i);
    }

    return 0;
}

ScanResultSet* ScanPatternSet(const uint8_t* haystack, size_t haystackLen,
                              const uint8_t* patterns, const uint8_t* masks,
                              const uint32_t* patternIds, const int32_t* offsets,
                              uint32_t numPatterns, size_t patternLen)
{
    if (!haystack || !patterns || !masks || numPatterns == 0)
        return NULL;

    ScanResultSet* set = (ScanResultSet*)calloc(1, sizeof(ScanResultSet));
    if (!set)
        return NULL;

    set->results = (ScanResult*)calloc(numPatterns, sizeof(ScanResult));
    if (!set->results)
    {
        free(set);
        return NULL;
    }

    set->capacity = numPatterns;
    set->count = 0;

    for (uint32_t i = 0; i < numPatterns; i++)
    {
        const uint8_t* pat = patterns + (i * patternLen);
        const uint8_t* msk = masks + (i * patternLen);

        uintptr_t addr = ScanSIMD(haystack, haystackLen, pat, msk, patternLen);
        if (addr)
        {
            set->results[set->count].address  = addr;
            set->results[set->count].patternId = patternIds[i];
            set->results[set->count].offset    = offsets[i];
            set->count++;
        }
    }

    return set;
}

void FreeScanResults(ScanResultSet* set)
{
    if (set)
    {
        free(set->results);
        free(set);
    }
}
