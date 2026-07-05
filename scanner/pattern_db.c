#include "pattern_db.h"
#include "simd_scanner.h"
#include "hash_resolver.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

uint32_t g_PatternCount = 0;

void DecryptPatternTable(void)
{
    uint8_t key = PATTERN_TABLE_ENCRYPT_KEY;
    uint8_t* raw = (uint8_t*)g_PatternTable;
    size_t total = sizeof(PatternEntry) * MAX_PATTERNS;

    for (size_t i = 0; i < total; i++)
    {
        uint8_t k = key + (uint8_t)(i & 0xFF);
        raw[i] ^= k;
        key = (key << 1) | (key >> 7);
    }
}

void EncryptPatternTable(void)
{
    DecryptPatternTable();
}

bool ResolvePattern(PatternEntry* entry, HMODULE moduleBase)
{
    if (!entry || !moduleBase || entry->bResolved)
        return entry->bResolved;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)moduleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)moduleBase + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    uint8_t* textBase = NULL;
    size_t   textSize = 0;

    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(sections[i].Name, ".text", 5) == 0)
        {
            textBase = (uint8_t*)moduleBase + sections[i].VirtualAddress;
            textSize = sections[i].Misc.VirtualSize;
            break;
        }
        if (memcmp(sections[i].Name, "PAGE", 4) == 0 && textBase == NULL)
        {
            textBase = (uint8_t*)moduleBase + sections[i].VirtualAddress;
            textSize = sections[i].Misc.VirtualSize;
        }
    }

    if (!textBase)
        return false;

    size_t patternLen = PATTERN_MAX_BYTES;
    while (patternLen > 0 && entry->mask[patternLen - 1] == 0)
        patternLen--;

    uintptr_t match = ScanSIMD(textBase, textSize, entry->bytes, entry->mask, patternLen);
    if (!match)
        return false;

    entry->resolvedAddr = match + entry->offset;
    entry->bResolved = true;
    return true;
}

bool ResolveAllPatterns(void)
{
    uint32_t resolved = 0;

    for (uint32_t i = 0; i < g_PatternCount; i++)
    {
        HMODULE mod = ResolveModuleByHash(g_PatternTable[i].moduleHash, FNV1a32);
        if (!mod)
        {
            g_PatternTable[i].bResolved = false;
            continue;
        }

        if (ResolvePattern(&g_PatternTable[i], mod))
            resolved++;
    }

    return resolved == g_PatternCount;
}

PatternEntry* FindPatternById(uint32_t patternId)
{
    for (uint32_t i = 0; i < g_PatternCount; i++)
    {
        if (g_PatternTable[i].patternId == patternId)
            return &g_PatternTable[i];
    }
    return NULL;
}

PatternEntry* FindPatternByFeature(uint32_t featureHash)
{
    for (uint32_t i = 0; i < g_PatternCount; i++)
    {
        if (g_PatternTable[i].featureHash == featureHash)
            return &g_PatternTable[i];
    }
    return NULL;
}

uint32_t GetPatternCount(void)
{
    return g_PatternCount;
}

uint32_t GetResolvedCount(void)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < g_PatternCount; i++)
    {
        if (g_PatternTable[i].bResolved)
            count++;
    }
    return count;
}

void LogPatternStatus(void)
{
    uint32_t total = g_PatternCount;
    uint32_t found = GetResolvedCount();

    if (found == total)
    {
        OutputDebugStringA("[LIBERTEA] All patterns resolved successfully");
    }
    else
    {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "[LIBERTEA] Patterns: %u/%u found. Some features may not work.", found, total);
        OutputDebugStringA(buf);

        for (uint32_t i = 0; i < total; i++)
        {
            if (!g_PatternTable[i].bResolved)
            {
                sprintf_s(buf, sizeof(buf), "[LIBERTEA] Missing: pattern 0x%08X", g_PatternTable[i].patternId);
                OutputDebugStringA(buf);
            }
        }
    }
}

void GetPatternSummary(PatternSummary* summary, uint32_t* count)
{
    static PatternSummary summaries[MAX_PATTERNS];
    uint32_t n = 0;

    for (uint32_t i = 0; i < g_PatternCount; i++)
    {
        bool found = false;
        for (uint32_t j = 0; j < n; j++)
        {
            if (summaries[j].moduleHash == g_PatternTable[i].moduleHash)
            {
                summaries[j].count++;
                if (g_PatternTable[i].bResolved)
                    summaries[j].resolved++;
                found = true;
                break;
            }
        }
        if (!found)
        {
            summaries[n].moduleHash = g_PatternTable[i].moduleHash;
            summaries[n].featureHash = g_PatternTable[i].featureHash;
            summaries[n].count = 1;
            summaries[n].resolved = g_PatternTable[i].bResolved ? 1 : 0;
            n++;
        }
    }

    memcpy(summary, summaries, sizeof(PatternSummary) * n);
    *count = n;
}
