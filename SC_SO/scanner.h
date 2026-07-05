#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include <psapi.h>

struct AOBPattern {
    std::vector<uint8_t> bytes;
    std::vector<bool>    mask;

    static AOBPattern parse(const char* pattern) {
        AOBPattern p;
        while (*pattern) {
            while (*pattern == ' ') pattern++;
            if (!*pattern) break;
            if (pattern[0] == '?') {
                p.bytes.push_back(0);
                p.mask.push_back(false);
                pattern += (pattern[1] == '?') ? 2 : 1;
            } else {
                auto hex = [](char c) -> uint8_t {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    return 0;
                };
                p.bytes.push_back((hex(pattern[0]) << 4) | hex(pattern[1]));
                p.mask.push_back(true);
                pattern += 2;
            }
        }
        return p;
    }
};

inline uintptr_t ScanModule(const char* moduleName, const AOBPattern& pat) {
    HMODULE mod = GetModuleHandleA(moduleName);
    if (!mod) return 0;

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
        return 0;

    auto base = (const uint8_t*)mi.lpBaseOfDll;
    size_t size = mi.SizeOfImage;
    size_t patLen = pat.bytes.size();
    if (patLen == 0 || patLen > size) return 0;

    for (size_t i = 0; i <= size - patLen; i++) {
        bool match = true;
        for (size_t j = 0; j < patLen; j++) {
            if (pat.mask[j] && base[i + j] != pat.bytes[j]) {
                match = false;
                break;
            }
        }
        if (match) return (uintptr_t)(base + i);
    }
    return 0;
}

inline uintptr_t ScanModule(const char* moduleName, const char* pattern) {
    return ScanModule(moduleName, AOBPattern::parse(pattern));
}
