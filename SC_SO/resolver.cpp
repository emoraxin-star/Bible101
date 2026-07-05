
#include "resolver.h"
#include "offsets.h"
#include "scanner.h"
#include "state.h"
#include <windows.h>
#include <cstring>
#include <cstdio>
#include <vector>

std::vector<RvaReport> g_rvaReports;

static uintptr_t s_gameBase = 0;
static size_t    s_gameSize = 0;

static int32_t SafeRead32(uintptr_t addr) {
    if (!addr || addr + 4 > s_gameBase + s_gameSize) return 0;
    int32_t v = 0; memcpy(&v, (void*)addr, 4); return v;
}

static uintptr_t RipRelTarget(uintptr_t instr_addr) {
    int32_t rel32 = SafeRead32(instr_addr + 3);
    return instr_addr + 7 + (intptr_t)rel32;
}

static uintptr_t ToRVA(uintptr_t addr) {
    if (!addr || addr < s_gameBase) return 0;
    return addr - s_gameBase;
}

static void Report(const char* name, uintptr_t , uintptr_t& rva_var, uintptr_t resolved_rva, bool found, const char* method) {
    RvaReport r;
    r.name     = name;
    r.hardcoded = rva_var;
    r.found    = found;
    strncpy(r.method, method, sizeof(r.method) - 1);
    r.method[sizeof(r.method) - 1] = '\0';
    if (found) {
        r.resolved = resolved_rva;
        r.updated  = (resolved_rva != rva_var);
        rva_var    = resolved_rva;
    } else {
        r.resolved = rva_var;
        r.updated  = false;
    }
    g_rvaReports.push_back(r);
}

void ResolveAllRVAs(uintptr_t gameBase, size_t gameSize) {
    s_gameBase = gameBase;
    s_gameSize = gameSize;
    g_rvaReports.clear();

    auto FindRVA = [&](const char* pat) -> uintptr_t {
        uintptr_t addr = ScanModule("game.dll", pat);
        return ToRVA(addr);
    };
    auto FindAddr = [&](const char* pat) -> uintptr_t {
        return ScanModule("game.dll", pat);
    };

    struct PatternSet { const char* pat; const char* ver; };

    auto RevolverRVA = [&](const PatternSet* pats, int count, const char** hitVer) -> uintptr_t {
        for (int i = 0; i < count; i++) {
            uintptr_t rva = FindRVA(pats[i].pat);
            if (rva) { if (hitVer) *hitVer = pats[i].ver; return rva; }
        }
        if (hitVer) *hitVer = "none";
        return 0;
    };
    auto RevolverAddr = [&](const PatternSet* pats, int count, const char** hitVer) -> uintptr_t {
        for (int i = 0; i < count; i++) {
            uintptr_t addr = FindAddr(pats[i].pat);
            if (addr) { if (hitVer) *hitVer = pats[i].ver; return addr; }
        }
        if (hitVer) *hitVer = "none";
        return 0;
    };

    {
        const char* ver = nullptr;
        PatternSet pats[] = {
            {"48 89 5C 24 08 57 48 83 EC 30 C7 02 FF FF FF FF", "v22"},
            {"48 89 5C 24 08 57 48 83 EC 30 C7 02 FF FF FF 7F", "v21"},
            {"48 89 5C 24 08 57 48 83 EC 20 C7 02 FF FF FF FF", "v20"},
        };
        uintptr_t rva = RevolverRVA(pats, 3, &ver);
        char method[32]; snprintf(method, sizeof(method), "prologue/%s", ver);
        Report("FN_C", 0xEF9030, GS::rv_fn5, rva, rva != 0, rva ? method : "fallback");
    }

    {
        const char* ver = nullptr;
        PatternSet pats[] = {
            {"8B 46 ?? 83 E8 ?? 83 F8 ?? 41", "v22"},
            {"8B 47 ?? 83 E8 ?? 83 F8 ?? 41", "v21"},
        };
        uintptr_t rva = RevolverRVA(pats, 2, &ver);
        char method[32]; snprintf(method, sizeof(method), "prologue/%s", ver);
        Report("FN_D", 0x525C3E, GS::rv_fn6, rva, rva != 0, rva ? method : "fallback");
    }

    {
        const char* ver = nullptr;
        PatternSet pats[] = {
            {"40 53 57 48 81 EC 18 0D 00 00", "v22"},
            {"40 53 57 48 81 EC 28 0D 00 00", "v21"},
        };
        uintptr_t rva = RevolverRVA(pats, 2, &ver);
        char method[32]; snprintf(method, sizeof(method), "prologue/%s", ver);
        Report("FN_F", 0xEF74E0, GS::rv_fn8, rva, rva != 0, rva ? method : "fallback");
    }

    {
        const char* ver = nullptr;
        PatternSet pats[] = {
            {"C7 44 24 24 1B 94 E7 01", "v22"},
            {"C7 44 24 20 1B 94 E7 01", "v21"},
        };
        uintptr_t hit = RevolverAddr(pats, 2, &ver);
        uintptr_t rva = (hit && hit > s_gameBase + 0x40) ? ToRVA(hit - 0x40) : 0;
        char method[32]; snprintf(method, sizeof(method), "constant/%s", ver);
        Report("FN_9", 0xEE9E00, GS::rv_fn9, rva, rva != 0, rva ? method : "fallback");
    }

    {
        const char* ver = nullptr;
        PatternSet pats[] = {
            {"74 ?? 49 8D 83 ?? ?? ?? ?? 39 50 04 74 ?? "
             "FF C1 48 83 C0 18 41 3B ?? 72 F0 EB ?? 8B", "v22"},
            {"74 ?? 49 8D 87 ?? ?? ?? ?? 39 50 04 74 ?? "
             "FF C1 48 83 C0 18 41 3B ?? 72 F0 EB ?? 8B", "v21"},
        };
        uintptr_t rva = RevolverRVA(pats, 2, &ver);
        char method[32]; snprintf(method, sizeof(method), "context/%s", ver);
        Report("FN_GT", 0xF0889F, GS::rv_gt, rva, rva != 0, rva ? method : "fallback");
    }

    uintptr_t serFactXrefAddr = 0;
    int serFactFuncOffset = 0x021;
    {
        const char* ver = nullptr;
        PatternSet pats[] = {
            {"48 8B 05 ?? ?? ?? ?? 33 D2 48 8B 35", "v22/off21"},
            {"48 8B 05 ?? ?? ?? ?? 33 D2 48 8B 3D", "v21/off21"},
            {"48 8B 05 ?? ?? ?? ?? 33 D2 4C 8B 35", "v20/off21"},
        };
        uintptr_t xref = RevolverAddr(pats, 3, &ver);
        serFactXrefAddr = xref;
        uintptr_t global_addr = xref ? RipRelTarget(xref) : 0;
        uintptr_t rva = ToRVA(global_addr);
        char method[32]; snprintf(method, sizeof(method), "xref/%s", ver);
        Report("PTR_A", 0x1A7F738, GS::rv_gp1, rva, rva != 0, rva ? method : "fallback");
    }

    {
        uintptr_t rva = serFactXrefAddr ? ToRVA(serFactXrefAddr - serFactFuncOffset) : 0;
        Report("FN_B", 0xEEF040, GS::rv_fn1, rva, rva != 0, "derived");
    }

    {
        const char* ver = nullptr;
        PatternSet pats[] = {
            {"48 8B 35 ?? ?? ?? ?? 49 8B E9 41 8B D8 48 8B 88 28 01", "v22"},
            {"48 8B 35 ?? ?? ?? ?? 33 C9 49 8B E9 41 8B D8 4C 8B 90 28 01", "v21"},
            {"48 8B 3D ?? ?? ?? ?? 49 8B E9 41 8B D8 48 8B 88 28 01", "v20"},
        };
        uintptr_t xref = RevolverAddr(pats, 3, &ver);
        uintptr_t global_addr = xref ? RipRelTarget(xref) : 0;
        uintptr_t rva = ToRVA(global_addr);
        char method[32]; snprintf(method, sizeof(method), "xref/%s", ver);
        Report("PTR_D", 0x1A91BA8, GS::rv_gp4, rva, rva != 0, rva ? method : "fallback");
    }

    uintptr_t sessDataXrefAddr = 0;
    {
        const char* ver = nullptr;
        PatternSet pats[] = {
            {"48 8B 0D ?? ?? ?? ?? 44 89 80 60 0C", "v22"},
            {"48 8B 0D ?? ?? ?? ?? 44 89 80 58 0C", "v21"},
            {"48 8B 0D ?? ?? ?? ?? 44 89 80 68 0C", "v20"},
        };
        uintptr_t xref = RevolverAddr(pats, 3, &ver);
        sessDataXrefAddr = xref;
        uintptr_t global_addr = xref ? RipRelTarget(xref) : 0;
        uintptr_t rva = ToRVA(global_addr);
        char method[32]; snprintf(method, sizeof(method), "xref/%s", ver);
        Report("PTR_C", 0x1A7F788, GS::rv_gp3, rva, rva != 0, rva ? method : "fallback");
    }

    {
        uintptr_t rva = sessDataXrefAddr ? ToRVA(sessDataXrefAddr - 0x1F4) : 0;
        Report("FN_A", 0xEEEA80, GS::rv_fn0, rva, rva != 0, "derived");
    }

    {
        const char* ver = nullptr;
        PatternSet pats[] = {
            {"48 8B 05 ?? ?? ?? ?? 8B 90 90 63 01 00 4C 8D 88 C8 62 01 00", "v22"},
            {"48 8B 05 ?? ?? ?? ?? 8B 90 98 63 01 00 4C 8D 88 D0 62 01 00", "v21"},
            {"48 8B 05 ?? ?? ?? ?? 8B 90 88 63 01 00 4C 8D 88 C0 62 01 00", "v20"},
        };
        uintptr_t xref = RevolverAddr(pats, 3, &ver);
        uintptr_t global_addr = xref ? RipRelTarget(xref) : 0;
        uintptr_t rva = ToRVA(global_addr);
        char method[32]; snprintf(method, sizeof(method), "xref/%s", ver);
        Report("PTR_PM", 0x1A925B8, GS::rv_gp7, rva, rva != 0, rva ? method : "fallback");
    }

    bool anyFallback = false;
    for (auto& r : g_rvaReports) {
        if (!r.found) { anyFallback = true; break; }
    }

    if (anyFallback && s_gameBase && s_gameSize) {

        std::string dir = GetDllDir();
        std::string outPath = dir + "game_current.dll";

        auto* dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(s_gameBase);
        auto* ntHdr  = reinterpret_cast<IMAGE_NT_HEADERS64*>(s_gameBase + dosHdr->e_lfanew);
        DWORD imageSize = ntHdr->OptionalHeader.SizeOfImage;

        std::vector<BYTE> buf(imageSize, 0);

        static const DWORD kBadProtect = PAGE_NOACCESS | PAGE_GUARD;
        for (DWORD off = 0; off < imageSize; off += 0x1000) {
            MEMORY_BASIC_INFORMATION mbi{};
            uintptr_t page = s_gameBase + off;
            if (!VirtualQuery((void*)page, &mbi, sizeof(mbi))) continue;
            if (mbi.State != MEM_COMMIT) continue;
            if (mbi.Protect & kBadProtect) continue;
            DWORD copyLen = (imageSize - off < 0x1000u) ? (imageSize - off) : 0x1000u;
            memcpy(buf.data() + off, (void*)page, copyLen);
        }

        FILE* f = fopen(outPath.c_str(), "wb");
        if (f) {
            fwrite(buf.data(), 1, imageSize, f);
            fclose(f);
        }
    }
}
