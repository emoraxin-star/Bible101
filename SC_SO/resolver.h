#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct RvaReport {
    std::string name;
    uintptr_t   hardcoded;
    uintptr_t   resolved;
    bool        found;
    bool        updated;
    char method[48];
};

extern std::vector<RvaReport> g_rvaReports;

void ResolveAllRVAs(uintptr_t gameBase, size_t gameSize);
