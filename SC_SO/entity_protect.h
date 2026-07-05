#pragma once

#include <windows.h>
#include <cstdint>

namespace EntityProtect {
    void Install();
    void Add(uintptr_t addr);
    void Remove(uintptr_t addr);
    void ClearAll();
    bool IsProtected(uintptr_t addr);
    bool IsAlive(uintptr_t addr, uintptr_t expectedVtable);
}
