
#include "entity_protect.h"

namespace EntityProtect {

void Install() {

}

void Add(uintptr_t ) {

}

void Remove(uintptr_t ) {

}

void ClearAll() {

}

bool IsProtected(uintptr_t ) {
    return false;
}

bool IsAlive(uintptr_t addr, uintptr_t expectedVtable) {

    if (!addr || !expectedVtable) return false;
    __try {
        uintptr_t vt = *(uintptr_t*)addr;
        return (vt == expectedVtable);
    } __except(1) {
        return false;
    }
}

}
