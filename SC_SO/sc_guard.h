#pragma once
#include <windows.h>

namespace ScGuard {

    void Install(uintptr_t gameBase, size_t gameSize);

    void RegisterOwnThread(DWORD tid);

    void UnregisterOwnThread(DWORD tid);

    void NotifyScApc(DWORD gameTid);

    bool ShouldBackoff();

    void ResetBackoff();

    int  GetAbsorptionCount();
}
