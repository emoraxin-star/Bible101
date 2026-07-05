#pragma once
#include <cstdint>

namespace Probe {
    bool Install(uintptr_t gameBase);
    void Uninstall();

    void EnableInstantComplete(bool enable);
    bool IsInstantCompleteActive();

    void RearmIC();

    void PauseDR2();
    void ResumeDR2();

    struct PlayerInfo {
        uint64_t id;
        char     name[33];
        uint32_t rank;
    };

    void GetCapturedPlayerInfo(PlayerInfo out[4], int& count);
}

extern bool g_probeEnabled;
