
#include "farming.h"

namespace Farming {
    void Init() {}
    void Shutdown() {}
    void SetMultiplierHook(bool) {}
    bool IsMultiplierActive() { return false; }
    void SetAddSamples(bool) {}
    bool IsAddSamplesActive() { return false; }
    void SetSamplesReward(bool) {}
    bool IsSamplesRewardActive() { return false; }
    void SetForceDifficulty(bool) {}
    bool IsForceDifficultyActive() { return false; }
    void SetInstantShuttle(bool) {}
    bool IsInstantShuttleActive() { return false; }
    void SetReplayRefresh(bool) {}
    bool IsReplayRefreshActive() { return false; }
}
