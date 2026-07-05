#pragma once
#include <windows.h>
#include <cstdint>

namespace FarmingConfig {

    inline int  difficultyLevel   = 10;

    inline int  rewardCommon = 100;
    inline int  rewardRare   = 100;
    inline int  rewardSuper  = 100;
}

namespace Farming {
    void Init();
    void Shutdown();

    void SetMultiplierHook(bool enable);
    bool IsMultiplierActive();

    void SetAddSamples(bool enable);
    bool IsAddSamplesActive();

    void SetSamplesReward(bool enable);
    bool IsSamplesRewardActive();

    void SetForceDifficulty(bool enable);
    bool IsForceDifficultyActive();

    void SetInstantShuttle(bool enable);
    bool IsInstantShuttleActive();

    void SetReplayRefresh(bool enable);
    bool IsReplayRefreshActive();

}
