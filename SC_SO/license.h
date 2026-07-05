#pragma once
#include <string>
#include <functional>

namespace License {

    void SetDeferredInit(std::function<void()> fn);
    void PollDeferredInit();

    void Init();

    bool IsUnlocked();

    void Validate(const char* key);

    void Revoke();

    const char* GetStatus();

    std::string GetCacheFilePath();
}
