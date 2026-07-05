
#include "license.h"
#include <functional>
#include <atomic>

static std::function<void()> s_deferredInitFn;
static std::atomic<bool>     s_initFired{false};

namespace License {

void SetDeferredInit(std::function<void()> fn) {
    s_deferredInitFn = fn;
}

void Init() {

    if (!s_initFired.exchange(true) && s_deferredInitFn)
        s_deferredInitFn();
}

bool IsUnlocked() { return true; }
void PollDeferredInit() {}
void Validate(const char*) {}
void Revoke() {}
const char* GetStatus() { return ""; }
std::string GetCacheFilePath() { return ""; }

}
