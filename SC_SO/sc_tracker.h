#pragma once
#include <atomic>

namespace ScTracker {
    void AddCall();
    int  GetCallCount();
    int  GetEstimatedSC();
    void Reset();
}
