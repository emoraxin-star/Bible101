
#include "sc_tracker.h"

static std::atomic<int> s_callCount{0};

void ScTracker::AddCall()         { s_callCount.fetch_add(1); }
int  ScTracker::GetCallCount()    { return s_callCount.load(); }
int  ScTracker::GetEstimatedSC()  { return s_callCount.load() * 10; }
void ScTracker::Reset()           { s_callCount.store(0); }
