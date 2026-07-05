#pragma once

namespace ScPresent {
    bool Install();
    void Shutdown();
    bool IsReady();
    bool QueueSC(void* actObj);
    bool QueueCall(void* fn, void* arg);
    void SetCallback(void* fn);
}
