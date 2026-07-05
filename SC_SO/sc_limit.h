#pragma once

namespace ScLimit {
    bool Install();
    void SetEnabled(bool on);
    bool IsEnabled();
    bool IsInstalled();
    void RotateNow();
    void RequestRotate();
    void ForceUUID(const char* uuid);
}
