#pragma once
#include <atomic>

namespace Replay {
    void TriggerReplay();
    void BurstReplay(int count);
    void ForceRewardSync();
    void Init();
    void Shutdown();
    void SetScEnabled(bool v);
    bool IsScEnabled();
    void SetScAutoSync(bool en);
    bool GetScAutoSync();
    void SetScIds(const uint64_t* ids, int count);
    void ClearReplayGuards();
    void SyncNow();
    void ReadCaptureToScIds();
    int  GetScIdCount();

    void SetScIntervalMs(int ms);
    int  GetScIntervalMs();
    void SetMaxXpEnabled(bool v);
    bool IsMaxXpEnabled();
    void SetScTimer(int minutes);
    void ClearScTimer();
    int  GetScCallsMade();
    int  GetScTimeRemaining();
    bool IsScCooldown();
    int  GetScCooldownRemaining();
    void SetMedalsEnabled(bool v);
    bool IsMedalsEnabled();
    void SetMedalsOnly(bool v);
    bool IsMedalsOnly();
    bool IsMedalBurst();
    int  GetScSkippedCalls();
    void SetScGoal(int sc);
    int  GetScGoal();

    int  GetCapturedParticipantCount();
}

extern bool g_offlineBoostMode;

extern std::atomic<bool>  g_burstActive;
extern std::atomic<int>   g_burstSent;
extern std::atomic<int>   g_burstTotal;
extern std::atomic<bool>  g_burstDone;

void* Replay_GetScApcCallback();

void* GetFakeEntityPtr();
void* GetFakeFixupPtr();
void* GetRetStubPtr();
void* GetFakeVtablePtr();
void* GetScRetStub();
