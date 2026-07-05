#pragma once
#include <atomic>
#include <cstdint>

extern std::atomic<bool> g_scCallInFlight;

namespace HttpMonitor {
    void   Install(uintptr_t gameBase);
    void   Uninstall();
    void   InstallWinHttpHooks();
    void   ScanForActivityFunction();
    void*  GetRetStubAddr();
    void*  GetFakeVtableAddr();
    void*  GetFakeEntityAddr();
    void*  GetFakeFixupAddr();
}

bool        HasGoldenMissionId();
const char* GetGoldenMissionId();

int  HttpMonitor_GetActTotal();
int  HttpMonitor_GetActRewarded();
int  HttpMonitor_GetActNoReward();
int  HttpMonitor_GetActSCEarned();
int  HttpMonitor_GetActBonus();
void HttpMonitor_ResetCounters();

void HttpMonitor_ClearCallResult();
void HttpMonitor_SetCallResult(int v);
int  HttpMonitor_GetCallResult();

void HttpMonitor_AddRetryRecovered();
void HttpMonitor_AddRetryFailed();
int  HttpMonitor_GetRetryRecovered();
int  HttpMonitor_GetRetryFailed();

void ActivatePostSwap(const char* uuid);
void DeactivatePostSwap();

typedef void (*MissionEndRespCb)(int httpStatus, const char* bodySnippet);
void HttpMonitor_SetMissionEndCb(MissionEndRespCb cb);

bool        HttpMonitor_HasCapturedMissionEnd();
const char* HttpMonitor_GetCapturedMissionEndBody();
int         HttpMonitor_GetCapturedMissionEndBodyLen();
