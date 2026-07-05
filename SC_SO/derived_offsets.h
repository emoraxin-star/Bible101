#pragma once
#include "offsets.h"

inline uintptr_t GetActivityFnRVA() {
    if (GS::rv_sc_act) return GS::rv_sc_act;
    return GS::rv_fn0 ? (GS::rv_fn0 + 0x230) : 0;
}

inline uintptr_t GetGameGlobalRVA() {
    if (GS::rv_sc_gbl) return GS::rv_sc_gbl;
    return GS::rv_gp4 ? (GS::rv_gp4 + 8) : 0;
}

inline uint32_t GetMissionIdOffset() {
    return GS::rv_sc_mid ? (uint32_t)GS::rv_sc_mid : 0;
}

inline uint32_t GetSessionDispatch() {
    return GS::rv_sc_ses ? (uint32_t)GS::rv_sc_ses : 0;
}

inline uint32_t GetPeerMgrCountOff() {
    return GS::rv_pm_cnt ? (uint32_t)GS::rv_pm_cnt : 0;
}

inline uint32_t GetPeerMgrSlotOff() {
    return GS::rv_pm_slt ? (uint32_t)GS::rv_pm_slt : 0;
}

inline uint32_t GetSICtrOff() {
    return GS::rv_si_ctr ? (uint32_t)GS::rv_si_ctr : 0;
}

inline uint32_t GetSIFlagOff() {
    return GS::rv_si_flg ? (uint32_t)GS::rv_si_flg : 0;
}

inline uint32_t GetSIUrlOff() {
    return GS::rv_si_url ? (uint32_t)GS::rv_si_url : 0;
}

inline uint32_t GetSIQueueOff() {
    return GS::rv_si_que ? (uint32_t)GS::rv_si_que : 0;
}

inline uint32_t GetSIReqBufOff() {
    return GS::rv_si_rb ? (uint32_t)GS::rv_si_rb : 0;
}
