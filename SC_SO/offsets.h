#pragma once
#include <cstdint>

namespace GS {

    extern uintptr_t rv_fn6;
    extern uintptr_t rv_fn0;
    extern uintptr_t rv_fn5;
    extern uintptr_t rv_fn1;
    extern uintptr_t rv_fn7;
    extern uintptr_t rv_fn9;

    extern uintptr_t rv_gp4;
    extern uintptr_t rv_gp7;
    extern uintptr_t rv_gp3;
    extern uintptr_t rv_gp6;
    extern uintptr_t rv_gp5;
    extern uintptr_t rv_gp1;
    extern uintptr_t rv_fn8;
    extern uintptr_t rv_gp8;
    extern uintptr_t rv_gt;

    extern uintptr_t rv_sc_act;
    extern uintptr_t rv_sc_gbl;
    extern uintptr_t rv_sc_mid;
    extern uintptr_t rv_sc_ses;
    extern uintptr_t rv_pm_cnt;
    extern uintptr_t rv_pm_slt;
    extern uintptr_t rv_si_ctr;
    extern uintptr_t rv_si_flg;
    extern uintptr_t rv_si_url;
    extern uintptr_t rv_si_que;
    extern uintptr_t rv_si_rb;

    constexpr uint32_t OFF_RING_INDEX      = 0x3E0F0;
    constexpr uint32_t OFF_RING_BASE       = 0x3E0F8;
    constexpr uint32_t RING_SLOT_SIZE      = 0xC88;
    constexpr uint32_t RING_SLOT_COUNT     = 64;
    constexpr uint32_t RING_SLOT_MASK      = 0x3F;

    constexpr uint32_t SLOT_FLAG           = 0x000;
    constexpr uint32_t SLOT_TYPE_HASH      = 0x004;
    constexpr uint32_t SLOT_VERSION        = 0x008;
    constexpr uint32_t SLOT_URL            = 0x00C;
    constexpr uint32_t SLOT_URL_MAXLEN     = 0xC00;
    constexpr uint32_t SLOT_SERIAL_OBJ     = 0xC10;
    constexpr uint32_t SLOT_FLAGS2         = 0xC18;
    constexpr uint32_t SLOT_SELF_PTR       = 0xC20;
    constexpr uint32_t SLOT_READY          = 0xC28;
    constexpr uint32_t SLOT_SEQUENCE       = 0xC60;
    constexpr uint32_t SLOT_FIXUP          = 0xC68;
    constexpr uint32_t SLOT_FIELD_C70      = 0xC70;
    constexpr uint32_t SLOT_ENTITY_DATA    = 0xC78;
    constexpr uint32_t SLOT_FIELD_C80      = 0xC80;
    constexpr uint32_t SLOT_FIELD_C84      = 0xC84;

    constexpr uint32_t ENT_SESSION_ID      = 0x11B0B0;
    constexpr uint32_t ENT_FLAG_BYTE       = 0x31D789;
    constexpr uint32_t ENT_GATE_STRING     = 0x31D7BC;
    constexpr uint32_t kEFS                = 0x33A5A0;

    constexpr uint32_t WAR_SESSION_ID      = 0xB398;

    constexpr uint32_t TYPE_MISSION_END    = 0x1E555EA6;

    constexpr uint8_t   kGO     = 0x74;
    constexpr uint8_t   kGP    = 0xEB;

    constexpr uint8_t ENQUEUE_SIG[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83 };

}
