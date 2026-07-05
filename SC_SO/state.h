#pragma once
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include "offsets.h"

struct FieldOverride {
    int32_t  offset  = -1;
    uint32_t value   = 0;
    bool     enabled = false;
    char     label[32] = {};
};

struct CapturedMission {
    uintptr_t serverInfo     = 0;
    uintptr_t entityPtr      = 0;
    uintptr_t missionData    = 0;
    uintptr_t entityDataVal  = 0;
    uintptr_t entityVtable   = 0;

    void*    entityDeepCopy      = nullptr;
    size_t   entityDeepCopySize  = 0;
    void*    entityDataDeepCopy  = nullptr;
    size_t   entityDataDeepCopySize = 0;
    uint8_t   slotData[GS::RING_SLOT_SIZE] = {};
    std::vector<uint8_t> missionDataSnapshot;
    std::vector<uint8_t> serObjSnapshot;
    uintptr_t serObjOrigAddr = 0;
    bool      valid          = false;
    uint64_t  captureTime    = 0;
    char      missionStr[64] = {};
    char      url[256]       = {};

    FieldOverride xpOverride     = {-1, 0, false, "XP"};
    FieldOverride medalsOverride = {-1, 0, false, "Medals"};
    FieldOverride slipsOverride  = {-1, 0, false, "Req.Slips"};
};

struct LogEntry {
    char      message[256];
    bool      isError;
    uint64_t  timestamp;
};

inline void FormatHex(char* buf, size_t bufSz, uintptr_t val) {
    snprintf(buf, bufSz, "0x%llX", (unsigned long long)val);
}

struct ReplayState {

    std::atomic<bool> probeArmed{false};
    std::atomic<bool> hookInstalled{false};

    std::atomic<bool> instantMissionEnabled{false};

    std::mutex captureMutex;
    std::vector<CapturedMission> captures;

    ReplayState() { captures.reserve(2); }

    std::atomic<int>  replayCount{0};
    std::atomic<bool> replayInProgress{false};
    float cooldownRemaining = 0.0f;
    float replayHardlock    = 300.0f;
    uint64_t lastReplayTick = 0;

    bool autoReplayEnabled    = false;
    float autoReplayInterval  = 45.0f;
    bool sessionLimitEnabled  = false;
    int  sessionLimitMinutes  = 30;
    uint64_t sessionStartTick = 0;
    uint64_t lastAutoReplayTick = 0;
    bool replayLimitEnabled   = false;
    int  maxReplays           = 10;

    std::atomic<bool> gatePatched{false};
    uintptr_t gateAddress   = 0;
    uint8_t   gateOrigByte  = 0;

    DWORD     gameThreadId    = 0;
    HANDLE    gameThreadHandle = nullptr;
    uint32_t  capturedWarTime = 0;
    uint64_t  captureTickCount = 0;

    uintptr_t gameBase      = 0;
    uintptr_t gameEnd       = 0;
    uintptr_t pServerInfo   = 0;
    uintptr_t pWarData      = 0;
    uintptr_t pEntityData   = 0;

    std::mutex logMutex;
    std::vector<LogEntry> log;

    std::mutex replayLogMutex;
    std::vector<LogEntry> replayLog;

    void AddLog(const char* msg, bool isError = false) {
        std::lock_guard<std::mutex> lk(logMutex);
        LogEntry e{};
        strncpy(e.message, msg, sizeof(e.message) - 1);
        e.isError   = isError;
        e.timestamp = GetTickCount64();
        log.push_back(e);
        if (log.size() > 200) log.erase(log.begin());
    }
    void AddReplayLog(const char* msg, bool isError = false) {
        std::lock_guard<std::mutex> lk(replayLogMutex);
        LogEntry e{};
        strncpy(e.message, msg, sizeof(e.message) - 1);
        e.isError   = isError;
        e.timestamp = GetTickCount64();
        replayLog.push_back(e);
        if (replayLog.size() > 100) replayLog.erase(replayLog.begin());
    }

    void AddLogFmt(bool isError, const char* fmt, ...) {
        char buf[256];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        AddLog(buf, isError);
    }

    bool     activityCaptured    = true;
    char     activityGmiStr[256] = "5E6A8B0956099E8F73549268D7FD0A2F7D1C2FC5524F1F682EFEC91AA0DB74A31938FF783173BBDE56E9DC57400E34E676D9B617E4275BA6F51F837AE222D631B5EBD73EBACFCD6998F1F1B9A5324A8765F237863909DFFA36F5863D4A2F426C3690344C0ABA52DDE0EC08B6D1283895";
    uint32_t activityObjectId    = 1309039571u;
};

struct WeaponOverride {
    bool     enabled          = false;
    uint32_t targetId         = 0;
    char     targetName[64]   = {};
    int      selectedIndex    = -1;
    int      lastReplacements = 0;

    bool     allGunsMode      = false;
    int      allGunsIndex     = 0;
    int      gunsReplaysPerWeapon = 9;
    int      allGunsCounter   = 0;

    bool     selectedGunsMode       = false;
    bool     selectedGunsChecked[51];
    int      selectedGunsList[51];
    int      selectedGunsCount      = 0;
    int      selectedGunsPos        = 0;
    int      selectedGunsCounter    = 0;
    bool     forceNextWeapon        = false;

    int      scPerReplay            = 0;

    WeaponOverride() {
        memset(selectedGunsChecked, 0, sizeof(selectedGunsChecked));
        memset(selectedGunsList,    0, sizeof(selectedGunsList));
    }
};

inline std::string BinToHex(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789ABCDEF";
    std::string out; out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out += hex[data[i] >> 4];
        out += hex[data[i] & 0xF];
    }
    return out;
}

inline std::vector<uint8_t> HexToBin(const std::string& s) {
    auto h = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
        if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
        if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
        return 0;
    };
    std::vector<uint8_t> out; out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back((h(s[i]) << 4) | h(s[i+1]));
    return out;
}

inline ReplayState g_state;
inline WeaponOverride g_weaponOverride;

inline HMODULE g_hModule = nullptr;

inline std::string GetDllDir() {
    if (!g_hModule) return "C:\\";
    wchar_t wpath[MAX_PATH] = {};
    GetModuleFileNameW(g_hModule, wpath, MAX_PATH);
    std::wstring ws(wpath);
    auto pos = ws.rfind(L'\\');
    if (pos != std::wstring::npos) ws = ws.substr(0, pos + 1);
    char narrow[MAX_PATH] = {};
    WideCharToMultiByte(CP_ACP, 0, ws.c_str(), -1, narrow, MAX_PATH, nullptr, nullptr);
    return std::string(narrow);
}

inline void SaveCapture(ReplayState& st) {
    if (st.captures.empty()) return;
    const auto& cap = st.captures.back();
    if (!cap.valid) return;

    std::string path = GetDllDir() + "replay_cap.json";
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return;

    fprintf(f, "{\n");
    fprintf(f, "  \"capturedWarTime\": %u,\n", st.capturedWarTime);
    std::string urlEsc;
    for (char c : std::string(cap.url)) { if (c == '\\') urlEsc += "\\\\"; else urlEsc += c; }
    fprintf(f, "  \"url\": \"%s\",\n", urlEsc.c_str());
    fprintf(f, "  \"serObjOrigAddr\": %llu,\n", (unsigned long long)cap.serObjOrigAddr);
    fprintf(f, "  \"md\": \"%s\",\n",
            BinToHex(cap.missionDataSnapshot.data(), cap.missionDataSnapshot.size()).c_str());
    fprintf(f, "  \"serObj\": \"%s\",\n",
            BinToHex(cap.serObjSnapshot.data(), cap.serObjSnapshot.size()).c_str());
    fprintf(f, "  \"slotData\": \"%s\",\n",
            BinToHex(cap.slotData, GS::RING_SLOT_SIZE).c_str());

    if (cap.entityDeepCopy && cap.entityDeepCopySize > 0)
        fprintf(f, "  \"entityDeep\": \"%s\",\n",
                BinToHex((const uint8_t*)cap.entityDeepCopy, cap.entityDeepCopySize).c_str());
    if (cap.entityDataDeepCopy && cap.entityDataDeepCopySize > 0)
        fprintf(f, "  \"entityDataDeep\": \"%s\",\n",
                BinToHex((const uint8_t*)cap.entityDataDeepCopy, cap.entityDataDeepCopySize).c_str());

    fprintf(f, "  \"ac\": %d,\n", st.activityCaptured ? 1 : 0);
    fprintf(f, "  \"oi\": %u,\n", st.activityObjectId);
    fprintf(f, "  \"gs\": \"%s\"\n", st.activityGmiStr);
    fprintf(f, "}\n");
    fclose(f);
}

inline bool LoadCapture(ReplayState& st) {
    std::string path = GetDllDir() + "replay_cap.json";
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return false;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 64 * 1024 * 1024) { fclose(f); return false; }

    std::string json((size_t)sz, '\0');
    fread(&json[0], 1, (size_t)sz, f);
    fclose(f);

    auto extractStr = [&](const char* key) -> std::string {
        std::string k = std::string("\"") + key + "\": \"";
        size_t p = json.find(k);
        if (p == std::string::npos) return {};
        p += k.size();
        std::string out;
        while (p < json.size() && json[p] != '"') {
            if (json[p] == '\\' && p + 1 < json.size()) { ++p; }
            out += json[p++];
        }
        return out;
    };
    auto extractNum = [&](const char* key) -> unsigned long long {
        std::string k = std::string("\"") + key + "\": ";
        size_t p = json.find(k);
        if (p == std::string::npos) return 0;
        p += k.size();
        return strtoull(json.c_str() + p, nullptr, 10);
    };

    CapturedMission cap;
    cap.valid       = true;
    cap.captureTime = GetTickCount64();

    st.capturedWarTime = (uint32_t)extractNum("capturedWarTime");
    cap.serObjOrigAddr = (uintptr_t)extractNum("serObjOrigAddr");

    std::string urlStr = extractStr("url");
    strncpy(cap.url, urlStr.c_str(), sizeof(cap.url) - 1);

    auto mdHex = extractStr("md");
    cap.missionDataSnapshot = HexToBin(mdHex);
    cap.serObjSnapshot      = HexToBin(extractStr("serObj"));

    auto slotBin = HexToBin(extractStr("slotData"));
    size_t copyLen = slotBin.size() < GS::RING_SLOT_SIZE ? slotBin.size() : GS::RING_SLOT_SIZE;
    if (copyLen > 0) memcpy(cap.slotData, slotBin.data(), copyLen);

    if (cap.missionDataSnapshot.empty()) return false;

    {
        auto edHex = extractStr("entityDeep");
        if (!edHex.empty()) {
            auto edBin = HexToBin(edHex);
            if (!edBin.empty()) {
                void* mem = VirtualAlloc(nullptr, edBin.size(),
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (mem) {
                    memcpy(mem, edBin.data(), edBin.size());
                    cap.entityDeepCopy     = mem;
                    cap.entityDeepCopySize = edBin.size();
                }
            }
        }
        auto eddHex = extractStr("entityDataDeep");
        if (!eddHex.empty()) {
            auto eddBin = HexToBin(eddHex);
            if (!eddBin.empty()) {
                void* mem = VirtualAlloc(nullptr, eddBin.size(),
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (mem) {
                    memcpy(mem, eddBin.data(), eddBin.size());
                    cap.entityDataDeepCopy     = mem;
                    cap.entityDataDeepCopySize = eddBin.size();
                }
            }
        }
    }

    auto oi = extractNum("oi");
    st.activityObjectId = (uint32_t)oi;
    std::string gmiStr  = extractStr("gs");
    auto ac = extractNum("ac");
    if (!gmiStr.empty()) {
        strncpy(st.activityGmiStr, gmiStr.c_str(), sizeof(st.activityGmiStr) - 1);
        st.activityCaptured = (ac != 0) && !gmiStr.empty();
    }

    {
        std::lock_guard<std::mutex> lk(st.captureMutex);
        st.captures.push_back(std::move(cap));
    }
    st.AddLog("[+] Data restored");
    if (st.activityCaptured)
        st.AddLog("[+] Ready");
    return true;
}

#include "baked_capture.h"

inline bool LoadBakedCapture(ReplayState& st) {
    CapturedMission cap;
    cap.valid       = true;
    cap.captureTime = GetTickCount64();

    st.capturedWarTime = kBakedWarTime;
    cap.serObjOrigAddr = kBakedSerObjAddr;

    strncpy(cap.url, kBakedUrl, sizeof(cap.url) - 1);

    cap.missionDataSnapshot.assign(kBakedMd, kBakedMd + sizeof(kBakedMd));

    size_t slotCopy = sizeof(kBakedSlot) < GS::RING_SLOT_SIZE ? sizeof(kBakedSlot) : GS::RING_SLOT_SIZE;
    memcpy(cap.slotData, kBakedSlot, slotCopy);

    st.activityObjectId = kBakedObjectId;
    char gsHex[512] = {};
    for (size_t i = 0; i < sizeof(kBakedGs) && i * 2 + 1 < sizeof(gsHex); i++) {
        static const char hex[] = "0123456789ABCDEF";
        gsHex[i * 2]     = hex[(kBakedGs[i] >> 4) & 0xF];
        gsHex[i * 2 + 1] = hex[kBakedGs[i] & 0xF];
    }
    strncpy(st.activityGmiStr, gsHex, sizeof(st.activityGmiStr) - 1);
    st.activityCaptured = true;

    {
        std::lock_guard<std::mutex> lk(st.captureMutex);
        st.captures.push_back(std::move(cap));
    }
    st.AddLog("[+] Baked capture loaded");
    st.AddLog("[+] Ready — hit Sync");
    return true;
}

inline void SaveSessionStats(int sent, int acked) {
    std::string path = GetDllDir() + "session.json";
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return;
    fprintf(f, "{\"sent\":%d,\"acked\":%d}\n", sent, acked);
    fclose(f);
}

inline bool LoadSessionStats(int& sent, int& acked) {
    std::string path = GetDllDir() + "session.json";
    FILE* f = fopen(path.c_str(), "r");
    if (!f) { sent = 0; acked = 0; return false; }
    sent = 0; acked = 0;
    fscanf(f, "{\"sent\":%d,\"acked\":%d}", &sent, &acked);
    fclose(f);
    return (sent > 0 || acked > 0);
}
