
#include "http_monitor.h"
#include "sc_debug.h"
#include <windows.h>
#include <cstring>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstdio>
#include <objbase.h>   
#include <dbghelp.h>   
#pragma comment(lib, "dbghelp.lib")
#include <psapi.h>     
#pragma comment(lib, "psapi.lib")
#include <tlhelp32.h>  

typedef void  CURL;
typedef int   CURLcode;
typedef unsigned int CURLoption;
typedef unsigned int CURLINFO;

#define OPT_WRITEDATA       10001u
#define OPT_URL             10002u
#define OPT_POSTFIELDS      10015u
#define OPT_HTTPHEADER      10023u
#define OPT_WRITEFUNCTION   20011u
#define OPT_HEADERFUNCTION  20079u
#define OPT_HEADERDATA      10029u
#define OPT_POSTFIELDSIZE   60u
#define OPT_COPYPOSTFIELDS  10165u

#define INFO_RESPONSE_CODE  0x200002u

typedef size_t (__cdecl *write_fn_t)(char*, size_t, size_t, void*);
typedef CURLcode (*pfn_setopt )(CURL*, CURLoption, ...);
typedef CURLcode (*pfn_perform)(CURL*);
typedef CURLcode (*pfn_getinfo)(CURL*, CURLINFO, ...);
typedef void     (*pfn_cleanup)(CURL*);

static pfn_setopt   o_setopt   = nullptr;
static pfn_perform  o_perform  = nullptr;
static pfn_cleanup  o_cleanup  = nullptr;
static pfn_getinfo  d_getinfo  = nullptr;

#define MAX_TRACKED  64
struct HInfo {
    uintptr_t   key;
    char        url[512];
    bool        mg;
    bool        act;
    bool        recon;
    write_fn_t  real_wfn;
    void*       real_wdata;
    char        body[4096];
    int         blen;
    bool        status_logged;
    bool        capture_installed;

    char        rawPost[8192];
    int         rawPostLen;
    char        modPost[8192];
    int         modPostLen;
    bool        postInjected;

    char        cloneHdrs[16][1024];
    int         cloneHdrCount;
    bool        hasXSig;

    long        resp_code;
    bool        needsRewardCheck;
};

static CRITICAL_SECTION  g_cs;
static HInfo             g_slots[MAX_TRACKED];
static volatile bool     g_installed = false;

struct curl_slist { char* data; struct curl_slist* next; };

#define MAX_AUTH_HEADERS 32
#define MAX_HDR_LEN     1024
static char  g_authHeaders[MAX_AUTH_HEADERS][MAX_HDR_LEN];
static int   g_authHeaderCount = 0;
static bool  g_authCaptured = false;
static char  g_authBaseURL[512] = {0};

static char  g_goldenMissionId[128] = {0};
static bool  g_hasGolden = false;

static std::atomic<bool> g_swapActive{false};
static char              g_swapUUID[64] = {0};

typedef CURL* (*pfn_easy_init)(void);
typedef struct curl_slist* (*pfn_slist_append)(struct curl_slist*, const char*);
typedef void (*pfn_slist_free)(struct curl_slist*);
static pfn_easy_init   p_easy_init   = nullptr;
static pfn_slist_append p_slist_append = nullptr;
static pfn_slist_free  p_slist_free  = nullptr;
static volatile LONG   g_cloneTestDone = 0;

#define OPT_SSL_VERIFYPEER  64u
#define OPT_SSL_VERIFYHOST  81u

struct CloneData {
    char url[512];
    char hdrs[16][1024];
    int  hdrCount;
    char body[8192];
    int  bodyLen;
};
static CloneData g_cloneData = {};

static DWORD WINAPI clone_worker(LPVOID);

static void httpLog(const char* , ...) {  }

static MissionEndRespCb g_missionEndCb = nullptr;
void HttpMonitor_SetMissionEndCb(MissionEndRespCb cb) { g_missionEndCb = cb; }

static char*  g_capturedMEBody    = nullptr;
static int    g_capturedMEBodyLen = 0;
static bool   g_hasCapturedME    = false;
bool        HttpMonitor_HasCapturedMissionEnd()        { return g_hasCapturedME; }
const char* HttpMonitor_GetCapturedMissionEndBody()    { return g_capturedMEBody; }
int         HttpMonitor_GetCapturedMissionEndBodyLen() { return g_capturedMEBodyLen; }

static bool extract_missionid(const char* body, char* out, int outSz) {

    const char* keys[] = { "\"missionId\":\"", "\"missionId\" : \"" };
    const char* p = nullptr;
    size_t klen = 0;
    for (int i = 0; i < 2; i++) {
        p = strstr(body, keys[i]);
        if (p) { klen = strlen(keys[i]); break; }
    }
    if (!p) return false;
    p += klen;
    const char* end = strchr(p, '"');
    if (!end || (end - p) < 8 || (end - p) >= outSz) return false;
    memcpy(out, p, end - p);
    out[end - p] = 0;
    return true;
}

static void try_capture_golden(const char* rawPost) {
    char mid[128];
    int rlen = (int)strlen(rawPost);
    httpLog("[GOLDEN-CAP] try_capture_golden called, rawPost len=%d", rlen);

    {
        char dump[513];
        int dlen = rlen < 512 ? rlen : 512;
        memcpy(dump, rawPost, dlen);
        dump[dlen] = 0;
        httpLog("[GOLDEN-CAP] rawPost dump: %s", dump);
    }

    {
        char hex[256];
        int hlen = rlen < 64 ? rlen : 64;
        for (int i = 0; i < hlen; i++)
            sprintf(hex + i*3, "%02X ", (unsigned char)rawPost[i]);
        hex[hlen*3] = 0;
        httpLog("[GOLDEN-CAP] rawPost hex[0..%d]: %s", hlen, hex);
    }

    if (!extract_missionid(rawPost, mid, sizeof(mid))) {
        httpLog("[GOLDEN-CAP] extract_missionid FAILED — no missionId key found");
        return;
    }
    if (mid[0] == 0) {
        httpLog("[GOLDEN-CAP] missionId is empty — skipping (ship mode)");
        return;
    }
    strncpy(g_goldenMissionId, mid, sizeof(g_goldenMissionId) - 1);
    g_goldenMissionId[sizeof(g_goldenMissionId) - 1] = 0;
    g_hasGolden = true;
    httpLog("[GOLDEN-CAP] ✓ CAPTURED missionId=%s", g_goldenMissionId);
}

static HInfo* find_slot(uintptr_t k, bool create) {
    HInfo* empty = nullptr;
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (g_slots[i].key == k) return &g_slots[i];
        if (!empty && g_slots[i].key == 0) empty = &g_slots[i];
    }
    if (create && empty) {
        memset(empty, 0, sizeof(*empty));
        empty->key = k;
        return empty;
    }
    return nullptr;
}

static void free_slot(uintptr_t k) {
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (g_slots[i].key == k) { g_slots[i].key = 0; return; }
    }
}

static void gen_uuid4(char* buf) {
    GUID guid;
    CoCreateGuid(&guid);
    sprintf(buf, "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

static bool try_inject_missionid(HInfo* hi) {
    if (!hi->act) return false;
    if (hi->rawPostLen <= 0) return false;

    const char* needle = "\"missionId\"";
    const char* mpos = strstr(hi->rawPost, needle);
    if (!mpos) {
        sc_dbg("[HTTP] INJECT: no missionId field found in Activity POST body");
        return false;
    }

    const char* p = mpos + strlen(needle);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;

    if (*p != '"') {
        sc_dbg("[HTTP] INJECT: missionId value not a string (got 0x%02X)", (unsigned)*p);
        return false;
    }

    const char* valStart = p;
    const char* valEnd = nullptr;
    for (const char* q = valStart + 1; *q; q++) {
        if (*q == '\\') { q++; continue; }
        if (*q == '"') { valEnd = q; break; }
    }
    if (!valEnd) {
        sc_dbg("[HTTP] INJECT: unterminated missionId string");
        return false;
    }

    int oldValLen = (int)(valEnd - valStart - 1);

    char idBuf[128];
    int idLen;

    if (oldValLen > 0 && g_swapActive.load()) {

        strncpy(idBuf, g_swapUUID, sizeof(idBuf) - 1);
        idBuf[sizeof(idBuf) - 1] = 0;
        idLen = (int)strlen(idBuf);
        httpLog("[HTTP] SWAP: replacing missionId (old %d chars) with %s", oldValLen, idBuf);
    } else if (oldValLen > 0) {

        return false;
    } else {

        if (g_hasGolden && g_goldenMissionId[0]) {
            strncpy(idBuf, g_goldenMissionId, sizeof(idBuf) - 1);
            idBuf[sizeof(idBuf) - 1] = 0;
        } else {
            gen_uuid4(idBuf);
        }
        idLen = (int)strlen(idBuf);
    }

    int newLen = hi->rawPostLen - oldValLen + idLen;
    if (newLen >= (int)sizeof(hi->modPost) - 1) {
        sc_dbg("[HTTP] INJECT: modified body too large (%d bytes)", newLen);
        return false;
    }

    int prefixLen = (int)(valStart - hi->rawPost) + 1;
    memcpy(hi->modPost, hi->rawPost, prefixLen);
    memcpy(hi->modPost + prefixLen, idBuf, idLen);
    int suffixStart = (int)(valEnd - hi->rawPost);
    int suffixLen   = hi->rawPostLen - suffixStart;
    memcpy(hi->modPost + prefixLen + idLen, hi->rawPost + suffixStart, suffixLen);
    hi->modPost[prefixLen + idLen + suffixLen] = 0;
    hi->modPostLen = newLen;
    hi->postInjected = true;

    sc_dbg("[HTTP] INJECT: missionId=\"%s\" (%s) injected (%d → %d bytes)",
           idBuf, g_hasGolden ? "GOLDEN" : "UUID", hi->rawPostLen, newLen);

    return true;
}

void ActivatePostSwap(const char* uuid) {
    strncpy(g_swapUUID, uuid, sizeof(g_swapUUID) - 1);
    g_swapUUID[sizeof(g_swapUUID) - 1] = 0;
    g_swapActive.store(true);
    httpLog("[SWAP] Activated — next POST will use missionId=%s", g_swapUUID);
}

void DeactivatePostSwap() {
    g_swapActive.store(false);
}

static void apply_injected_post(CURL* h, HInfo* hi) {
    if (!hi->postInjected) return;
    o_setopt(h, (CURLoption)OPT_POSTFIELDSIZE, (void*)(intptr_t)hi->modPostLen);
    o_setopt(h, (CURLoption)OPT_POSTFIELDS, (void*)hi->modPost);
    sc_dbg("[HTTP] INJECT: forwarded modified POST body (%d bytes)", hi->modPostLen);
}

#ifndef _HDE64_H_
#define _HDE64_H_

typedef struct {
    uint8_t  len;
    uint8_t  p_rep;
    uint8_t  p_lock;
    uint8_t  p_seg;
    uint8_t  p_66;
    uint8_t  p_67;
    uint8_t  rex;
    uint8_t  rex_w;
    uint8_t  opcode;
    uint8_t  opcode2;
    uint8_t  modrm;
    uint8_t  modrm_mod;
    uint8_t  modrm_reg;
    uint8_t  modrm_rm;
    uint8_t  sib;
    uint8_t  flags;
    int32_t  disp32;
    uint64_t imm64;
} hde64s;

#define F_MODRM     0x01
#define F_SIB       0x02
#define F_IMM8      0x04
#define F_IMM16     0x08
#define F_IMM32     0x10
#define F_IMM64     0x20
#define F_DISP8     0x40
#define F_DISP32    0x80
#define F_RELATIVE  0x100

static unsigned hde64_disasm(const void *code, hde64s *hs) {
    memset(hs, 0, sizeof(*hs));
    const uint8_t *p = (const uint8_t *)code;
    const uint8_t *p0 = p;

    bool has_rex = false;
    for (;;) {
        uint8_t c = *p;
        if (c == 0xF0) { hs->p_lock = c; p++; continue; }
        if (c == 0xF2 || c == 0xF3) { hs->p_rep = c; p++; continue; }
        if (c == 0x2E || c == 0x36 || c == 0x3E || c == 0x26 ||
            c == 0x64 || c == 0x65) { hs->p_seg = c; p++; continue; }
        if (c == 0x66) { hs->p_66 = c; p++; continue; }
        if (c == 0x67) { hs->p_67 = c; p++; continue; }
        if ((c & 0xF0) == 0x40) { hs->rex = c; hs->rex_w = (c >> 3) & 1; has_rex = true; p++; continue; }
        break;
    }

    hs->opcode = *p++;

    if (hs->opcode == 0x0F) {
        hs->opcode2 = *p++;
        if (hs->opcode2 == 0x38) { p++; goto parse_modrm; }
        if (hs->opcode2 == 0x3A) { p++; goto parse_modrm_imm8; }

        uint8_t op2 = hs->opcode2;
        bool has_modrm2 = true;
        if ((op2 >= 0x80 && op2 <= 0x8F) ||
            (op2 >= 0x90 && op2 <= 0x9F) ||
            op2 == 0x05 || op2 == 0x06 || op2 == 0x07 || op2 == 0x08 ||
            op2 == 0x09 || op2 == 0x0B || op2 == 0x0E ||
            op2 == 0xA0 || op2 == 0xA1 || op2 == 0xA2 || op2 == 0xA8 || op2 == 0xA9 ||
            op2 == 0x77 || op2 == 0xC8 || op2 == 0xC9 || op2 == 0xCA || op2 == 0xCB) {
            has_modrm2 = false;
        }
        if (op2 >= 0x80 && op2 <= 0x8F) {
            hs->flags |= F_IMM32;
            hs->disp32 = *(int32_t*)p; p += 4;
            hs->len = (unsigned)(p - p0);
            return hs->len;
        }
        if (has_modrm2) goto parse_modrm;
        hs->len = (unsigned)(p - p0);
        return hs->len;
    }

    {
        uint8_t op = hs->opcode;

        if ((op >= 0x50 && op <= 0x5F) ||
            op == 0x90 || op == 0xC3 || op == 0xCB ||
            op == 0xCC || op == 0xC9 ||
            op == 0xF5 || op == 0xF8 || op == 0xF9 || op == 0xFC || op == 0xFD ||
            op == 0x98 || op == 0x99 || op == 0x9E || op == 0x9F) {
            hs->len = (unsigned)(p - p0);
            return hs->len;
        }

        if (op == 0x04 || op == 0x0C || op == 0x14 || op == 0x1C ||
            op == 0x24 || op == 0x2C || op == 0x34 || op == 0x3C ||
            op == 0x6A || op == 0xA8 || op == 0xB0 || op == 0xB1 ||
            op == 0xB2 || op == 0xB3 || op == 0xB4 || op == 0xB5 ||
            op == 0xB6 || op == 0xB7 || op == 0xCD || op == 0xEB ||
            op == 0x70 || op == 0x71 || op == 0x72 || op == 0x73 ||
            op == 0x74 || op == 0x75 || op == 0x76 || op == 0x77 ||
            op == 0x78 || op == 0x79 || op == 0x7A || op == 0x7B ||
            op == 0x7C || op == 0x7D || op == 0x7E || op == 0x7F ||
            op == 0xE0 || op == 0xE1 || op == 0xE2 || op == 0xE3) {
            p += 1;
            hs->len = (unsigned)(p - p0);
            return hs->len;
        }

        if (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D ||
            op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D ||
            op == 0x68 || op == 0xA9 || op == 0xE8 || op == 0xE9) {
            p += (hs->p_66 ? 2 : 4);
            hs->len = (unsigned)(p - p0);
            return hs->len;
        }

        if (op >= 0xB8 && op <= 0xBF) {
            p += (hs->rex_w ? 8 : (hs->p_66 ? 2 : 4));
            hs->len = (unsigned)(p - p0);
            return hs->len;
        }

        if ((op <= 0x3F && (op & 7) <= 5 && (op & 7) >= 0) ||
            (op >= 0x80 && op <= 0x8F) ||
            (op >= 0xC0 && op <= 0xC1) ||
            (op >= 0xC4 && op <= 0xC7) ||
            (op >= 0xD0 && op <= 0xD3) ||
            op == 0x62 || op == 0x63 || op == 0x69 || op == 0x6B ||
            op == 0xF6 || op == 0xF7 || op == 0xFE || op == 0xFF) {
            bool has_imm8  = (op == 0x80 || op == 0x82 || op == 0x83 || op == 0x6B ||
                              op == 0xC0 || op == 0xC1 || op == 0xC6);
            bool has_imm32 = (op == 0x81 || op == 0x69 || op == 0xC7);
            goto parse_modrm_with_imm;

        parse_modrm_with_imm:
            {
                uint8_t modrm = *p++;
                hs->modrm = modrm;
                hs->modrm_mod = modrm >> 6;
                hs->modrm_reg = (modrm >> 3) & 7;
                hs->modrm_rm  = modrm & 7;

                if ((op == 0xF6) && hs->modrm_reg == 0) has_imm8 = true;
                if ((op == 0xF7) && hs->modrm_reg == 0) has_imm32 = true;

                uint8_t mod = hs->modrm_mod;
                uint8_t rm  = hs->modrm_rm;

                bool need_sib = (mod != 3 && rm == 4);
                if (need_sib) { hs->sib = *p++; }

                if (mod == 0 && rm == 5) p += 4;
                else if (mod == 0 && need_sib && (hs->sib & 7) == 5) p += 4;
                else if (mod == 1) p += 1;
                else if (mod == 2) p += 4;

                if (has_imm8)  p += 1;
                if (has_imm32) p += (hs->p_66 ? 2 : 4);
            }
            hs->len = (unsigned)(p - p0);
            return hs->len;
        }

        if (op >= 0xA0 && op <= 0xA3) {
            p += (hs->p_67 ? 4 : 8);
            hs->len = (unsigned)(p - p0);
            return hs->len;
        }

        if (op == 0x8D || op == 0x8F || op == 0xD8 || op == 0xD9 ||
            op == 0xDA || op == 0xDB || op == 0xDC || op == 0xDD ||
            op == 0xDE || op == 0xDF) {
            goto parse_modrm;
        }
    }

    goto parse_modrm;

parse_modrm:
    {
        uint8_t modrm = *p++;
        hs->modrm = modrm;
        hs->modrm_mod = modrm >> 6;
        hs->modrm_reg = (modrm >> 3) & 7;
        hs->modrm_rm  = modrm & 7;

        uint8_t mod = hs->modrm_mod;
        uint8_t rm  = hs->modrm_rm;
        bool need_sib = (mod != 3 && rm == 4);
        if (need_sib) { hs->sib = *p++; }

        if (mod == 0 && rm == 5) p += 4;
        else if (mod == 0 && need_sib && (hs->sib & 7) == 5) p += 4;
        else if (mod == 1) p += 1;
        else if (mod == 2) p += 4;
    }
    hs->len = (unsigned)(p - p0);
    return hs->len;

parse_modrm_imm8:
    {
        uint8_t modrm = *p++;
        uint8_t mod = modrm >> 6;
        uint8_t rm  = modrm & 7;
        bool need_sib = (mod != 3 && rm == 4);
        if (need_sib) p++;
        if (mod == 0 && rm == 5) p += 4;
        else if (mod == 0 && need_sib && (*(p-1) & 7) == 5) p += 4;
        else if (mod == 1) p += 1;
        else if (mod == 2) p += 4;
        p += 1;
    }
    hs->len = (unsigned)(p - p0);
    return hs->len;
}
#endif

static uint8_t* g_tramp_pool = nullptr;
static int      g_tramp_used = 0;
#define TRAMP_POOL_SIZE  4096
#define TRAMP_SLOT_SIZE  64

static uint8_t* alloc_trampoline() {
    if (!g_tramp_pool) {
        g_tramp_pool = (uint8_t*)VirtualAlloc(nullptr, TRAMP_POOL_SIZE,
                                               MEM_COMMIT | MEM_RESERVE,
                                               PAGE_EXECUTE_READWRITE);
        if (!g_tramp_pool) return nullptr;
    }
    if (g_tramp_used >= TRAMP_POOL_SIZE / TRAMP_SLOT_SIZE) return nullptr;
    uint8_t* slot = g_tramp_pool + g_tramp_used * TRAMP_SLOT_SIZE;
    g_tramp_used++;
    return slot;
}

static void* hook_inline(void* target, void* hook_fn) {
    uint8_t* fn = (uint8_t*)target;

    int stolen = 0;
    int nInsn  = 0;
    bool has_rip_rel = false;
    while (stolen < 14 && nInsn < 20) {
        hde64s hs;
        unsigned l = hde64_disasm(fn + stolen, &hs);
        if (l == 0) { sc_dbg("[HOOK] hde64 fail at +%d", stolen); return nullptr; }

        if (hs.modrm_mod != 3 && hs.modrm_rm == 5 && hs.modrm_mod == 0) {
            has_rip_rel = true;
        }

        stolen += l;
        nInsn++;
    }

    sc_dbg("[HOOK] %p: stealing %d bytes (%d insns) ripRel=%d", target, stolen, nInsn, has_rip_rel);

    if (has_rip_rel) {
        sc_dbg("[HOOK] WARNING: RIP-relative instruction in stolen region — trampoline may crash");
    }

    uint8_t* tramp = alloc_trampoline();
    if (!tramp) { sc_dbg("[HOOK] tramp alloc fail"); return nullptr; }

    memcpy(tramp, fn, stolen);

    int off = stolen;
    tramp[off++] = 0x48; tramp[off++] = 0xB8;
    *(uint64_t*)(tramp + off) = (uint64_t)(fn + stolen);
    off += 8;
    tramp[off++] = 0xFF; tramp[off++] = 0xE0;

    DWORD oldProt;
    VirtualProtect(fn, stolen, PAGE_EXECUTE_READWRITE, &oldProt);

    fn[0] = 0x48; fn[1] = 0xB8;
    *(uint64_t*)(fn + 2) = (uint64_t)hook_fn;
    fn[10] = 0xFF; fn[11] = 0xE0;
    for (int i = 12; i < stolen; i++) fn[i] = 0x90;

    VirtualProtect(fn, stolen, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), fn, stolen);

    return tramp;
}

static size_t __cdecl activity_header_cb(char* buf, size_t size, size_t nmemb, void* userdata)
{
    size_t total = size * nmemb;
    char line[1024];
    int len = ((int)total < (int)sizeof(line)-1) ? (int)total : (int)(sizeof(line)-1);
    memcpy(line, buf, len);
    line[len] = 0;

    while (len > 0 && (line[len-1] == '\r' || line[len-1] == '\n')) line[--len] = 0;
    if (len > 0) {
        sc_dbg("[HTTP] Activity HDR: %s", line);
    }
    return total;
}

std::atomic<bool> g_scCallInFlight{false};

static std::atomic<int> s_actTotal{0};
static std::atomic<int> s_actRewarded{0};
static std::atomic<int> s_actNoReward{0};
static std::atomic<int> s_scCallResult{0};
static std::atomic<int> s_actSCEarned{0};
static std::atomic<int> s_actBonus{0};

static int parse_reward_amount(const char* body, int len) {
    int total = 0;
    const char* p = body;
    while (p && (p - body) < len) {
        const char* hit = strstr(p, "\"amount\"");
        if (!hit || (hit - body) >= len) break;
        const char* q = hit + 8;
        while (q < body + len && (*q == ':' || *q == ' ' || *q == '\t')) q++;

        int val = 0;
        while (q < body + len && *q >= '0' && *q <= '9') {
            val = val * 10 + (*q - '0');
            q++;
        }
        total += val;
        p = q;
    }
    return total;
}

static size_t __cdecl intercept_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    CURL*       h     = (CURL*)userdata;
    size_t      total = size * nmemb;
    write_fn_t  rfn   = nullptr;
    void*       rd    = nullptr;
    bool        first = false;
    bool        is_act = false;

    EnterCriticalSection(&g_cs);
    HInfo* hi = find_slot((uintptr_t)h, false);
    if (hi) {
        rfn = hi->real_wfn;
        rd  = hi->real_wdata;
        is_act = hi->act;

        int space = (int)sizeof(hi->body) - 1 - hi->blen;
        if (space > 0) {
            int cp = ((int)total < space) ? (int)total : space;
            memcpy(hi->body + hi->blen, ptr, cp);
            hi->blen += cp;
            hi->body[hi->blen] = 0;
        }
        first = !hi->status_logged;
        hi->status_logged = true;
    }
    LeaveCriticalSection(&g_cs);

    if (first) {
        bool is_recon = false;
        char reconUrl[512] = {0};
        EnterCriticalSection(&g_cs);
        HInfo* hiR = find_slot((uintptr_t)h, false);
        if (hiR && hiR->recon) {
            is_recon = true;
            strncpy(reconUrl, hiR->url, sizeof(reconUrl)-1);
        }
        LeaveCriticalSection(&g_cs);
        if (is_recon) {
            long rcode = 0;
            if (d_getinfo) d_getinfo(h, (CURLINFO)INFO_RESPONSE_CODE, &rcode);
            char rsnip[2048];
            int rslen = ((int)total < (int)sizeof(rsnip)-1) ? (int)total : (int)(sizeof(rsnip)-1);
            memcpy(rsnip, ptr, rslen);
            rsnip[rslen] = 0;
            httpLog("[RECON-BODY] %ld %s → %s", rcode, reconUrl, rsnip);

            if (g_missionEndCb && strstr(reconUrl, "Mission/end")) {
                g_missionEndCb((int)rcode, rsnip);
            }
        }
    }

    if (first && is_act) {
        long code = 0;
        if (d_getinfo) d_getinfo(h, (CURLINFO)INFO_RESPONSE_CODE, &code);

        s_actTotal.fetch_add(1);
        if (code != 200) {
            s_actNoReward.fetch_add(1);
            s_scCallResult.store(2);
        } else {
            int amt = parse_reward_amount(ptr, (int)total);
            if (amt > 0) {
                s_actRewarded.fetch_add(1);
                s_actSCEarned.fetch_add(amt);
                if (amt > 10) s_actBonus.fetch_add(1);
                s_scCallResult.store(1);
            } else {
                s_actNoReward.fetch_add(1);
                s_scCallResult.store(2);
            }
        }

        sc_dbg("[HTTP] >>> Activity WRITE CB first_chunk: status=%ld size=%zu fwd=%s",
               code, total, rfn ? "yes" : "NO(game_wfn_unknown)");

        char snippet[2048];
        int slen = ((int)total < (int)sizeof(snippet)-1) ? (int)total : (int)(sizeof(snippet)-1);
        memcpy(snippet, ptr, slen);
        snippet[slen] = 0;
        sc_dbg("[HTTP] <<< BODY: %s", snippet);

        httpLog("[HTTP-RESP] Activity response: code=%ld hasGolden=%d", code, (int)g_hasGolden);
        {
            EnterCriticalSection(&g_cs);
            HInfo* hi2 = find_slot((uintptr_t)h, false);
            if (hi2 && hi2->rawPostLen > 0) {

                char reqMid[128] = {0};
                if (extract_missionid(hi2->rawPost, reqMid, sizeof(reqMid))) {
                    httpLog("[HTTP-RESP] POST missionId=%s", reqMid);
                } else {
                    httpLog("[HTTP-RESP] POST missionId=<not found>");
                }

                if (code == 200 && !g_hasGolden) {
                    httpLog("[HTTP-RESP] Golden capture: hi2=%p rawPostLen=%d",
                            (void*)hi2, hi2 ? hi2->rawPostLen : -1);
                    try_capture_golden(hi2->rawPost);
                }
            }
            LeaveCriticalSection(&g_cs);
        }
    }

    if (rfn) return rfn(ptr, size, nmemb, rd);

    return total;
}

static void install_response_capture(CURL* h, HInfo* hi) {
    if (hi->capture_installed) return;

    sc_dbg("[HTTP] CAPTURE: installing on h=%p (known_wfn=%p known_wdata=%p)",
           h, (void*)hi->real_wfn, hi->real_wdata);

    o_setopt(h, (CURLoption)OPT_WRITEFUNCTION, (void*)(uintptr_t)intercept_write_cb);
    o_setopt(h, (CURLoption)OPT_WRITEDATA, (void*)h);

    o_setopt(h, (CURLoption)OPT_HEADERFUNCTION, (void*)(uintptr_t)activity_header_cb);
    o_setopt(h, (CURLoption)OPT_HEADERDATA, (void*)h);

    hi->capture_installed = true;
}

static CURLcode hk_setopt(CURL* h, CURLoption opt, void* arg)
{
    EnterCriticalSection(&g_cs);
    HInfo* hi = find_slot((uintptr_t)h, true);

    if (!hi) {
        LeaveCriticalSection(&g_cs);
        return o_setopt(h, opt, arg);
    }

    if (opt == OPT_URL && arg) {
        strncpy(hi->url, (const char*)arg, sizeof(hi->url) - 1);
        hi->url[sizeof(hi->url) - 1] = 0;
        hi->mg  = (strstr(hi->url, "MiniGame") != nullptr);
        hi->act = (strstr(hi->url, "Activity") != nullptr && strstr(hi->url, "SetMax") == nullptr);

        hi->recon = (strstr(hi->url, "war") || strstr(hi->url, "War") ||
                     strstr(hi->url, "mission") || strstr(hi->url, "Mission") ||
                     strstr(hi->url, "operation") || strstr(hi->url, "Operation") ||
                     strstr(hi->url, "campaign") || strstr(hi->url, "Campaign") ||
                     strstr(hi->url, "planet") || strstr(hi->url, "Planet") ||
                     strstr(hi->url, "deploy") || strstr(hi->url, "Deploy") ||
                     strstr(hi->url, "dispatch") || strstr(hi->url, "Dispatch") ||
                     strstr(hi->url, "lobby") || strstr(hi->url, "Lobby") ||
                     strstr(hi->url, "join") || strstr(hi->url, "Join") ||
                     strstr(hi->url, "session") || strstr(hi->url, "Session") ||
                     strstr(hi->url, "assignment") || strstr(hi->url, "Assignment"));
        hi->blen = 0;
        hi->body[0] = 0;
        hi->status_logged = false;
        hi->capture_installed = false;
        hi->postInjected = false;
        hi->rawPostLen = 0;
        hi->cloneHdrCount = 0;
        hi->hasXSig = false;

        httpLog("[RECON-URL] TID=%lu %s", (unsigned long)GetCurrentThreadId(), hi->url);

        LeaveCriticalSection(&g_cs);
        return o_setopt(h, opt, arg);
    }

    if (opt == OPT_WRITEFUNCTION) {
        sc_dbg("[HTTP] SETOPT WRITEFUNCTION h=%p fn=%p (act=%d mg=%d recon=%d)",
               h, arg, hi->act, hi->mg, hi->recon);
        hi->real_wfn = (write_fn_t)arg;

        if (hi->act || hi->mg || hi->recon) {

            LeaveCriticalSection(&g_cs);
            o_setopt(h, (CURLoption)OPT_WRITEDATA, (void*)h);
            return o_setopt(h, opt, (void*)(uintptr_t)intercept_write_cb);
        }
        LeaveCriticalSection(&g_cs);
        return o_setopt(h, opt, arg);
    }

    if (opt == OPT_WRITEDATA) {
        hi->real_wdata = arg;
        if (hi->act || hi->mg || hi->recon) {

            LeaveCriticalSection(&g_cs);
            return o_setopt(h, opt, (void*)h);
        }
        LeaveCriticalSection(&g_cs);
        return o_setopt(h, opt, arg);
    }

    if (opt == OPT_HEADERFUNCTION) {

        LeaveCriticalSection(&g_cs);
        return o_setopt(h, opt, arg);
    }

    if (opt == OPT_HEADERDATA) {

        LeaveCriticalSection(&g_cs);
        return o_setopt(h, opt, arg);
    }

    if (opt == OPT_HTTPHEADER && arg) {
        curl_slist* sl = (curl_slist*)arg;
        int idx = 0;
        bool hasAuth = false;
        hi->cloneHdrCount = 0;
        hi->hasXSig = false;
        while (sl && sl->data) {

            httpLog("[RECON-HDR] h=%p [%d] %s", h, idx, sl->data);

            if (hi->cloneHdrCount < 16) {
                strncpy(hi->cloneHdrs[hi->cloneHdrCount], sl->data, 1023);
                hi->cloneHdrs[hi->cloneHdrCount][1023] = 0;
                hi->cloneHdrCount++;
            }

            if (_strnicmp(sl->data, "X-Signature:", 12) == 0) {
                hi->hasXSig = true;
            }

            if (_strnicmp(sl->data, "Authorization:", 14) == 0 ||
                _strnicmp(sl->data, "Cookie:", 7) == 0 ||
                _strnicmp(sl->data, "X-Session", 9) == 0 ||
                _strnicmp(sl->data, "X-Auth", 6) == 0 ||
                _strnicmp(sl->data, "X-Token", 7) == 0 ||
                _strnicmp(sl->data, "Content-Type:", 13) == 0 ||
                _strnicmp(sl->data, "Accept:", 7) == 0) {
                if (g_authHeaderCount < MAX_AUTH_HEADERS) {
                    strncpy(g_authHeaders[g_authHeaderCount], sl->data, MAX_HDR_LEN - 1);
                    g_authHeaders[g_authHeaderCount][MAX_HDR_LEN - 1] = 0;
                    g_authHeaderCount++;
                    hasAuth = true;
                }
            }

            sl = sl->next;
            idx++;
        }
        if (hasAuth && !g_authCaptured) {
            g_authCaptured = true;
            httpLog("[RECON-AUTH] ✓ Captured %d auth headers from game request", g_authHeaderCount);
        }

        if (hi->url[0] && !g_authBaseURL[0]) {
            const char* api = strstr(hi->url, "/api/");
            if (api) {
                int baseLen = (int)(api - hi->url);
                if (baseLen > 0 && baseLen < (int)sizeof(g_authBaseURL)) {
                    memcpy(g_authBaseURL, hi->url, baseLen);
                    g_authBaseURL[baseLen] = 0;
                    httpLog("[RECON-AUTH] Base URL: %s", g_authBaseURL);
                }
            }
        }

        LeaveCriticalSection(&g_cs);
        return o_setopt(h, opt, arg);
    }

    if ((opt == OPT_POSTFIELDS || opt == OPT_COPYPOSTFIELDS) && arg) {
        const char* p = (const char*)arg;
        int plen = (int)strlen(p);
        bool tracked = hi->mg || hi->act;

        {
            int dumpLen = plen < 2048 ? plen : 2048;
            char dumpBuf[2050];
            memcpy(dumpBuf, p, dumpLen);
            dumpBuf[dumpLen] = 0;
            httpLog("[RECON-POST] (%d bytes) %s", plen, dumpBuf);
        }

        if (strstr(hi->url, "Mission/end")) {
            if (g_capturedMEBody) { free(g_capturedMEBody); g_capturedMEBody = nullptr; }
            g_capturedMEBody = (char*)malloc(plen + 1);
            if (g_capturedMEBody) {
                memcpy(g_capturedMEBody, p, plen);
                g_capturedMEBody[plen] = 0;
                g_capturedMEBodyLen = plen;
                g_hasCapturedME = true;
            }
            if (g_missionEndCb) {
                char msg[128];
                snprintf(msg, sizeof(msg), "Captured Mission/end POST body: %d bytes", plen);
                g_missionEndCb(0, msg);
            }
        }

        if (tracked) {
            sc_dbg("[HTTP] SETOPT POSTFIELDS h=%p len=%d (%s)", h, plen,
                   hi->act ? "Activity" : "MiniGame");
        }

        {
            int copyLen = (plen < (int)sizeof(hi->rawPost) - 1) ? plen : (int)sizeof(hi->rawPost) - 1;
            memcpy(hi->rawPost, p, copyLen);
            hi->rawPost[copyLen] = 0;
            hi->rawPostLen = copyLen;
        }

        if (hi->act) {
            hi->postInjected = false;

            if (try_inject_missionid(hi)) {
                LeaveCriticalSection(&g_cs);
                apply_injected_post(h, hi);
                return 0;
            }
        }

        LeaveCriticalSection(&g_cs);
        return o_setopt(h, opt, arg);
    }

    if (opt == OPT_POSTFIELDSIZE) {
        if (hi->act && hi->postInjected) {
            LeaveCriticalSection(&g_cs);
            sc_dbg("[HTTP] INJECT: overriding POSTFIELDSIZE %ld → %d",
                   (long)(intptr_t)arg, hi->modPostLen);
            return o_setopt(h, opt, (void*)(intptr_t)hi->modPostLen);
        }
        LeaveCriticalSection(&g_cs);
        return o_setopt(h, opt, arg);
    }

    LeaveCriticalSection(&g_cs);
    return o_setopt(h, opt, arg);
}

static CURLcode hk_perform(CURL* h)
{
    bool tracked = false;
    bool is_act = false;

    EnterCriticalSection(&g_cs);
    HInfo* hi = find_slot((uintptr_t)h, false);
    if (hi && (hi->mg || hi->act || hi->recon)) {
        tracked = true;
        is_act = hi->act;
        hi->blen = 0;
        hi->body[0] = 0;
        hi->status_logged = false;
    }
    LeaveCriticalSection(&g_cs);

    if (tracked) {
        sc_dbg("[HTTP] >>> curl_easy_perform %s h=%p", is_act ? "Activity" : "MiniGame", h);
    }

    CURLcode rc = o_perform(h);

    {
        long code = 0;
        char perfUrl[512] = {0};
        if (d_getinfo) d_getinfo(h, (CURLINFO)INFO_RESPONSE_CODE, &code);
        EnterCriticalSection(&g_cs);
        HInfo* hi2 = find_slot((uintptr_t)h, false);
        if (hi2) strncpy(perfUrl, hi2->url, sizeof(perfUrl)-1);
        LeaveCriticalSection(&g_cs);
        httpLog("[RECON-RESP] %ld %s", code, perfUrl);
    }

    if (tracked) {
        long code = 0;
        if (d_getinfo) d_getinfo(h, (CURLINFO)INFO_RESPONSE_CODE, &code);

        char body[4096] = {};
        EnterCriticalSection(&g_cs);
        hi = find_slot((uintptr_t)h, false);
        if (hi) {
            memcpy(body, hi->body, hi->blen);
            body[hi->blen] = 0;
        }
        LeaveCriticalSection(&g_cs);

        sc_dbg("[HTTP] <<< PERFORM DONE: status=%ld curl_rc=%d", code, (int)rc);
        sc_dbg("[HTTP] <<< BODY(%d bytes): %.1024s", (int)strlen(body), body);
    }

    return rc;
}

static void hk_cleanup(CURL* h)
{

    EnterCriticalSection(&g_cs);
    free_slot((uintptr_t)h);
    LeaveCriticalSection(&g_cs);
    o_cleanup(h);
}

static void log_modules()
{
    sc_dbg("[HTTP] Loaded modules (checking for HTTP libs):");
    const char* names[] = {
        "libcurl.dll", "libcurl-x64.dll", "curl.dll",
        "winhttp.dll", "wininet.dll",
        "game.dll", "game_live.dll",
        nullptr
    };
    for (int i = 0; names[i]; i++) {
        HMODULE m = GetModuleHandleA(names[i]);
        if (m) sc_dbg("[HTTP]   %s → %p", names[i], m);
    }
}

typedef long (__stdcall *pfn_BCryptHashData)(void* hHash, uint8_t* pbInput, unsigned long cbInput, unsigned long dwFlags);
static pfn_BCryptHashData o_BCryptHashData = nullptr;

static uint8_t  g_sigNonce[8]   = {0};
static uint8_t  g_sigKey512[512] = {0};
static bool     g_sigKeyCaptured = false;
static int      g_sigCaptureCount = 0;

static void*    g_trackingHandle = nullptr;
static int      g_chunkIndex     = 0;
static uint8_t  g_pendingNonce[8] = {0};
static CRITICAL_SECTION g_sigLock;
static bool     g_sigLockInit = false;

static long __stdcall hk_BCryptHashData(void* hHash, uint8_t* pbInput, unsigned long cbInput, unsigned long dwFlags)
{
    if (!g_sigLockInit) { InitializeCriticalSection(&g_sigLock); g_sigLockInit = true; }

    if (pbInput && cbInput > 0) {
        EnterCriticalSection(&g_sigLock);

        if (cbInput >= (4 + 8 + 1 + 512) && memcmp(pbInput, "f2s7", 4) == 0) {
            unsigned long bodyXorLen = cbInput - 4 - 8 - 512;
            memcpy(g_sigNonce, pbInput + 4, 8);
            memcpy(g_sigKey512, pbInput + cbInput - 512, 512);
            g_sigKeyCaptured = true;
            g_sigCaptureCount++;
            g_trackingHandle = nullptr;

            char nonceHex[24];
            for (int i = 0; i < 8; i++) sprintf(nonceHex + i*2, "%02X", g_sigNonce[i]);
            nonceHex[16] = 0;
            httpLog("[SIG-CAPTURE] SINGLE #%d bufLen=%lu bodyXorLen=%lu nonce=%s",
                    g_sigCaptureCount, cbInput, bodyXorLen, nonceHex);

            LeaveCriticalSection(&g_sigLock);
            return o_BCryptHashData(hHash, pbInput, cbInput, dwFlags);
        }

        if (cbInput == 4 && memcmp(pbInput, "f2s7", 4) == 0) {
            g_trackingHandle = hHash;
            g_chunkIndex = 1;
            httpLog("[SIG-CHUNK] Tracking handle %p — got f2s7", hHash);
            LeaveCriticalSection(&g_sigLock);
            return o_BCryptHashData(hHash, pbInput, cbInput, dwFlags);
        }

        if (cbInput >= 4 && cbInput < (4 + 8 + 512) && memcmp(pbInput, "f2s7", 4) == 0) {
            g_trackingHandle = hHash;
            if (cbInput >= 12) {

                memcpy(g_pendingNonce, pbInput + 4, 8);
                g_chunkIndex = 3;
                httpLog("[SIG-CHUNK] Tracking handle %p — got f2s7+nonce (%lu bytes)", hHash, cbInput);
            } else {
                g_chunkIndex = 1;
                httpLog("[SIG-CHUNK] Tracking handle %p — got f2s7+partial (%lu bytes)", hHash, cbInput);
            }
            LeaveCriticalSection(&g_sigLock);
            return o_BCryptHashData(hHash, pbInput, cbInput, dwFlags);
        }

        if (hHash == g_trackingHandle && g_trackingHandle != nullptr) {
            if (g_chunkIndex == 1 && cbInput >= 8) {

                memcpy(g_pendingNonce, pbInput, 8);
                g_chunkIndex = 3;
                httpLog("[SIG-CHUNK] handle %p — nonce captured (%lu bytes)", hHash, cbInput);
            }
            else if (g_chunkIndex >= 3 && cbInput == 512) {

                memcpy(g_sigNonce, g_pendingNonce, 8);
                memcpy(g_sigKey512, pbInput, 512);
                g_sigKeyCaptured = true;
                g_sigCaptureCount++;
                g_trackingHandle = nullptr;

                char nonceHex[24];
                for (int i = 0; i < 8; i++) sprintf(nonceHex + i*2, "%02X", g_sigNonce[i]);
                nonceHex[16] = 0;
                char keyHex[68];
                for (int i = 0; i < 32; i++) sprintf(keyHex + i*2, "%02X", g_sigKey512[i]);
                keyHex[64] = 0;
                httpLog("[SIG-CAPTURE] CHUNKED #%d nonce=%s key32=%s...",
                        g_sigCaptureCount, nonceHex, keyHex);
            }
            else if (g_chunkIndex >= 3) {

                g_chunkIndex++;
                httpLog("[SIG-CHUNK] handle %p — body chunk %lu bytes (waiting for key)", hHash, cbInput);
            }
            else {

                httpLog("[SIG-CHUNK] handle %p — unexpected chunk idx=%d size=%lu", hHash, g_chunkIndex, cbInput);
                g_chunkIndex++;
            }
        }

        static int g_bcryptLogCount = 0;
        if (g_bcryptLogCount < 20) {
            char preview[32];
            int previewLen = (cbInput < 12) ? (int)cbInput : 12;
            for (int i = 0; i < previewLen; i++) sprintf(preview + i*2, "%02X", pbInput[i]);
            preview[previewLen*2] = 0;
            httpLog("[BCRYPT-RAW] #%d hHash=%p cbInput=%lu preview=%s",
                    g_bcryptLogCount, hHash, cbInput, preview);
            g_bcryptLogCount++;
        }

        LeaveCriticalSection(&g_sigLock);
    }

    return o_BCryptHashData(hHash, pbInput, cbInput, dwFlags);
}

struct CloneResp {
    char body[4096];
    int  len;
};

static size_t __cdecl clone_write_cb(char* ptr, size_t sz, size_t nm, void* ud) {
    CloneResp* r = (CloneResp*)ud;
    size_t total = sz * nm;
    int space = (int)sizeof(r->body) - 1 - r->len;
    if (space > 0) {
        int cp = ((int)total < space) ? (int)total : space;
        memcpy(r->body + r->len, ptr, cp);
        r->len += cp;
        r->body[r->len] = 0;
    }
    return total;
}

static DWORD WINAPI clone_worker(LPVOID) {
    httpLog("[CLONE] === Starting clone test ===");

    if (!p_easy_init || !o_setopt || !o_perform || !p_slist_append) {
        httpLog("[CLONE] Missing curl functions (init=%p setopt=%p perform=%p slist=%p)",
                (void*)p_easy_init, (void*)o_setopt, (void*)o_perform, (void*)p_slist_append);
        return 0;
    }

    CURL* h = p_easy_init();
    if (!h) { httpLog("[CLONE] curl_easy_init FAILED"); return 0; }

    o_setopt(h, (CURLoption)OPT_URL, (void*)g_cloneData.url);

    curl_slist* hdrs = nullptr;
    for (int i = 0; i < g_cloneData.hdrCount; i++) {

        if (_strnicmp(g_cloneData.hdrs[i], "Content-Length:", 14) == 0) continue;
        curl_slist* tmp = p_slist_append(hdrs, g_cloneData.hdrs[i]);
        if (tmp) hdrs = tmp;
    }
    o_setopt(h, (CURLoption)OPT_HTTPHEADER, (void*)hdrs);

    o_setopt(h, (CURLoption)OPT_COPYPOSTFIELDS, (void*)g_cloneData.body);

    o_setopt(h, (CURLoption)OPT_SSL_VERIFYPEER, (void*)0);
    o_setopt(h, (CURLoption)OPT_SSL_VERIFYHOST, (void*)0);

    CloneResp resp = {};
    o_setopt(h, (CURLoption)OPT_WRITEFUNCTION, (void*)(uintptr_t)clone_write_cb);
    o_setopt(h, (CURLoption)OPT_WRITEDATA, (void*)&resp);

    httpLog("[CLONE] Sending: url=%s body=%d bytes hdrs=%d",
            g_cloneData.url, g_cloneData.bodyLen, g_cloneData.hdrCount);

    for (int i = 0; i < g_cloneData.hdrCount; i++) {
        if (_strnicmp(g_cloneData.hdrs[i], "Content-Length:", 14) != 0)
            httpLog("[CLONE-HDR] %s", g_cloneData.hdrs[i]);
    }

    CURLcode res = o_perform(h);

    long code = 0;
    if (d_getinfo) d_getinfo(h, (CURLINFO)INFO_RESPONSE_CODE, &code);

    httpLog("[CLONE] RESULT: curl=%d http=%ld", (int)res, code);
    if (resp.len > 0) {

        char snippet[1024];
        int slen = (resp.len < (int)sizeof(snippet)-1) ? resp.len : (int)(sizeof(snippet)-1);
        memcpy(snippet, resp.body, slen);
        snippet[slen] = 0;
        httpLog("[CLONE-BODY] %s", snippet);
    }

    if (code == 200)
        httpLog("[CLONE] *** SUCCESS — X-Signature replay WORKS! ***");
    else
        httpLog("[CLONE] Replay returned %ld — may need ct update or different approach", code);

    if (p_slist_free) p_slist_free(hdrs);
    o_cleanup(h);

    return 0;
}

namespace HttpMonitor {

static bool mem_readable(void* addr, size_t len) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(addr, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return true;
}

void Install(uintptr_t gameBase) {
    httpLog("[HTTP] Install called — gameBase=0x%llX", (unsigned long long)gameBase);

    struct { uint32_t rva; const char* label; } retAddrs[] = {
        {0x43FD8E,  "frame9_outer"},
        {0x9CDECB,  "frame8"},
        {0x101C913, "frame7"},
        {0xEE26B5,  "frame6"},
        {0xEE49A1,  "frame5"},
        {0xEE58C3,  "frame4_lobby"},
        {0xEE58FB,  "frame4_oper"},
    };

    for (int i = 0; i < 7; i++) {
        uint8_t* retAddr = (uint8_t*)(gameBase + retAddrs[i].rva);
        if (!mem_readable(retAddr - 16, 32)) {
            httpLog("[CALL-SITE] %s RVA=0x%X NOT READABLE", retAddrs[i].label, retAddrs[i].rva);
            continue;
        }

        uint8_t* pre = retAddr - 16;
        httpLog("[CALL-SITE] %s retRVA=0x%X bytes[-16..-1]: "
                "%02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                retAddrs[i].label, retAddrs[i].rva,
                pre[0],pre[1],pre[2],pre[3],pre[4],pre[5],pre[6],pre[7],
                pre[8],pre[9],pre[10],pre[11],pre[12],pre[13],pre[14],pre[15]);

        if (retAddr[-5] == 0xE8) {
            int32_t rel = *(int32_t*)(retAddr - 4);
            uintptr_t target = (uintptr_t)retAddr + rel;
            uint32_t targetRVA = (uint32_t)(target - gameBase);
            httpLog("[CALL-SITE] %s → DIRECT CALL E8 rel32 → targetRVA=0x%X",
                    retAddrs[i].label, targetRVA);
        }

        else if (retAddr[-2] == 0xFF && (retAddr[-1] >= 0xD0 && retAddr[-1] <= 0xD7)) {
            httpLog("[CALL-SITE] %s → INDIRECT CALL via reg (FF %02X)",
                    retAddrs[i].label, retAddr[-1]);
        }

        else if (retAddr[-3] == 0x41 && retAddr[-2] == 0xFF &&
                 (retAddr[-1] >= 0xD0 && retAddr[-1] <= 0xD7)) {
            httpLog("[CALL-SITE] %s → INDIRECT CALL via r%d (41 FF %02X)",
                    retAddrs[i].label, (retAddr[-1] & 0x07) + 8, retAddr[-1]);
        }

        else if (retAddr[-6] == 0xFF && retAddr[-5] == 0x15) {
            int32_t rel = *(int32_t*)(retAddr - 4);
            uintptr_t iatEntry = (uintptr_t)retAddr + rel;
            httpLog("[CALL-SITE] %s → CALL [rip+rel32] IAT=0x%llX",
                    retAddrs[i].label, (unsigned long long)iatEntry);
        }
        else {
            httpLog("[CALL-SITE] %s → UNKNOWN pattern (last 8 bytes: %02X %02X %02X %02X %02X %02X %02X %02X)",
                    retAddrs[i].label,
                    retAddr[-8],retAddr[-7],retAddr[-6],retAddr[-5],
                    retAddr[-4],retAddr[-3],retAddr[-2],retAddr[-1]);
        }

        DWORD64 imgBase = 0;
        RUNTIME_FUNCTION* rtf = RtlLookupFunctionEntry((DWORD64)retAddr, &imgBase, NULL);
        if (rtf) {
            httpLog("[CALL-SITE] %s → containing func: RVA=0x%X..0x%X (entry=0x%X)",
                    retAddrs[i].label, rtf->BeginAddress, rtf->EndAddress, rtf->BeginAddress);
        } else {
            httpLog("[CALL-SITE] %s → RtlLookupFunctionEntry returned NULL (no unwind info)",
                    retAddrs[i].label);
        }
    }

    httpLog("[SC] Dispatch hook disabled — using clone-based replay approach");
}
void Uninstall()                 {  }
void* GetRetStubAddr()           { return nullptr; }
void* GetFakeVtableAddr()        { return nullptr; }
void* GetFakeEntityAddr()        { return nullptr; }
void* GetFakeFixupAddr()         { return nullptr; }

void InstallWinHttpHooks()
{
    if (g_installed) return;

    InitializeCriticalSection(&g_cs);
    memset(g_slots, 0, sizeof(g_slots));

    httpLog("[HTTP] === Installing libcurl hooks ===");
    log_modules();

    HMODULE hCurl = GetModuleHandleA("libcurl.dll");
    if (!hCurl) hCurl = GetModuleHandleA("libcurl-x64.dll");
    if (!hCurl) hCurl = GetModuleHandleA("curl.dll");
    if (!hCurl) {
        httpLog("[HTTP] ERROR: libcurl.dll not found! Cannot hook.");
        return;
    }
    httpLog("[HTTP] Found libcurl at %p", hCurl);

    void* p_setopt  = (void*)GetProcAddress(hCurl, "curl_easy_setopt");
    void* p_perform = (void*)GetProcAddress(hCurl, "curl_easy_perform");
    void* p_getinfo = (void*)GetProcAddress(hCurl, "curl_easy_getinfo");
    void* p_cleanup = (void*)GetProcAddress(hCurl, "curl_easy_cleanup");

    httpLog("[HTTP] Resolved: setopt=%p perform=%p getinfo=%p cleanup=%p",
           p_setopt, p_perform, p_getinfo, p_cleanup);

    if (!p_setopt || !p_perform) {
        httpLog("[HTTP] ERROR: critical exports not found!");
        return;
    }

    d_getinfo = (pfn_getinfo)p_getinfo;

    p_easy_init = (pfn_easy_init)GetProcAddress(hCurl, "curl_easy_init");
    p_slist_append = (pfn_slist_append)GetProcAddress(hCurl, "curl_slist_append");
    p_slist_free = (pfn_slist_free)GetProcAddress(hCurl, "curl_slist_free_all");
    httpLog("[HTTP] Clone curl: init=%p slist_append=%p slist_free=%p",
            (void*)p_easy_init, (void*)p_slist_append, (void*)p_slist_free);

    if (p_setopt) {
        uint8_t* b = (uint8_t*)p_setopt;
        httpLog("[HTTP] setopt  bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
               b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
    }
    if (p_perform) {
        uint8_t* b = (uint8_t*)p_perform;
        httpLog("[HTTP] perform bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
               b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
    }

    o_setopt = (pfn_setopt)hook_inline(p_setopt, (void*)hk_setopt);
    if (o_setopt) httpLog("[HTTP] curl_easy_setopt hooked OK");
    else          httpLog("[HTTP] curl_easy_setopt hook FAILED");

    o_perform = (pfn_perform)hook_inline(p_perform, (void*)hk_perform);
    if (o_perform) httpLog("[HTTP] curl_easy_perform hooked OK");
    else           httpLog("[HTTP] curl_easy_perform hook FAILED");

    if (p_cleanup) {
        o_cleanup = (pfn_cleanup)hook_inline(p_cleanup, (void*)hk_cleanup);
        if (o_cleanup) httpLog("[HTTP] curl_easy_cleanup hooked OK");
        else           httpLog("[HTTP] curl_easy_cleanup hook FAILED");
    }

    int hooked = (o_setopt ? 1 : 0) + (o_perform ? 1 : 0) + (o_cleanup ? 1 : 0);
    httpLog("[HTTP] === Done: %d/3 curl hooks active ===", hooked);

    {
        HMODULE hBcrypt = GetModuleHandleA("bcrypt.dll");
        if (!hBcrypt) hBcrypt = LoadLibraryA("bcrypt.dll");
        if (hBcrypt) {
            void* p_hashData = (void*)GetProcAddress(hBcrypt, "BCryptHashData");
            if (p_hashData) {
                o_BCryptHashData = (pfn_BCryptHashData)hook_inline(p_hashData, (void*)hk_BCryptHashData);
                if (o_BCryptHashData) httpLog("[HTTP] BCryptHashData hooked OK");
                else                 httpLog("[HTTP] BCryptHashData hook FAILED");
            } else {
                httpLog("[HTTP] BCryptHashData export not found");
            }
        } else {
            httpLog("[HTTP] bcrypt.dll not found/loaded");
        }
    }

    g_installed = true;

    ScanForActivityFunction();
}

void ScanForActivityFunction()
{

}

}

bool HasGoldenMissionId()  { return g_hasGolden; }
const char* GetGoldenMissionId() { return g_hasGolden ? g_goldenMissionId : ""; }

static std::atomic<int> s_retryRecovered{0};
static std::atomic<int> s_retryFailed{0};

int  HttpMonitor_GetActTotal()    { return s_actTotal.load(); }
int  HttpMonitor_GetActRewarded() { return s_actRewarded.load(); }
int  HttpMonitor_GetActNoReward() { return s_actNoReward.load(); }
int  HttpMonitor_GetActSCEarned() { return s_actSCEarned.load(); }
int  HttpMonitor_GetActBonus()    { return s_actBonus.load(); }
void HttpMonitor_ResetCounters()  {
    s_actTotal.store(0); s_actRewarded.store(0); s_actNoReward.store(0); s_actSCEarned.store(0); s_actBonus.store(0);
    s_retryRecovered.store(0); s_retryFailed.store(0);
}

void HttpMonitor_ClearCallResult() { s_scCallResult.store(0); }
void HttpMonitor_SetCallResult(int v) { s_scCallResult.store(v); }
int  HttpMonitor_GetCallResult()   { return s_scCallResult.load(); }

void HttpMonitor_AddRetryRecovered() { s_retryRecovered.fetch_add(1); }
void HttpMonitor_AddRetryFailed()    { s_retryFailed.fetch_add(1); }
int  HttpMonitor_GetRetryRecovered() { return s_retryRecovered.load(); }
int  HttpMonitor_GetRetryFailed()    { return s_retryFailed.load(); }
