
#include "sc_present.h"
#include "sc_debug.h"
#include <windows.h>
#include <atomic>

typedef void (NTAPI *ScApcFn)(ULONG_PTR, ULONG_PTR, ULONG_PTR);

#define WM_SC_DISPATCH  (WM_USER + 0x7EA)
#define WM_GT_DISPATCH  (WM_USER + 0x7EB)

static WNDPROC  s_origWndProc = nullptr;
static HWND     s_gameHwnd    = nullptr;
static ScApcFn  s_scCallback  = nullptr;
static bool     s_installed   = false;
static std::atomic<int> s_scProcessing{0};

static LRESULT CALLBACK ScWndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_SC_DISPATCH && s_scCallback) {

        sc_dbg("WndProc: WM_SC_DISPATCH received, actObj=%p, TID=%u", (void*)wp, GetCurrentThreadId());
        if (s_scProcessing.exchange(1) == 0) {
            sc_dbg("WndProc: calling s_scCallback(%p)...", (void*)wp);
            s_scCallback((ULONG_PTR)wp, 0, 0);
            sc_dbg("WndProc: s_scCallback returned OK");
            s_scProcessing.store(0);
        } else {
            sc_dbg("WndProc: SKIPPED — s_scProcessing was already 1 (re-entrancy)");
        }
        return 0;
    }
    if (msg == WM_GT_DISPATCH) {

        auto fn = (ScApcFn)wp;
        if (fn) fn((ULONG_PTR)lp, 0, 0);
        return 0;
    }
    return CallWindowProcA(s_origWndProc, hw, msg, wp, lp);
}

bool ScPresent::Install() {
    if (s_installed) return true;

    s_gameHwnd = nullptr;
    for (int i = 0; i < 50 && !s_gameHwnd; i++) {
        s_gameHwnd = FindWindowA("Helldivers2", nullptr);
        if (!s_gameHwnd) s_gameHwnd = FindWindowA("helldivers2", nullptr);
        if (!s_gameHwnd) s_gameHwnd = FindWindowA(nullptr, "HELLDIVERS 2");
        if (!s_gameHwnd) {

            struct FindCtx { HWND result; } ctx = { nullptr };
            EnumWindows([](HWND hw, LPARAM lp) -> BOOL {
                auto* c = (FindCtx*)lp;
                char title[256] = {};
                GetWindowTextA(hw, title, sizeof(title));
                if (strstr(title, "HELLDIVERS")) {

                    if (IsWindowVisible(hw) && GetWindowLong(hw, GWL_STYLE) & WS_VISIBLE) {
                        c->result = hw;
                        return FALSE;
                    }
                }
                return TRUE;
            }, (LPARAM)&ctx);
            s_gameHwnd = ctx.result;
        }
        if (!s_gameHwnd) Sleep(500);
    }
    if (!s_gameHwnd) return false;

    s_origWndProc = (WNDPROC)SetWindowLongPtrA(s_gameHwnd, GWLP_WNDPROC, (LONG_PTR)ScWndProc);
    sc_dbg("ScPresent::Install: hwnd=%p origWndProc=%p", s_gameHwnd, s_origWndProc);
    if (!s_origWndProc) { sc_dbg("ScPresent::Install: FAILED — SetWindowLongPtr returned 0"); return false; }

    s_installed = true;
    sc_dbg("ScPresent::Install: SUCCESS");
    return true;
}

void ScPresent::Shutdown() {
    if (s_installed && s_gameHwnd && s_origWndProc) {
        SetWindowLongPtrA(s_gameHwnd, GWLP_WNDPROC, (LONG_PTR)s_origWndProc);
    }
    s_installed = false;
    s_gameHwnd = nullptr;
    s_origWndProc = nullptr;
}

bool ScPresent::IsReady() {
    return s_installed && s_gameHwnd != nullptr;
}

bool ScPresent::QueueCall(void* fn, void* arg) {
    if (!s_installed || !s_gameHwnd) return false;
    return PostMessageA(s_gameHwnd, WM_GT_DISPATCH, (WPARAM)fn, (LPARAM)arg) != 0;
}

bool ScPresent::QueueSC(void* actObj) {
    if (!s_installed || !s_gameHwnd) {
        sc_dbg("QueueSC: FAILED — installed=%d hwnd=%p", s_installed, s_gameHwnd);
        return false;
    }
    BOOL ok = PostMessageA(s_gameHwnd, WM_SC_DISPATCH, (WPARAM)actObj, 0);
    sc_dbg("QueueSC: PostMessage(hwnd=%p, actObj=%p) = %d, LastErr=%u",
           s_gameHwnd, actObj, (int)ok, ok ? 0 : GetLastError());
    return ok != 0;
}

void ScPresent::SetCallback(void* fn) {
    s_scCallback = (ScApcFn)fn;
}
