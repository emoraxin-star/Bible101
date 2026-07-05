#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <strsafe.h>

#pragma comment(lib, "ntdll.lib")

extern NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
extern NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
extern NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);

static HANDLE g_hwbpThread = NULL;
static BOOL   g_hwbpShutdown = FALSE;
static HANDLE g_hwbpLogMutex = NULL;

static void hwbp_log(const char* message)
{
    if (g_hwbpLogMutex) {
        WaitForSingleObject(g_hwbpLogMutex, INFINITE);
    }
    OutputDebugStringA("[HWBP] ");
    OutputDebugStringA(message);
    if (g_hwbpLogMutex) {
        ReleaseMutex(g_hwbpLogMutex);
    }
}

static BOOL hwbp_check_and_clear(HANDLE hThread)
{
    CONTEXT ctx;
    RtlSecureZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    NTSTATUS status = NtGetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        hwbp_log("NtGetContextThread failed");
        return FALSE;
    }

    BOOL detected = FALSE;
    char buf[256];

    if (ctx.Dr0 != 0) {
        StringCbPrintfA(buf, sizeof(buf), "DR0 = 0x%p", (void*)ctx.Dr0);
        hwbp_log(buf);
        ctx.Dr0 = 0;
        detected = TRUE;
    }
    if (ctx.Dr1 != 0) {
        StringCbPrintfA(buf, sizeof(buf), "DR1 = 0x%p", (void*)ctx.Dr1);
        hwbp_log(buf);
        ctx.Dr1 = 0;
        detected = TRUE;
    }
    if (ctx.Dr2 != 0) {
        StringCbPrintfA(buf, sizeof(buf), "DR2 = 0x%p", (void*)ctx.Dr2);
        hwbp_log(buf);
        ctx.Dr2 = 0;
        detected = TRUE;
    }
    if (ctx.Dr3 != 0) {
        StringCbPrintfA(buf, sizeof(buf), "DR3 = 0x%p", (void*)ctx.Dr3);
        hwbp_log(buf);
        ctx.Dr3 = 0;
        detected = TRUE;
    }

    if (ctx.Dr6 & 0x0000000F) {
        StringCbPrintfA(buf, sizeof(buf), "DR6 = 0x%08X (recent BP hit)", ctx.Dr6);
        hwbp_log(buf);
        ctx.Dr6 = 0;
        detected = TRUE;
    }

    if (ctx.Dr7 & 0x000000FF) {
        StringCbPrintfA(buf, sizeof(buf), "DR7 = 0x%08X (BPs enabled)", ctx.Dr7);
        hwbp_log(buf);
        ctx.Dr7 = 0;
        detected = TRUE;
    }

    if (detected) {
        hwbp_log("Hardware breakpoint detected -- clearing all DR registers");
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        status = NtSetContextThread(hThread, &ctx);
        if (!NT_SUCCESS(status)) {
            hwbp_log("NtSetContextThread failed -- registers may not be cleared");
        }
    }

    return detected;
}

static DWORD WINAPI hwbp_monitor_thread(LPVOID param)
{
    (void)param;
    HANDLE hThread = GetCurrentThread();

    while (!g_hwbpShutdown) {
        DWORD jitter = (DWORD)(__rdtsc() % 50001) + 10000;

        LARGE_INTEGER delay;
        delay.QuadPart = -(LONGLONG)jitter * 10000;
        NtDelayExecution(FALSE, &delay);

        if (g_hwbpShutdown) break;

        hwbp_check_and_clear(hThread);
    }

    return 0;
}

__declspec(dllexport) BOOL HWBP_Initialize(void)
{
    g_hwbpShutdown = FALSE;
    g_hwbpLogMutex = CreateMutexA(NULL, FALSE, "Local\\HWBP_LogMutex");
    if (!g_hwbpLogMutex) return FALSE;

    HANDLE hThread = GetCurrentThread();
    hwbp_check_and_clear(hThread);

    g_hwbpThread = CreateThread(NULL, 0, hwbp_monitor_thread, NULL, 0, NULL);
    if (!g_hwbpThread) {
        CloseHandle(g_hwbpLogMutex);
        g_hwbpLogMutex = NULL;
        return FALSE;
    }

    return TRUE;
}

__declspec(dllexport) void HWBP_Shutdown(void)
{
    g_hwbpShutdown = TRUE;
    if (g_hwbpThread) {
        WaitForSingleObject(g_hwbpThread, 5000);
        CloseHandle(g_hwbpThread);
        g_hwbpThread = NULL;
    }
    if (g_hwbpLogMutex) {
        CloseHandle(g_hwbpLogMutex);
        g_hwbpLogMutex = NULL;
    }
}
