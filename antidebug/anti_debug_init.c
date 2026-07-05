#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <strsafe.h>

typedef struct _VM_DETECT_RESULT {
    DWORD Flags;
    char  Vendor[64];
    char  Detail[256];
} VM_DETECT_RESULT;

#pragma comment(lib, "ntdll.lib")

extern BOOL  Packer_AntiDebug_Check(void);
extern void  Packer_DestroyAndExit(void*, SIZE_T);
extern BOOL  HWBP_Initialize(void);
extern void  HWBP_Shutdown(void);
extern BOOL  VM_Detect(void*);
extern BOOL  VM_IsVM(void*);
extern BOOL  Integrity_Initialize(void);
extern void  Integrity_Shutdown(void);

static BOOL   g_vmDetected = FALSE;
static HANDLE g_vmThread = NULL;
static BOOL   g_vmShutdown = FALSE;
static HANDLE g_integrityInitDone = NULL;

typedef struct _PACKER_CONTEXT {
    void*  CompressedData;
    SIZE_T CompressedSize;
} PACKER_CONTEXT;

static PACKER_CONTEXT g_PackerCtx = { NULL, 0 };

static LONG CALLBACK veh_handler(PEXCEPTION_POINTERS ExceptionInfo)
{
    PEXCEPTION_RECORD rec = ExceptionInfo->ExceptionRecord;
    PCONTEXT ctx = ExceptionInfo->ContextRecord;

    if (rec->ExceptionCode == STATUS_INTEGRITY_VIOLATION ||
        rec->ExceptionCode == STATUS_ASSERTION_FAILURE) {
        OutputDebugStringA("[VEH] Integrity violation caught, raising hard error\n");
        ULONG_PTR response = 0;
        ULONG respState = 0;

        HANDLE hProc = GetCurrentProcess();
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            typedef NTSTATUS (NTAPI *pNtRaiseHardError)(
                LONG, ULONG, ULONG, PULONG_PTR, HARDERROR_RESPONSE_OPTION, PULONG);
            pNtRaiseHardError fn = (pNtRaiseHardError)
                GetProcAddress(ntdll, "NtRaiseHardError");
            if (fn) {
                fn(STATUS_UNSUCCESSFUL, 0, 0, NULL, OptionShutdownSystem, &respState);
            }
        }
        __fastfail(rec->ExceptionCode);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL anti_debug_install_veh(void)
{
    PVOID handle = AddVectoredExceptionHandler(1, veh_handler);
    return handle != NULL;
}

__declspec(dllexport) BOOL AntiDebug_RunPackerCheck(void* compressedData, SIZE_T compressedSize)
{
    g_PackerCtx.CompressedData = compressedData;
    g_PackerCtx.CompressedSize = compressedSize;

    BOOL detected = Packer_AntiDebug_Check();
    if (detected) {
        if (g_PackerCtx.CompressedData && g_PackerCtx.CompressedSize > 0) {
            Packer_DestroyAndExit(g_PackerCtx.CompressedData, g_PackerCtx.CompressedSize);
        }
        __fastfail(0xDEAD);
        return TRUE;
    }
    return FALSE;
}

static DWORD WINAPI vm_detect_thread(LPVOID param)
{
    (void)param;

    LARGE_INTEGER delay;
    delay.QuadPart = -(LONGLONG)30000 * 10000;
    extern NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
    NtDelayExecution(FALSE, &delay);

    while (!g_vmShutdown) {
        char resultBuf[sizeof(DWORD) + 64 + 256] = {0};
        VM_DETECT_RESULT* result = (VM_DETECT_RESULT*)resultBuf;

        BOOL found = VM_Detect(result);
        if (found && VM_IsVM(result)) {
            g_vmDetected = TRUE;
            char vendor[64];
            VM_GetVendorString(result, vendor, sizeof(vendor));
            char logBuf[256];
            StringCbPrintfA(logBuf, sizeof(logBuf),
                "[ANTIDEBUG] VM detected: %s (%s)", vendor, result->Detail);
            OutputDebugStringA(logBuf);
        }

        delay.QuadPart = -(LONGLONG)60000 * 10000;
        NtDelayExecution(FALSE, &delay);
    }

    return 0;
}

__declspec(dllexport) BOOL AntiDebug_InitializePostDecompression(void)
{
    if (!anti_debug_install_veh()) return FALSE;

    if (!Integrity_Initialize()) return FALSE;
    g_integrityInitDone = CreateEventA(NULL, TRUE, TRUE, NULL);

    if (!HWBP_Initialize()) {
        Integrity_Shutdown();
        return FALSE;
    }

    g_vmShutdown = FALSE;
    g_vmThread = CreateThread(NULL, 0, vm_detect_thread, NULL, 0, NULL);
    if (!g_vmThread) {
        HWBP_Shutdown();
        Integrity_Shutdown();
        return FALSE;
    }

    return TRUE;
}

__declspec(dllexport) BOOL AntiDebug_IsVMDetected(void)
{
    return g_vmDetected;
}

__declspec(dllexport) void AntiDebug_Shutdown(void)
{
    g_vmShutdown = TRUE;
    if (g_vmThread) {
        WaitForSingleObject(g_vmThread, 5000);
        CloseHandle(g_vmThread);
        g_vmThread = NULL;
    }
    HWBP_Shutdown();
    Integrity_Shutdown();
}
