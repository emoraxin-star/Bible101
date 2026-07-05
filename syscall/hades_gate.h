#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HADES_NTDLL_INFO {
    PVOID  DllBase;
    ULONG  ImageSize;
    PVOID  TextStart;
    ULONG  TextSize;
} HADES_NTDLL_INFO, *PHADES_NTDLL_INFO;

__declspec(noinline) PVOID HadesGetNtdllBase(void);

BOOL HadesGetNtdllInfo(PHADES_NTDLL_INFO Info);

ULONG HadesExtractSsnFromProc(PVOID NtdllBase, PVOID ProcAddress);

ULONG HadesGetSSN(PVOID NtdllBase, PCSTR FunctionName);

ULONG HadesResolveSSN(PCSTR FunctionName);

PVOID HadesGetProcR(PVOID NtdllBase, PCSTR FunctionName);

#ifdef __cplusplus
}
#endif
