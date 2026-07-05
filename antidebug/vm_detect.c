#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <intrin.h>
#include <strsafe.h>
#include <stdlib.h>

#pragma comment(lib, "ntdll.lib")

#define VM_FLAG_NONE       0x0000
#define VM_FLAG_VMWARE     0x0001
#define VM_FLAG_VBOX       0x0002
#define VM_FLAG_QEMU       0x0004
#define VM_FLAG_XEN        0x0008
#define VM_FLAG_HYPERV     0x0010
#define VM_FLAG_GENERIC    0x0020

typedef struct _VM_DETECT_RESULT {
    DWORD Flags;
    char  Vendor[64];
    char  Detail[256];
} VM_DETECT_RESULT;

static const struct {
    const wchar_t* Path;
    const wchar_t* ValueName;
    const wchar_t* Needle;
    DWORD Flag;
} vmRegistryChecks[] = {
    { L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
      L"Identifier", L"VMWARE", VM_FLAG_VMWARE },
    { L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
      L"Identifier", L"VBOX", VM_FLAG_VBOX },
    { L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
      L"Identifier", L"QEMU", VM_FLAG_QEMU },
    { L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
      L"Identifier", L"Virtual", VM_FLAG_GENERIC },
    { L"\\Registry\\Machine\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
      L"DisplayName", L"VirtualBox", VM_FLAG_VBOX },
    { L"\\Registry\\Machine\\SOFTWARE\\VMware, Inc.\\VMware Tools",
      L"DisplayName", L"VMware", VM_FLAG_VMWARE },
    { NULL, NULL, NULL, 0 }
};

extern NTSTATUS NTAPI NtOpenKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
extern NTSTATUS NTAPI NtQueryValueKey(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
extern NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
extern NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);

static BOOL vm_detect_registry(VM_DETECT_RESULT* result)
{
    BOOL found = FALSE;

    for (int i = 0; vmRegistryChecks[i].Path; i++) {
        UNICODE_STRING objName;
        RtlInitUnicodeString(&objName, vmRegistryChecks[i].Path);

        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &objName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hKey = NULL;
        NTSTATUS status = NtOpenKey(&hKey, KEY_READ, &objAttr);
        if (!NT_SUCCESS(status)) continue;

        UNICODE_STRING valueName;
        RtlInitUnicodeString(&valueName, vmRegistryChecks[i].ValueName);

        BYTE buffer[512];
        ULONG resultLen = 0;
        status = NtQueryValueKey(hKey, &valueName, KeyValuePartialInformation,
                                 buffer, sizeof(buffer), &resultLen);
        if (NT_SUCCESS(status)) {
            PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
            if (info->Type == REG_SZ) {
                const wchar_t* data = (const wchar_t*)info->Data;
                SIZE_T dataLen = info->DataLength / sizeof(wchar_t);
                if (wcsstr(data, vmRegistryChecks[i].Needle)) {
                    result->Flags |= vmRegistryChecks[i].Flag;
                    result->Flags |= VM_FLAG_GENERIC;
                    StringCbPrintfA(result->Detail, sizeof(result->Detail),
                        "Registry: %ls contains '%ls'",
                        vmRegistryChecks[i].Path, vmRegistryChecks[i].Needle);
                    found = TRUE;
                }
            }
        }
        NtClose(hKey);
    }
    return found;
}

static const char* vmProcessNames[] = {
    "vmtoolsd.exe",
    "VBoxService.exe",
    "vbox.exe",
    "xenservice.exe",
    "qemu-ga.exe",
    "VGAuthService.exe",
    NULL
};

static BOOL vm_detect_processes(VM_DETECT_RESULT* result)
{
    ULONG bufferSize = 0x10000;
    PVOID buffer = malloc(bufferSize);
    if (!buffer) return FALSE;

    SYSTEM_PROCESS_INFORMATION* spi;
    ULONG returnLen = 0;

    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLen);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        bufferSize = returnLen;
        free(buffer);
        buffer = malloc(bufferSize);
        if (!buffer) return FALSE;
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLen);
    }

    if (!NT_SUCCESS(status)) {
        free(buffer);
        return FALSE;
    }

    BOOL found = FALSE;
    spi = (SYSTEM_PROCESS_INFORMATION*)buffer;
    while (TRUE) {
        if (spi->ImageName.Buffer) {
            int len = spi->ImageName.Length / sizeof(wchar_t);
            for (int i = 0; vmProcessNames[i]; i++) {
                int nameLen = (int)strlen(vmProcessNames[i]);
                int wnameLen = MultiByteToWideChar(CP_ACP, 0, vmProcessNames[i], -1, NULL, 0) - 1;
                if (len >= wnameLen) {
                    const wchar_t* procName = spi->ImageName.Buffer + len - wnameLen;
                    if (_wcsicmp(procName, L"vmtoolsd.exe") == 0) {
                        result->Flags |= VM_FLAG_VMWARE; found = TRUE;
                    } else if (_wcsicmp(procName, L"VBoxService.exe") == 0 ||
                               _wcsicmp(procName, L"vbox.exe") == 0) {
                        result->Flags |= VM_FLAG_VBOX; found = TRUE;
                    } else if (_wcsicmp(procName, L"xenservice.exe") == 0) {
                        result->Flags |= VM_FLAG_XEN; found = TRUE;
                    } else if (_wcsicmp(procName, L"qemu-ga.exe") == 0) {
                        result->Flags |= VM_FLAG_QEMU; found = TRUE;
                    }
                    if (found) {
                        result->Flags |= VM_FLAG_GENERIC;
                        char ansiName[64];
                        WideCharToMultiByte(CP_ACP, 0, procName, -1, ansiName, sizeof(ansiName), NULL, NULL);
                        StringCbPrintfA(result->Detail, sizeof(result->Detail),
                            "Process: %s", ansiName);
                    }
                }
            }
        }
        if (spi->NextEntryOffset == 0) break;
        spi = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
    }

    free(buffer);
    return found;
}

static void vm_detect_cpuid(VM_DETECT_RESULT* result)
{
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);

    if (cpuInfo[2] & (1 << 31)) {
        result->Flags |= VM_FLAG_GENERIC;
        StringCbPrintfA(result->Detail, sizeof(result->Detail),
            "CPUID: Hypervisor bit (ECX[31]) set");
    }

    __cpuid(cpuInfo, 0x40000000);
    if (cpuInfo[0] >= 0x40000000) {
        char vendor[13];
        memcpy(vendor + 0, &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[2], 4);
        memcpy(vendor + 8, &cpuInfo[3], 4);
        vendor[12] = 0;

        if (strstr(vendor, "VMware") || strstr(vendor, "VMW")) {
            result->Flags |= VM_FLAG_VMWARE | VM_FLAG_GENERIC;
        } else if (strstr(vendor, "VBox") || strstr(vendor, "VirtualBox")) {
            result->Flags |= VM_FLAG_VBOX | VM_FLAG_GENERIC;
        } else if (strstr(vendor, "KVM") || strstr(vendor, "QEMU")) {
            result->Flags |= VM_FLAG_QEMU | VM_FLAG_GENERIC;
        } else if (strstr(vendor, "Xen")) {
            result->Flags |= VM_FLAG_XEN | VM_FLAG_GENERIC;
        } else if (strstr(vendor, "Microsoft Hv")) {
            result->Flags |= VM_FLAG_HYPERV | VM_FLAG_GENERIC;
        }

        if (result->Flags & VM_FLAG_GENERIC) {
            StringCbPrintfA(result->Detail, sizeof(result->Detail),
                "CPUID hypervisor leaf: %s", vendor);
        }
    }
}

static void vm_detect_windows(VM_DETECT_RESULT* result)
{
    HWND hwnd;
    const struct {
        const char* Class;
        DWORD Flag;
    } debugClasses[] = {
        { "OLLYDBG",               VM_FLAG_GENERIC },
        { "x64_dbg",               VM_FLAG_GENERIC },
        { "x32_dbg",               VM_FLAG_GENERIC },
        { "ImmunityDebugger",      VM_FLAG_GENERIC },
        { "WinDbgFrameClass",      VM_FLAG_GENERIC },
        { "IDAClass",              VM_FLAG_GENERIC },
        { "GhidraFrame",           VM_FLAG_GENERIC },
        { NULL, 0 }
    };

    for (int i = 0; debugClasses[i].Class; i++) {
        hwnd = FindWindowA(debugClasses[i].Class, NULL);
        if (hwnd) {
            result->Flags |= debugClasses[i].Flag;
            if (!result->Detail[0]) {
                StringCbPrintfA(result->Detail, sizeof(result->Detail),
                    "Window class: %s", debugClasses[i].Class);
            }
            break;
        }
    }
}

__declspec(dllexport) BOOL VM_Detect(VM_DETECT_RESULT* result)
{
    if (!result) return FALSE;
    RtlSecureZeroMemory(result, sizeof(*result));

    vm_detect_registry(result);
    vm_detect_processes(result);
    vm_detect_cpuid(result);
    vm_detect_windows(result);

    return (result->Flags != VM_FLAG_NONE);
}

__declspec(dllexport) BOOL VM_IsVM(VM_DETECT_RESULT* result)
{
    if (!result) return FALSE;
    return (result->Flags & VM_FLAG_GENERIC) != 0;
}

__declspec(dllexport) void VM_GetVendorString(VM_DETECT_RESULT* result, char* buffer, SIZE_T bufferSize)
{
    if (!result || !buffer || !bufferSize) return;
    buffer[0] = 0;

    if (result->Flags & VM_FLAG_VMWARE) {
        StringCbCopyA(buffer, bufferSize, "VMware");
    } else if (result->Flags & VM_FLAG_VBOX) {
        StringCbCopyA(buffer, bufferSize, "VirtualBox");
    } else if (result->Flags & VM_FLAG_QEMU) {
        StringCbCopyA(buffer, bufferSize, "QEMU");
    } else if (result->Flags & VM_FLAG_XEN) {
        StringCbCopyA(buffer, bufferSize, "Xen");
    } else if (result->Flags & VM_FLAG_HYPERV) {
        StringCbCopyA(buffer, bufferSize, "Hyper-V");
    } else {
        StringCbCopyA(buffer, bufferSize, "Unknown");
    }
}
