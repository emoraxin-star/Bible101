.CODE

ALIGN 16

; NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead)
NtReadVirtualMemory PROC
    mov     r10, rcx
    mov     eax, 3Fh
    syscall
    ret
NtReadVirtualMemory ENDP

; NTSTATUS NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, HARDERROR_RESPONSE_OPTION ResponseOption, PULONG ReturnValue)
NtRaiseHardError PROC
    mov     r10, rcx
    mov     eax, 0D2h
    syscall
    ret
NtRaiseHardError ENDP

; NTSTATUS NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
NtDelayExecution PROC
    mov     r10, rcx
    mov     eax, 34h
    syscall
    ret
NtDelayExecution ENDP

; NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
NtQueryInformationProcess PROC
    mov     r10, rcx
    mov     eax, 19h
    syscall
    ret
NtQueryInformationProcess ENDP

; NTSTATUS NtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context)
NtGetContextThread PROC
    mov     r10, rcx
    mov     eax, 0B8h
    syscall
    ret
NtGetContextThread ENDP

; NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context)
NtSetContextThread PROC
    mov     r10, rcx
    mov     eax, 0B9h
    syscall
    ret
NtSetContextThread ENDP

; NTSTATUS NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
NtOpenKey PROC
    mov     r10, rcx
    mov     eax, 0Fh
    syscall
    ret
NtOpenKey ENDP

; NTSTATUS NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG KeyValueInformationLength, PULONG ResultLength)
NtQueryValueKey PROC
    mov     r10, rcx
    mov     eax, 11h
    syscall
    ret
NtQueryValueKey ENDP

; NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
NtQuerySystemInformation PROC
    mov     r10, rcx
    mov     eax, 36h
    syscall
    ret
NtQuerySystemInformation ENDP

; NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
NtOpenProcess PROC
    mov     r10, rcx
    mov     eax, 26h
    syscall
    ret
NtOpenProcess ENDP

END
