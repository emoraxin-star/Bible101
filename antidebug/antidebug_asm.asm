.CODE

ALIGN 16

; NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
NtQueryInformationProcess PROC
    mov     r10, rcx
    mov     eax, 19h
    syscall
    ret
NtQueryInformationProcess ENDP

; NTSTATUS NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
NtDelayExecution PROC
    mov     r10, rcx
    mov     eax, 34h
    syscall
    ret
NtDelayExecution ENDP

END
