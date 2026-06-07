default rel

extern GetStdHandle
extern WriteFile
extern ExitProcess
global mainCRTStartup

section .text
mainCRTStartup:
    sub rsp, 56
    ; STD_OUTPUT_HANDLE is -11 in WinBase.h and Microsoft GetStdHandle documentation.
    mov ecx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [message]
    mov r8d, message_len
    lea r9, [rsp + 40]
    mov qword [rsp + 32], 0
    call WriteFile
    xor ecx, ecx
    call ExitProcess

section .rdata
message db "Hello, world!", 13, 10
message_len equ $ - message
