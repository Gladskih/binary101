extern _GetStdHandle@4
extern _WriteFile@20
extern _ExitProcess@4
global _mainCRTStartup

section .text
_mainCRTStartup:
    ; STD_OUTPUT_HANDLE is -11 in WinBase.h and Microsoft GetStdHandle documentation.
    push dword -11
    call _GetStdHandle@4
    push dword 0
    push dword written
    push dword message_len
    push dword message
    push eax
    call _WriteFile@20
    push dword 0
    call _ExitProcess@4

section .data
written dd 0

section .rdata
message db "Hello, world!", 13, 10
message_len equ $ - message
