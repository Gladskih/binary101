.386
.model flat, stdcall
option casemap:none

extrn GetStdHandle@4:proc
extrn WriteFile@20:proc
extrn ExitProcess@4:proc

.data
message db "Hello, world!", 13, 10
message_len equ $ - message
written dd 0

.code
mainCRTStartup proc
    ; STD_OUTPUT_HANDLE is -11 in WinBase.h and Microsoft GetStdHandle documentation.
    push -11
    call GetStdHandle@4
    push 0
    push offset written
    push message_len
    push offset message
    push eax
    call WriteFile@20
    push 0
    call ExitProcess@4
mainCRTStartup endp
end mainCRTStartup
