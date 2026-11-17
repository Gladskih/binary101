PUBLIC call_probe
.code
; Win64 shadow space and a real caller frame.
; https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
call_probe PROC FRAME
    push rbp
    .pushreg rbp
    sub rsp, 32
    .allocstack 32
    lea rbp, [rsp + 32]
    .setframe rbp, 32
    .endprolog
    mov rax, rcx
    mov rcx, rdx
    call rax
    add rsp, 32
    pop rbp
    ret
call_probe ENDP
END
