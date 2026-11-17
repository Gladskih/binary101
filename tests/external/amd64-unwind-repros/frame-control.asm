PUBLIC probe
.code
probe PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    ; RBP anchors the frame before this allocation.
    ; SET_FPREG restores RSP from RBP during unwinding.
    ; https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
    sub rsp, 32
    .endprolog
    nop
    lea rax, [rcx + 1]
    xor rax, 42
    lea rsp, [rbp]
    pop rbp
    ret
probe ENDP
END
