PUBLIC probe
.code
probe PROC FRAME
    .endprolog
    lea rax, [rcx + 1]
    xor rax, 42
    ret
probe ENDP
END
