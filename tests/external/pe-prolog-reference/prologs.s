# Windows x64 unwind directives; operand units are documented by LLVM and Microsoft.
# https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
.text
.globl PrologPush
.seh_proc PrologPush
PrologPush:
 pushq %rbx
 .seh_pushreg %rbx
 subq $40, %rsp
 .seh_stackalloc 40
 .seh_endprologue
 nop
 movl $123, %ebx
 addq $40, %rsp
 popq %rbx
 retq
.seh_endproc

.globl PrologHome
.seh_proc PrologHome
PrologHome:
 movq %rbx, 8(%rsp)
 subq $40, %rsp
 .seh_stackalloc 40
 .seh_savereg %rbx, 48
 .seh_endprologue
 nop
 movq 48(%rsp), %rbx
 addq $40, %rsp
 retq
.seh_endproc

.globl PrologVector
.seh_proc PrologVector
PrologVector:
 pushq %rbp
 .seh_pushreg %rbp
 subq $64, %rsp
 .seh_stackalloc 64
 movaps %xmm6, 32(%rsp)
 .seh_savexmm %xmm6, 32
 leaq 32(%rsp), %rbp
 .seh_setframe %rbp, 32
 .seh_endprologue
 nop
 movaps 32(%rsp), %xmm6
 addq $64, %rsp
 popq %rbp
 retq
.seh_endproc

.globl PrologRegisterAllocation
.seh_proc PrologRegisterAllocation
PrologRegisterAllocation:
 movl $0x1238, %eax
 subq %rax, %rsp
 .seh_stackalloc 0x1238
 .seh_endprologue
 nop
 addq $0x1238, %rsp
 retq
.seh_endproc
