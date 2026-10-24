# LLVM COFF assembler directives generate real v1 UNWIND_INFO records.
# The linked image is inspected statically, never executed.
# https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
.text
.globl entry
.seh_proc entry
entry:
  pushq %rbp
  .seh_pushreg %rbp
  subq $512, %rsp
  .seh_stackalloc 512
  leaq 32(%rsp), %rbp
  .seh_setframe %rbp, 32
  movq %rdi, 40(%rsp)
  .seh_savereg %rdi, 40
  movaps %xmm6, 48(%rsp)
  .seh_savexmm %xmm6, 48
  .seh_endprologue
  movaps 48(%rsp), %xmm6
  movq 40(%rsp), %rdi
  addq $512, %rsp
  popq %rbp
  retq
.seh_endproc

.globl large_frame
.seh_proc large_frame
large_frame:
  subq $1114112, %rsp
  .seh_stackalloc 1114112
  movq %r12, 524288(%rsp)
  .seh_savereg %r12, 524288
  movaps %xmm15, 1048576(%rsp)
  .seh_savexmm %xmm15, 1048576
  .seh_endprologue
  movaps 1048576(%rsp), %xmm15
  movq 524288(%rsp), %r12
  addq $1114112, %rsp
  retq
.seh_endproc

.globl small_frame
.seh_proc small_frame
small_frame:
  subq $32, %rsp
  .seh_stackalloc 32
  .seh_endprologue
  addq $32, %rsp
  retq
.seh_endproc
