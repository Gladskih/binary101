// LLVM assembler emits the unwind pool from real instruction directives.
// Linked outputs are inspected statically, never executed.
.text
.globl entry
.p2align 2
.seh_proc entry
entry:
  stp x29, x30, [sp, #-96]!
  .seh_save_fplr_x 96
  stp x19, x20, [sp, #16]
  .seh_save_regp x19, 16
  stp x21, x22, [sp, #32]
  .seh_save_next
  stp d8, d9, [sp, #48]
  .seh_save_fregp d8, 48
  mov x29, sp
  .seh_set_fp
  .seh_endprologue
  nop
  .seh_startepilogue
  ldp d8, d9, [sp, #48]
  .seh_save_fregp d8, 48
  ldp x21, x22, [sp, #32]
  .seh_save_regp x21, 32
  ldp x19, x20, [sp, #16]
  .seh_save_regp x19, 16
  ldp x29, x30, [sp], #96
  .seh_save_fplr_x 96
  .seh_endepilogue
  ret
.seh_endproc

.globl packed
.p2align 2
.seh_proc packed
packed:
  sub sp, sp, #32
  .seh_stackalloc 32
  .seh_endprologue
  nop
  .seh_startepilogue
  add sp, sp, #32
  .seh_stackalloc 32
  .seh_endepilogue
  ret
.seh_endproc
