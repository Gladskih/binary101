.syntax unified
.thumb
.text
.globl arm_cpp
.def arm_cpp
.scl 2
.type 32
.endef
.thumb_func
.seh_proc arm_cpp
arm_cpp:
  push {r4, lr}
  .seh_save_regs {r4, lr}
  .seh_endprologue
  nop
  .seh_startepilogue
  pop {r4, pc}
  .seh_save_regs {r4, pc}
  .seh_endepilogue
  .seh_handler __CxxFrameHandler3, %except
  .seh_handlerdata
  .rva cpp_info
.text
.seh_endproc
.thumb_func
catch_code:
  bx lr
.section .xdata,"dr"
.p2align 2
cpp_info:
  .long 0x19930522, 2
  .rva uw_map
  .long 1
  .rva try_map
  .long 1
  .rva ip_map
  .long 0, 0, 1
uw_map:
  .long -1, 0, -1, 0
try_map:
  .long 0, 0, 1, 1
  .rva handler_map
handler_map:
  .long 0, 0, 0
  .rva catch_code
ip_map:
  .rva arm_cpp
  .long -1
