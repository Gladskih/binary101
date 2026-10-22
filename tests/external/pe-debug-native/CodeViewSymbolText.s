# Controlled records for public LLVM layouts not emitted by this MSVC version.
# llvmorg-23.1.3 llvm/lib/DebugInfo/CodeView/SymbolRecordMapping.cpp.
.section .debug$S,"dr"
.p2align 2
.long 4
.long 0xf1
.long .Lsymbols_end - .Lsymbols
.Lsymbols:
.Lcompiler:
.short .Lcompiler_end - .Lcompiler - 2
.short 0x1116 # S_COMPILE2, UTF-8 strings in C13.
.space 18, 0 # Flags, machine and six version numbers.
.asciz "compiler"
.asciz "empty"
.asciz ""
.asciz "next"
.asciz "kept"
.byte 0 # Empty key terminates the command block.
.p2align 2, 0
.Lcompiler_end:
.Lpatch:
.short .Lpatch_end - .Lpatch - 2
.short 0x1169 # S_HOTPATCHFUNC
.long 0 # Function reference is irrelevant to the stored name.
.asciz "patch_target"
.p2align 2, 0
.Lpatch_end:
.Lindirect:
.short .Lindirect_end - .Lindirect - 2
.short 0x1171 # S_REGREL32_INDIR
.long 0 # Offset
.long 0 # Type
.long 0 # OffsetInUdt
.short 0 # NoRegister
.asciz "indirect_value"
.p2align 2, 0
.Lindirect_end:
.Lsymbols_end:
