# Controlled layouts from TIS 2.2/3.3/3.4 and Microsoft's cvinfo.h.
# See 805655a28bd8198004be2ac27e6e0290121a5e89 for DISCARDEDSYM/lfPointer/lfRefSym.
.section .debug$S,"dr"
.p2align 2
.long 4
.long 0xf1
.long .Lsymbols_end - .Lsymbols
.Lsymbols:
.Ldiscard:
.short .Ldiscard_end - .Ldiscard - 2
.short 0x113b
.long 2 # CV_DISCARDED_NOT_REFERENCED, no reserved bits.
.long 0xffffffff # No source FILEID.
.long 0
.Lremoved:
.short .Lremoved_end - .Lremoved - 2
.short 0x110d # S_GDATA32
.long 0x74
.long 0
.short 0
.asciz "removedValue"
.p2align 2, 0
.Lremoved_end:
.Ldiscard_end:
.Lsymbols_end:

.section .debug$T,"dr"
.p2align 2
.long 4
.Lold:
.short .Lold_end - .Lold - 2
.short 2 # LF_POINTER_16t, based on type.
.short 8
.short 0x70
.short 0x74
.byte 7
.ascii "OldBase"
.byte 0xf2, 0xf1
.Lold_end:
.Lwide:
.short .Lwide_end - .Lwide - 2
.short 0x1002 # LF_POINTER, base-type name is still length-prefixed.
.long 0x70
.long 8
.long 0x74
.byte 8
.ascii "WideBase"
.byte 0xf3, 0xf2, 0xf1
.Lwide_end:
.Lref:
.short .Lref_end - .Lref - 2
.short 0x20c # LF_REFSYM
.Lreferenced:
.short .Lreferenced_end - .Lreferenced - 2
.short 0x110d
.long 0x74
.long 0
.short 0
.asciz "referenced"
.p2align 2, 0
.Lreferenced_end:
.Lref_end:
