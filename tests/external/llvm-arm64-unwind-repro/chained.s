// ARM64 flag 3 points to a parent RUNTIME_FUNCTION for an adrp/add/br thunk.
// Wine dump_arm64_unwind_info, case 3; also confirmed with MSVC dumpbin 14.51:
// https://github.com/wine-mirror/wine/blob/a15ee2ccf20e2fc9f470badd916855801933d31f/tools/winedump/pe.c#L2251-L2261
.text
.globl main
// Four-byte ARM64 instructions; .p2align 2 aligns to 2^2 bytes.
.p2align 2
main:
    ret
thunk:
    adrp x16, main
    add x16, x16, :lo12:main
    br x16
thunk_end:
.section .pdata,"dr"
// RUNTIME_FUNCTION consists of four-byte words (Microsoft ARM64 EH, linked below).
.p2align 2
parent_pdata:
    .rva main
    // Packed flag 1; length is measured in four-byte instructions, starting at bit 2.
    // https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#packed-unwind-data
    .long 1 | (((thunk - main) / 4) << 2)
    .rva thunk
.ifdef PACKED_CONTROL
    .long 1 | (((thunk_end - thunk) / 4) << 2)
.else
    .rva parent_pdata + 3
.endif
