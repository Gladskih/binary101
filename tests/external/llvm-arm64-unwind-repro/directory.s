// /merge:.tail=.pdata puts ordinary data after the eight-byte exception table.
// The PE Exception Directory size remains eight bytes; section size is sixteen.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
// https://learn.microsoft.com/en-us/cpp/build/reference/merge-combine-sections
.text
.globl main
// Four-byte ARM64 instructions; .p2align 2 aligns to 2^2 bytes.
.p2align 2
main:
    ret
function_end:
.section .pdata,"dr"
// RUNTIME_FUNCTION consists of four-byte words (Microsoft ARM64 EH, linked below).
.p2align 2
    .rva main
    // Packed flag 1, four-byte instruction units, length starts at bit 2.
    // https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#packed-unwind-data
    .long 1 | (((function_end - main) / 4) << 2)
.section .tail,"dr"
// Align these ordinary RVA values to their four-byte word size.
.p2align 2
    .rva main
    .rva ordinary_data
.section .rdata,"dr"
ordinary_data:
    // Deliberately ordinary zero data, outside the exception table. If incorrectly
    // treated as xdata, four bytes cannot hold its header plus unwind instructions.
    .long 0
