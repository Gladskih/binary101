// MSVC 14.51 include/ehdata.h: FuncInfo uses 32-bit VAs on x86, image-relative DWORDs
// on AMD64/ARM64. HandlerType has dispFrame only on Win64; LLVM's ARMNT emitter
// uses relative FuncInfo with 16-byte handlers. The linked ARMNT fixture checks that variant.
// https://github.com/llvm/llvm-project/blob/main/llvm/lib/CodeGen/AsmPrinter/WinException.cpp
// https://devblogs.microsoft.com/cppblog/making-cpp-exception-handling-smaller-x64/
export const FH3_LAYOUT = {
  magicNumber: 0x19930522, magicMask: 0x1fffffff, alignment: 4,
  // FI_EHS_FLAG | FI_DYNSTKALIGN_FLAG | FI_EHNOEXCEPT_FLAG. SVE frames stay unresolved.
  supportedEhFlags: 7,
  absoluteFuncInfoSize: 36, relativeFuncInfoSize: 40,
  unwindEntrySize: 8, tryBlockEntrySize: 20, ipStateEntrySize: 8,
  handlerEntrySize32: 16, handlerEntrySize64: 20
} as const;

// MSVC 14.51 include/ehdata4_export.h, FuncInfoHeader and HandlerTypeHeader.
// The Microsoft article reproduces FuncInfoHeader; local integration tests compile
// against this CRT and compare explicit continuations with link.exe EHCONT metadata.
// https://devblogs.microsoft.com/cppblog/making-cpp-exception-handling-smaller-x64/
export const FH4_FUNCTION_FLAGS = {
  isCatch: 1, isSeparated: 2, bbt: 4, unwindMap: 8, tryBlockMap: 16,
  synchronous: 32, noExcept: 64, reserved: 128
} as const;

export const FH4_HANDLER_FLAGS = {
  adjectives: 1, type: 2, catchObject: 4, continuationsAreRvas: 8,
  continuationCountShift: 4, continuationCountMask: 3, reserved: 0xc0
} as const;

// UnwindMapEntry4::Type; nextOffset occupies all bits above these low two type bits.
export const FH4_UNWIND_TYPE = { none: 0, object: 1, objectPointer: 2, funclet: 3 } as const;
