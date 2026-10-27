// x64 UNWIND_INFO flags; V3 retains the handler/chain ABI and adds LARGE.
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/Support/Win64EH.h
export const UNW_FLAG_EHANDLER = 0x01;
export const UNW_FLAG_UHANDLER = 0x02;
export const UNW_FLAG_CHAININFO = 0x04;
export const UNW_FLAG_LARGE = 0x08;
