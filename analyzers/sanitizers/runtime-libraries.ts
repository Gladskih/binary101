import type { SanitizerTool } from "./types.js";

// GCC runtime SONAMEs: https://github.com/gcc-mirror/gcc/tree/master/libsanitizer
// compiler-rt names: https://github.com/llvm/llvm-project/blob/main/compiler-rt/cmake/Modules/AddCompilerRT.cmake
// Windows ASan: https://learn.microsoft.com/en-us/cpp/sanitizers/asan-runtime
const RUNTIME_NAMES: Readonly<Record<string, SanitizerTool>> = {
  asan: "ASan", tsan: "TSan", ubsan: "UBSan", lsan: "LSan", hwasan: "HWASan",
  msan: "MSan", dfsan: "DFSan", rtsan: "RTSan", tysan: "TySan",
  ubsan_standalone: "UBSan", ubsan_minimal: "UBSan minimal"
};

export const identifySanitizerLibrary = (name: string): SanitizerTool | null => {
  const gcc = /^lib(asan|tsan|ubsan|lsan|hwasan)\.so(?:\.[0-9]+)*$/.exec(name);
  if (gcc) return RUNTIME_NAMES[gcc[1]!]!;
  const llvm = /^libclang_rt\.(asan|tsan|ubsan_standalone|ubsan_minimal|lsan|hwasan|msan|dfsan|rtsan|tysan)-(x86_64|i386|aarch64|arm|riscv64|powerpc64|powerpc64le|s390x|loongarch64)\.so$/.exec(name);
  if (llvm) return RUNTIME_NAMES[llvm[1]!]!;
  return /^clang_rt\.asan(?:_dbg)?_dynamic-(i386|x86_64|aarch64)\.dll$/i.test(name)
    ? "ASan" : null;
};
