import assert from "node:assert/strict";
import { test } from "node:test";
import { identifySanitizerLibrary } from "../../../../analyzers/sanitizers/runtime-libraries.js";

for (const [name, tool] of [
  ["libasan.so", "ASan"], ["libasan.so.8.0.0", "ASan"], ["libtsan.so.2", "TSan"],
  ["libubsan.so.1", "UBSan"], ["liblsan.so.0", "LSan"], ["libhwasan.so.0", "HWASan"],
  ["libclang_rt.asan-x86_64.so", "ASan"], ["libclang_rt.tsan-aarch64.so", "TSan"],
  ["libclang_rt.ubsan_standalone-i386.so", "UBSan"],
  ["libclang_rt.ubsan_minimal-aarch64.so", "UBSan minimal"],
  ["libclang_rt.msan-x86_64.so", "MSan"], ["libclang_rt.lsan-x86_64.so", "LSan"],
  ["libclang_rt.hwasan-aarch64.so", "HWASan"], ["libclang_rt.dfsan-x86_64.so", "DFSan"],
  ["libclang_rt.rtsan-x86_64.so", "RTSan"], ["libclang_rt.tysan-x86_64.so", "TySan"],
  ["clang_rt.asan_dynamic-i386.dll", "ASan"], ["clang_rt.asan_dbg_dynamic-x86_64.dll", "ASan"],
  ["CLANG_RT.ASAN_DYNAMIC-X86_64.DLL", "ASan"],
  ["libasan.so.12", "ASan"] // GCC version components are decimal numbers, not digits.
]) {
  void test(`recognizes runtime basename ${name}`, () => {
    assert.equal(identifySanitizerLibrary(name!), tool);
  });
}

void test("rejects names that merely mention a sanitizer", () => {
  assert.equal(identifySanitizerLibrary("example-asan.so"), null);
  assert.equal(identifySanitizerLibrary("libasan.so.8\0"), null);
  assert.equal(identifySanitizerLibrary("libasan.so.8\n"), null);
  assert.equal(identifySanitizerLibrary("libasan.so."), null);
  assert.equal(identifySanitizerLibrary("libclang_rt.asan-fake.so"), null);
  assert.equal(identifySanitizerLibrary(""), null);
});

for (const name of ["prefix-libclang_rt.asan-x86_64.so", "libclang_rt.asan-x86_64.so.bak",
  "prefix-clang_rt.asan_dynamic-x86_64.dll", "clang_rt.asan_dynamic-x86_64.dll.bak",
  "/usr/lib/libasan.so.8", "LIBASAN.SO.8", "libasan.so.8suffix"]) {
  void test(`requires an exact runtime basename: ${name}`, () => {
    assert.equal(identifySanitizerLibrary(name), null);
  });
}
