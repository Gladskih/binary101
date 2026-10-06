import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeSanitizerEvidence } from "../../../../analyzers/sanitizers/evidence.js";
import type { SanitizerSymbol } from "../../../../analyzers/sanitizers/types.js";

const symbols = (names: string[], kind: SanitizerSymbol["kind"] = "reference") =>
  names.map(name => ({ name, kind, source: "fixture symbols" }));

void test("recognizes separate ASan references and runtime definitions", () => {
  const result = analyzeSanitizerEvidence([], [
    ...symbols(["__asan_init", "__asan_report_load4"]),
    ...symbols(["__asan_init", "__asan_report_store8"], "definition")
  ]);
  assert.deepEqual(result.map(row => [row.tool, row.kind, row.name]), [
    ["ASan", "reference", "__asan_init"],
    ["ASan", "reference", "__asan_report_load4"],
    ["ASan", "definition", "__asan_init"],
    ["ASan", "definition", "__asan_report_store8"]
  ]);
});

void test("requires two distinct ABI symbols of the same family and kind", () => {
  assert.deepEqual(analyzeSanitizerEvidence([], symbols(["__asan_init"])), []);
  assert.deepEqual(analyzeSanitizerEvidence([], symbols(["__asan_init", "__asan_init"])), []);
  assert.deepEqual(analyzeSanitizerEvidence([], [
    ...symbols(["__asan_init"]), ...symbols(["__asan_report_load4"], "definition")
  ]), []);
  assert.deepEqual(analyzeSanitizerEvidence([], symbols(["__asan_init", "__tsan_init"])), []);
});

void test("rejects prefixes, configuration hooks, strings and malformed symbol names", () => {
  assert.deepEqual(analyzeSanitizerEvidence([], symbols([
    "asan", "__asan_custom", "__asan_default_options", "__asan_on_error",
    "prefix__asan_init", "__asan_init_suffix", "__asan_init\0", "__ASAN_INIT",
    "__asan_report_load3", "__asan_report_load4_extra", "__ubsan_handle_fake",
    "__ubsan_handle_add_overflow_minimal_extra", "__tsan_read3"
  ])), []);
});

void test("library dependencies alone are reported only as dependencies", () => {
  assert.deepEqual(analyzeSanitizerEvidence([
    { name: "libasan.so.8", source: "DT_NEEDED" },
    { name: "CLANG_RT.ASAN_DYNAMIC-X86_64.DLL", source: "PE import" }
  ], []), [
    { tool: "ASan", kind: "dependency", name: "libasan.so.8", source: "DT_NEEDED" },
    { tool: "ASan", kind: "dependency", name: "CLANG_RT.ASAN_DYNAMIC-X86_64.DLL",
      source: "PE import" }
  ]);
});

void test("rejects ambiguous, renamed, path-containing and suffixed dependencies", () => {
  assert.deepEqual(analyzeSanitizerEvidence([
    "asan.dll", "asan-helper.so", "libasan_custom.so", "libasan.so.bad", "libasan.so.8.bak",
    "/tmp/libasan.so.8", "C:\\libasan.so.8", "clang_rt.asan_dynamic-fake.dll",
    "libclang_rt.asan-x86_64.so.bak", "libsanitizer.so", "libASAN.so.8"
  ].map(name => ({ name, source: "DT_NEEDED" })), []), []);
});

// Independent ABI examples from compiler-rt interfaces, not production catalog constants.
for (const [tool, names] of [
  ["TSan", ["__tsan_func_entry", "__tsan_read4"]],
  ["UBSan", ["__ubsan_handle_type_mismatch_v1", "__ubsan_handle_add_overflow_abort"]],
  ["UBSan minimal", ["__ubsan_handle_add_overflow_minimal", "__ubsan_handle_type_mismatch_minimal_abort"]],
  ["MSan", ["__msan_init", "__msan_warning_noreturn"]],
  ["LSan", ["__lsan_init", "__lsan_do_leak_check"]],
  ["HWASan", ["__hwasan_init", "__hwasan_tag_mismatch_v2"]],
  ["DFSan", ["__dfsan_union_load", "__dfsan_load_label_and_origin"]],
  ["RTSan", ["__rtsan_realtime_enter", "__rtsan_realtime_exit"]],
  ["TySan", ["__tysan_init", "__tysan_check"]],
  ["SanitizerCoverage", ["__sanitizer_cov_trace_pc_guard", "__sanitizer_cov_trace_pc_guard_init"]]
] as const) {
  void test(`recognizes ${tool} without conflating sanitizer families`, () => {
    assert.deepEqual(analyzeSanitizerEvidence([], symbols([...names])).map(row => row.tool),
      [tool, tool]);
  });
}

void test("deduplicates repeated observations while retaining distinct sources", () => {
  const repeated = symbols(["__asan_init", "__asan_report_load4"]);
  assert.equal(analyzeSanitizerEvidence([], [...repeated, ...repeated]).length, 2);
  assert.equal(analyzeSanitizerEvidence([], [
    ...repeated, { ...repeated[0]!, source: "other table" }
  ]).length, 3);
});

void test("handles empty metadata", () => {
  assert.deepEqual(analyzeSanitizerEvidence([], []), []);
});
