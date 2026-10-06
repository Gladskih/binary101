import assert from "node:assert/strict";
import { test } from "node:test";
import { SANITIZER_ABI_SYMBOLS } from "../../../../analyzers/sanitizers/abi-catalog.js";

void test("distinguishes ASan variable-size load ABI from report ABI", () => {
  // compiler-rt/lib/asan/asan_interface.inc: loadN vs report_load_n.
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__asan_loadN"), "ASan");
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__asan_report_load_n"), "ASan");
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__asan_report_loadN"), undefined);
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__asan_report_store_n_noabort"), "ASan");
});

void test("includes only known fixed access widths", () => {
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__asan_report_store16"), "ASan");
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__asan_report_store32"), undefined);
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__tsan_read16_pc"), "TSan");
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__hwasan_store16"), "HWASan");
});

void test("keeps minimal UBSan type mismatch separate from the full versioned ABI", () => {
  // ubsan_handlers.h vs ubsan_minimal_handlers.cpp.
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__ubsan_handle_type_mismatch_v1"), "UBSan");
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__ubsan_handle_type_mismatch_minimal"), "UBSan minimal");
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__ubsan_handle_type_mismatch_v1_minimal"), undefined);
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__ubsan_handle_missing_return_abort"), undefined);
});

void test("configuration hooks and nonexistent names do not count as instrumentation", () => {
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__lsan_default_options"), undefined);
  assert.equal(SANITIZER_ABI_SYMBOLS.get("__dfsan_store_label"), undefined);
  assert.equal(SANITIZER_ABI_SYMBOLS.get("runtime.raceinit"), undefined);
});
