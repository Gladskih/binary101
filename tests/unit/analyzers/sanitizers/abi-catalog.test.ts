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

// Independent expectations from the upstream declarations linked in each group.
// These check the ABI contract, including exact suffixes, rather than catalog construction.
const interfaces = [
  ["ASan", "__asan_", "init register_globals register_elf_globals register_image_globals " +
    "unregister_globals unregister_elf_globals"],
  ["MSan", "__msan_", "init warning warning_noreturn warning_with_origin " +
    "warning_with_origin_noreturn maybe_warning_1 maybe_warning_2 maybe_warning_4 " +
    "maybe_warning_8 chain_origin"],
  ["HWASan", "__hwasan_", "init tag_mismatch tag_mismatch_v2 tag_memory generate_tag loadN storeN"],
  ["TSan", "__tsan_", "init func_entry func_exit read_range write_range vptr_read vptr_update"],
  ["LSan", "__lsan_", "init do_leak_check do_recoverable_leak_check"],
  ["DFSan", "__dfsan_", "union_load load_label_and_origin chain_origin set_label unimplemented"],
  ["RTSan", "__rtsan_", "init realtime_enter realtime_exit notify_blocking_call"],
  ["TySan", "__tysan_", "init check"],
  ["SanitizerCoverage", "__sanitizer_cov_", "trace_pc trace_pc_guard trace_pc_guard_init " +
    "8bit_counters_init bool_flag_init pcs_init trace_cmp1 trace_cmp2 trace_cmp4 trace_cmp8 " +
    "trace_const_cmp1 trace_const_cmp2 trace_const_cmp4 trace_const_cmp8 trace_switch"]
] as const;

for (const [tool, prefix, names] of interfaces) {
  void test(`preserves the documented ${tool} entry points`, () => {
    for (const name of names.split(" ")) {
      assert.equal(SANITIZER_ABI_SYMBOLS.get(prefix + name), tool, prefix + name);
    }
  });
}

for (const width of ["1", "2", "4", "8", "16"]) {
  // asan_interface.inc, hwasan_interface_internal.h, tsan_interface.h.
  for (const operation of ["load", "store"]) {
    for (const suffix of ["", "_noabort"]) {
      void test(`preserves ASan ${operation}${width}${suffix} access and report callbacks`, () => {
        assert.equal(SANITIZER_ABI_SYMBOLS.get(`__asan_${operation}${width}${suffix}`), "ASan");
        assert.equal(SANITIZER_ABI_SYMBOLS.get(`__asan_report_${operation}${width}${suffix}`), "ASan");
      });
    }
    void test(`preserves HWASan ${operation}${width} callbacks`, () => {
      assert.equal(SANITIZER_ABI_SYMBOLS.get(`__hwasan_${operation}${width}`), "HWASan");
    });
  }
  for (const operation of ["read", "write"]) {
    void test(`preserves TSan ${operation}${width} callbacks with and without a PC`, () => {
      assert.equal(SANITIZER_ABI_SYMBOLS.get(`__tsan_${operation}${width}`), "TSan");
      assert.equal(SANITIZER_ABI_SYMBOLS.get(`__tsan_${operation}${width}_pc`), "TSan");
    });
  }
}

void test("preserves ASan variable-length callbacks, including recovery variants", () => {
  for (const name of ["loadN", "storeN", "loadN_noabort", "storeN_noabort",
    "report_load_n", "report_store_n", "report_load_n_noabort", "report_store_n_noabort"]) {
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__asan_${name}`), "ASan", name);
  }
});

// ubsan_handlers.h / ubsan_handlers_cxx.h / ubsan_minimal_handlers.cpp.
const recoverableChecks = "alignment_assumption add_overflow sub_overflow mul_overflow " +
  "negate_overflow divrem_overflow shift_out_of_bounds out_of_bounds local_out_of_bounds " +
  "vla_bound_not_positive float_cast_overflow load_invalid_value invalid_builtin " +
  "invalid_objc_cast function_type_mismatch implicit_conversion pointer_overflow cfi_check_fail";

for (const name of recoverableChecks.split(" ")) {
  void test(`preserves full and minimal UBSan handlers for ${name}`, () => {
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__ubsan_handle_${name}`), "UBSan");
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__ubsan_handle_${name}_abort`), "UBSan");
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__ubsan_handle_${name}_minimal`), "UBSan minimal");
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__ubsan_handle_${name}_minimal_abort`), "UBSan minimal");
  });
}

void test("preserves UBSan handlers whose spelling or recovery differs between runtimes", () => {
  for (const name of ["type_mismatch_v1", "nonnull_arg", "nonnull_return_v1", "nullability_arg",
    "nullability_return_v1", "dynamic_type_cache_miss"]) {
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__ubsan_handle_${name}`), "UBSan");
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__ubsan_handle_${name}_abort`), "UBSan");
  }
  for (const name of ["type_mismatch", "nonnull_arg", "nonnull_return", "nullability_arg",
    "nullability_return"]) {
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__ubsan_handle_${name}_minimal`), "UBSan minimal");
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__ubsan_handle_${name}_minimal_abort`), "UBSan minimal");
  }
  for (const name of ["builtin_unreachable", "missing_return"]) {
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__ubsan_handle_${name}`), "UBSan");
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__ubsan_handle_${name}_minimal`), "UBSan minimal");
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__ubsan_handle_${name}_abort`), undefined);
    assert.equal(SANITIZER_ABI_SYMBOLS.get(`__ubsan_handle_${name}_minimal_abort`), undefined);
  }
});
