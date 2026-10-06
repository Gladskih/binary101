import type { SanitizerTool } from "./types.js";

const addNames = (catalog: Map<string, SanitizerTool>, tool: SanitizerTool,
  prefix: string, names: readonly string[]): void => {
  for (const name of names) catalog.set(prefix + name, tool);
};

const addMemoryInterfaces = (catalog: Map<string, SanitizerTool>): void => {
  // compiler-rt/lib/asan/asan_interface_internal.h and asan_interface.inc:
  // https://github.com/llvm/llvm-project/tree/main/compiler-rt/lib/asan
  addNames(catalog, "ASan", "__asan_", ["init", "register_globals", "register_elf_globals",
    "register_image_globals", "unregister_globals", "unregister_elf_globals"]);
  for (const size of ["1", "2", "4", "8", "16", "N"]) {
    for (const operation of ["load", "store"]) {
      addNames(catalog, "ASan", "__asan_", [`${operation}${size}`,
        `${operation}${size}_noabort`, `report_${operation}${size === "N" ? "_n" : size}`,
        `report_${operation}${size === "N" ? "_n" : size}_noabort`]);
    }
  }
  // https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/msan/msan_interface_internal.h
  addNames(catalog, "MSan", "__msan_", ["init", "warning", "warning_noreturn",
    "warning_with_origin", "warning_with_origin_noreturn", "maybe_warning_1",
    "maybe_warning_2", "maybe_warning_4", "maybe_warning_8", "chain_origin"]);
  // https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/hwasan/hwasan_interface_internal.h
  // tag_mismatch_v2: compiler-rt/lib/hwasan/hwasan_tag_mismatch_aarch64.S in the same project.
  addNames(catalog, "HWASan", "__hwasan_", ["init", "tag_mismatch", "tag_mismatch_v2",
    "tag_memory", "generate_tag", "loadN", "storeN"]);
  for (const size of ["1", "2", "4", "8", "16"]) {
    addNames(catalog, "HWASan", "__hwasan_", [`load${size}`, `store${size}`]);
  }
};

const addThreadInterfaces = (catalog: Map<string, SanitizerTool>): void => {
  // https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/tsan/rtl/tsan_interface.h
  addNames(catalog, "TSan", "__tsan_", ["init", "func_entry", "func_exit",
    "read_range", "write_range", "vptr_read", "vptr_update"]);
  for (const size of ["1", "2", "4", "8", "16"]) {
    addNames(catalog, "TSan", "__tsan_", [`read${size}`, `write${size}`,
      `read${size}_pc`, `write${size}_pc`]);
  }
  // Validated Go function metadata is handled separately from native symbol names.
  // https://github.com/golang/go/blob/master/src/runtime/race.go
};

const addUndefinedInterfaces = (catalog: Map<string, SanitizerTool>): void => {
  // Full ABI: https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/ubsan/ubsan_handlers.h
  // dynamic_type_cache_miss: compiler-rt/lib/ubsan/ubsan_handlers_cxx.h in the same project.
  // Minimal ABI differs (type_mismatch, not type_mismatch_v1):
  // https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/ubsan_minimal/ubsan_minimal_handlers.cpp
  const shared = ["alignment_assumption", "add_overflow", "sub_overflow", "mul_overflow",
    "negate_overflow", "divrem_overflow", "shift_out_of_bounds", "out_of_bounds",
    "vla_bound_not_positive", "float_cast_overflow", "load_invalid_value",
    "invalid_builtin", "invalid_objc_cast", "function_type_mismatch",
    "pointer_overflow", "cfi_check_fail", "local_out_of_bounds", "implicit_conversion"];
  addNames(catalog, "UBSan", "__ubsan_handle_", ["builtin_unreachable", "missing_return"]);
  addNames(catalog, "UBSan minimal", "__ubsan_handle_",
    ["builtin_unreachable_minimal", "missing_return_minimal"]);
  for (const name of [...shared, "type_mismatch_v1", "nonnull_arg", "nonnull_return_v1",
    "nullability_arg", "nullability_return_v1", "dynamic_type_cache_miss"]) {
    addNames(catalog, "UBSan", "__ubsan_handle_", [name, `${name}_abort`]);
  }
  for (const name of [...shared, "type_mismatch", "nonnull_arg", "nonnull_return",
    "nullability_arg", "nullability_return"]) {
    addNames(catalog, "UBSan minimal", "__ubsan_handle_",
      [`${name}_minimal`, `${name}_minimal_abort`]);
  }
};

const addOtherInterfaces = (catalog: Map<string, SanitizerTool>): void => {
  // https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/sanitizer/lsan_interface.h
  // __lsan_init: compiler-rt/lib/lsan/lsan.cpp; an ASan runtime may bundle LSan definitions.
  addNames(catalog, "LSan", "__lsan_", ["init", "do_leak_check", "do_recoverable_leak_check"]);
  // https://github.com/llvm/llvm-project/blob/main/llvm/lib/Transforms/Instrumentation/DataFlowSanitizer.cpp
  addNames(catalog, "DFSan", "__dfsan_", ["union_load", "load_label_and_origin",
    "chain_origin", "set_label", "unimplemented"]);
  // https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/rtsan/rtsan.cpp
  addNames(catalog, "RTSan", "__rtsan_", ["init", "realtime_enter", "realtime_exit",
    "notify_blocking_call"]);
  // https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/tysan/tysan.cpp
  addNames(catalog, "TySan", "__tysan_", ["init", "check"]);
  // https://clang.llvm.org/docs/SanitizerCoverage.html
  addNames(catalog, "SanitizerCoverage", "__sanitizer_cov_", ["trace_pc", "trace_pc_guard",
    "trace_pc_guard_init", "8bit_counters_init", "bool_flag_init", "pcs_init",
    "trace_cmp1", "trace_cmp2", "trace_cmp4", "trace_cmp8", "trace_const_cmp1",
    "trace_const_cmp2", "trace_const_cmp4", "trace_const_cmp8", "trace_switch"]);
};

const createAbiCatalog = (): ReadonlyMap<string, SanitizerTool> => {
  // Local construction avoids testing every regex against every file symbol.
  const catalog = new Map<string, SanitizerTool>();
  addMemoryInterfaces(catalog);
  addThreadInterfaces(catalog);
  addUndefinedInterfaces(catalog);
  addOtherInterfaces(catalog);
  return catalog;
};

export const SANITIZER_ABI_SYMBOLS = createAbiCatalog();
