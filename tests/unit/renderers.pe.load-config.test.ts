"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderLoadConfig } from "../../renderers/pe/load-config.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { PeLoadConfig } from "../../analyzers/pe/load-config.js";

const createLoadConfig = (): PeLoadConfig => ({
  Size: 0,
  TimeDateStamp: 0,
  Major: 0,
  Minor: 0,
  GlobalFlagsClear: 0,
  GlobalFlagsSet: 0,
  CriticalSectionDefaultTimeout: 0,
  DeCommitFreeBlockThreshold: 0n,
  DeCommitTotalFreeThreshold: 0n,
  LockPrefixTable: 0n,
  MaximumAllocationSize: 0n,
  VirtualMemoryThreshold: 0n,
  ProcessHeapFlags: 0,
  ProcessAffinityMask: 0n,
  CSDVersion: 0,
  DependentLoadFlags: 0,
  EditList: 0n,
  SecurityCookie: 0n,
  SEHandlerTable: 0n,
  SEHandlerCount: 0,
  GuardCFCheckFunctionPointer: 0n,
  GuardCFDispatchFunctionPointer: 0n,
  GuardCFFunctionTable: 0n,
  GuardCFFunctionCount: 0,
  CodeIntegrity: { Flags: 0, Catalog: 0, CatalogOffset: 0, Reserved: 0 },
  GuardAddressTakenIatEntryTable: 0n,
  GuardAddressTakenIatEntryCount: 0,
  GuardLongJumpTargetTable: 0n,
  GuardLongJumpTargetCount: 0,
  DynamicValueRelocTable: 0n,
  CHPEMetadataPointer: 0n,
  GuardRFFailureRoutine: 0n,
  GuardRFFailureRoutineFunctionPointer: 0n,
  DynamicValueRelocTableOffset: 0,
  DynamicValueRelocTableSection: 0,
  Reserved2: 0,
  GuardRFVerifyStackPointerFunctionPointer: 0n,
  HotPatchTableOffset: 0,
  Reserved3: 0,
  EnclaveConfigurationPointer: 0n,
  VolatileMetadataPointer: 0n,
  GuardEHContinuationTable: 0n,
  GuardEHContinuationCount: 0,
  GuardXFGCheckFunctionPointer: 0n,
  GuardXFGDispatchFunctionPointer: 0n,
  GuardXFGTableDispatchFunctionPointer: 0n,
  CastGuardOsDeterminedFailureMode: 0n,
  GuardMemcpyFunctionPointer: 0n,
  UmaFunctionPointers: 0n,
  GuardFlags: 0
});

void test("renderLoadConfig renders GuardFlags names and CFG function-table entry size", () => {
  const pe = {
    opt: { isPlus: false, ImageBase: 0x400000n },
    loadcfg: {
      ...createLoadConfig(),
      GuardFlags: 0x30417500,
      CodeIntegrity: { Flags: 0, Catalog: 0, CatalogOffset: 0, Reserved: 0 }
    }
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderLoadConfig(pe, out);
  const html = out.join("");

  assert.ok(html.includes("CF_INSTRUMENTED"));
  assert.ok(html.includes("CF_FUNCTION_TABLE_PRESENT"));
  assert.ok(html.includes("CF_EXPORT_SUPPRESSION_INFO_PRESENT"));
  assert.ok(html.includes("CF_LONGJUMP_TABLE_PRESENT"));
  assert.ok(html.includes("PROTECT_DELAYLOAD_IAT"));
  assert.ok(html.includes("DELAYLOAD_IAT_IN_ITS_OWN_SECTION"));
  assert.ok(html.includes("EH_CONTINUATION_TABLE_PRESENT"));
  assert.ok(html.includes("CF_FUNCTION_TABLE_SIZE_7BYTES"));
});
