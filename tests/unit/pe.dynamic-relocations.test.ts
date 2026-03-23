"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseDynamicRelocationsFromLoadConfig32,
  parseDynamicRelocationsFromLoadConfig64
} from "../../analyzers/pe/dynamic-relocations.js";
import type { PeLoadConfig } from "../../analyzers/pe/load-config.js";
import type { PeSection } from "../../analyzers/pe/types.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const makeLoadConfig = (overrides: Partial<PeLoadConfig>): PeLoadConfig => ({
  Size: 0,
  TimeDateStamp: 0,
  Major: 0,
  Minor: 0,
  GlobalFlagsClear: 0,
  GlobalFlagsSet: 0,
  CriticalSectionDefaultTimeout: 0,
  DeCommitFreeBlockThreshold: 0,
  DeCommitTotalFreeThreshold: 0,
  LockPrefixTable: 0,
  MaximumAllocationSize: 0,
  VirtualMemoryThreshold: 0,
  ProcessHeapFlags: 0,
  ProcessAffinityMask: 0,
  CSDVersion: 0,
  DependentLoadFlags: 0,
  EditList: 0,
  SecurityCookie: 0,
  SEHandlerTable: 0,
  SEHandlerCount: 0,
  GuardCFCheckFunctionPointer: 0,
  GuardCFDispatchFunctionPointer: 0,
  GuardCFFunctionTable: 0,
  GuardCFFunctionCount: 0,
  CodeIntegrity: { Flags: 0, Catalog: 0, CatalogOffset: 0, Reserved: 0 },
  GuardAddressTakenIatEntryTable: 0,
  GuardAddressTakenIatEntryCount: 0,
  GuardLongJumpTargetTable: 0,
  GuardLongJumpTargetCount: 0,
  DynamicValueRelocTable: 0,
  CHPEMetadataPointer: 0,
  GuardRFFailureRoutine: 0,
  GuardRFFailureRoutineFunctionPointer: 0,
  DynamicValueRelocTableOffset: 0,
  DynamicValueRelocTableSection: 0,
  Reserved2: 0,
  GuardRFVerifyStackPointerFunctionPointer: 0,
  HotPatchTableOffset: 0,
  Reserved3: 0,
  EnclaveConfigurationPointer: 0,
  VolatileMetadataPointer: 0,
  GuardEHContinuationTable: 0,
  GuardEHContinuationCount: 0,
  GuardXFGCheckFunctionPointer: 0,
  GuardXFGDispatchFunctionPointer: 0,
  GuardXFGTableDispatchFunctionPointer: 0,
  CastGuardOsDeterminedFailureMode: 0,
  GuardMemcpyFunctionPointer: 0,
  UmaFunctionPointers: 0,
  GuardFlags: 0,
  ...overrides
});

const makeSingleSection = (): PeSection[] => [
  {
    name: ".reloc",
    virtualSize: 0x1000,
    virtualAddress: 0,
    sizeOfRawData: 0x1000,
    pointerToRawData: 0,
    characteristics: 0
  }
];

void test("parseDynamicRelocationsFromLoadConfig parses a V1 table referenced by section+offset", async () => {
  const tableOff = 0x80;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tableOff + 0x00, 1, true); // Version
  // Dynamic relocation V1 for PE32 uses 4-byte Symbol + 4-byte BaseRelocSize.
  dv.setUint32(tableOff + 0x04, 0x4c, true); // Size (bytes after header)
  dv.setUint32(tableOff + 0x08, 7, true); // Symbol/type
  dv.setUint32(tableOff + 0x0c, 0x44, true); // BaseRelocSize
  bytes.fill(0xaa, tableOff + 0x10, tableOff + 0x10 + 0x44);

  const lc = makeLoadConfig({ DynamicValueRelocTableSection: 1, DynamicValueRelocTableOffset: tableOff });
  const parsed = expectDefined(
    await parseDynamicRelocationsFromLoadConfig32(
      new MockFile(bytes, "dynrel.bin"),
      makeSingleSection(),
      rva => rva,
      0x400000,
      lc
    )
  );

  assert.equal(parsed.version, 1);
  assert.equal(parsed.dataSize, 0x4c);
  assert.equal(parsed.entries.length, 1);
  const entry = expectDefined(parsed.entries[0]);
  assert.equal(entry.kind, "v1");
  if (entry.kind !== "v1") throw new Error("Expected v1 entry.");
  assert.equal(entry.symbol, 7);
  assert.equal(entry.baseRelocSize, 0x44);
  assert.equal(entry.availableBytes, 0x44);
  assert.equal(parsed.warnings?.length ?? 0, 0);
});

void test("parseDynamicRelocationsFromLoadConfig warns when the declared V1 payload is truncated", async () => {
  const tableOff = 0x80;
  const bytes = new Uint8Array(0x94).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tableOff + 0x00, 1, true); // Version
  dv.setUint32(tableOff + 0x04, 0x50, true); // Size (declared)
  dv.setBigUint64(tableOff + 0x08, 7n, true); // Symbol/type
  dv.setUint32(tableOff + 0x10, 0x44, true); // BaseRelocSize (but no bytes available)

  const lc = makeLoadConfig({ DynamicValueRelocTableSection: 1, DynamicValueRelocTableOffset: tableOff });
  const parsed = expectDefined(
    await parseDynamicRelocationsFromLoadConfig64(
      new MockFile(bytes, "dynrel-trunc.bin"),
      makeSingleSection(),
      rva => rva,
      0x140000000,
      lc
    )
  );

  assert.equal(parsed.version, 1);
  assert.ok(parsed.warnings?.some(w => w.toLowerCase().includes("truncated")));
});

void test(
  "parseDynamicRelocationsFromLoadConfig preserves 64-bit V1 symbols for PE32+",
  async () => {
  const tableOff = 0x80;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tableOff + 0x00, 1, true); // Version
  // PE32+ V1 entry header is 8-byte symbol + 4-byte BaseRelocSize, so dataSize is 0x0c here.
  dv.setUint32(tableOff + 0x04, 0x0c, true);
  // 0x0020000000000001n is 2^53 + 1.
  // That is the first unsigned integer JS cannot represent exactly as Number.
  const firstUnsafeSymbol = 0x0020000000000001n;
  // PE32+ stores Symbol as a 64-bit field; values above Number.MAX_SAFE_INTEGER must remain exact.
  dv.setBigUint64(tableOff + 0x08, firstUnsafeSymbol, true);
  dv.setUint32(tableOff + 0x10, 0, true);

  const lc = makeLoadConfig({ DynamicValueRelocTableSection: 1, DynamicValueRelocTableOffset: tableOff });
  const parsed = expectDefined(
    await parseDynamicRelocationsFromLoadConfig64(
      new MockFile(bytes, "dynrel-v1-pe32plus.bin"),
      makeSingleSection(),
      rva => rva,
      0x140000000,
      lc
    )
  );

  assert.equal(parsed.version, 1);
  assert.equal(parsed.entries.length, 1);
  const entry = expectDefined(parsed.entries[0]);
  assert.equal(entry.kind, "v1");
  if (entry.kind !== "v1") throw new Error("Expected v1 entry.");
  assert.equal(BigInt(entry.symbol), firstUnsafeSymbol);
  }
);

void test(
  "parseDynamicRelocationsFromLoadConfig preserves 64-bit V2 symbols for PE32+",
  async () => {
  const tableOff = 0x80;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tableOff + 0x00, 2, true); // Version
  // PE32+ V2 minimum header is 0x18 bytes: 8 bytes of fixed fields + 8-byte symbol + group + flags.
  dv.setUint32(tableOff + 0x04, 0x18, true);
  dv.setUint32(tableOff + 0x08, 0x18, true); // HeaderSize
  dv.setUint32(tableOff + 0x0c, 0, true); // FixupInfoSize
  const secondUnsafeSymbol = 0x0020000000000003n;
  // PE32+ stores Symbol as a 64-bit field; values above Number.MAX_SAFE_INTEGER must remain exact.
  dv.setBigUint64(tableOff + 0x10, secondUnsafeSymbol, true);
  dv.setUint32(tableOff + 0x18, 7, true);
  dv.setUint32(tableOff + 0x1c, 0x55, true);

  const lc = makeLoadConfig({ DynamicValueRelocTableSection: 1, DynamicValueRelocTableOffset: tableOff });
  const parsed = expectDefined(
    await parseDynamicRelocationsFromLoadConfig64(
      new MockFile(bytes, "dynrel-v2-pe32plus.bin"),
      makeSingleSection(),
      rva => rva,
      0x140000000,
      lc
    )
  );

  assert.equal(parsed.version, 2);
  assert.equal(parsed.entries.length, 1);
  const entry = expectDefined(parsed.entries[0]);
  assert.equal(entry.kind, "v2");
  if (entry.kind !== "v2") throw new Error("Expected v2 entry.");
  assert.equal(BigInt(entry.symbol), secondUnsafeSymbol);
  }
);

void test("parseDynamicRelocationsFromLoadConfig warns when a V2 entry header is smaller than the fixed structure size", async () => {
  const tableOff = 0x80;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tableOff + 0x00, 2, true); // Version 2
  // IMAGE_DYNAMIC_RELOCATION32_V2 has a fixed 0x14-byte header in winnt.h-compatible layouts.
  dv.setUint32(tableOff + 0x04, 0x14, true);
  // IMAGE_DYNAMIC_RELOCATION32_V2 has a fixed 20-byte header in winnt.h-compatible layouts.
  dv.setUint32(tableOff + 0x08, 0, true);
  dv.setUint32(tableOff + 0x0c, 0, true);
  dv.setUint32(tableOff + 0x10, 7, true);
  dv.setUint32(tableOff + 0x14, 1, true);
  dv.setUint32(tableOff + 0x18, 0, true);

  const lc = makeLoadConfig({ DynamicValueRelocTableSection: 1, DynamicValueRelocTableOffset: tableOff });
  const parsed = expectDefined(
    await parseDynamicRelocationsFromLoadConfig32(
      new MockFile(bytes, "dynrel-v2-small-header.bin"),
      makeSingleSection(),
      rva => rva,
      0x400000,
      lc
    )
  );

  assert.equal(parsed.version, 2);
  assert.ok(parsed.warnings?.some(warning => /header|undersized|invalid/i.test(warning)));
});

void test(
  "parseDynamicRelocationsFromLoadConfig warns on undersized V2 headers even with payload",
  async () => {
  const tableOff = 0x80;
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(tableOff + 0x00, 2, true); // Version 2
  dv.setUint32(tableOff + 0x04, 0x18, true); // Fixed header plus 4-byte payload
  // IMAGE_DYNAMIC_RELOCATION32_V2 has a fixed 0x14-byte header; smaller HeaderSize is malformed.
  dv.setUint32(tableOff + 0x08, 4, true); // HeaderSize
  dv.setUint32(tableOff + 0x0c, 4, true); // FixupInfoSize
  dv.setUint32(tableOff + 0x10, 7, true); // Symbol
  dv.setUint32(tableOff + 0x14, 1, true); // SymbolGroup
  dv.setUint32(tableOff + 0x18, 0, true); // Flags
  dv.setUint32(tableOff + 0x1c, 0x11223344, true); // Payload bytes

  const lc = makeLoadConfig({ DynamicValueRelocTableSection: 1, DynamicValueRelocTableOffset: tableOff });
  const parsed = expectDefined(
    await parseDynamicRelocationsFromLoadConfig32(
      new MockFile(bytes, "dynrel-v2-undersized-header-with-payload.bin"),
      makeSingleSection(),
      rva => rva,
      0x400000,
      lc
    )
  );

  assert.equal(parsed.version, 2);
  assert.ok(parsed.warnings?.some(warning => /header|undersized|invalid/i.test(warning)));
  }
);
