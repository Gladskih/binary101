"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  PE32_PLUS_POINTER_BYTES,
  type PePointerBytes
} from "../../../../../analyzers/pe/load-config/reference-reader.js";
import { parseLoadConfigReferences } from "../../../../../analyzers/pe/load-config/references.js";
import { createPeLoadConfigResult } from "../../../../../analyzers/pe/load-config/result.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const IMAGE_BASE = 0x140000000n;

const splitTableRvaToOffset = (rva: number): number | null => {
  if (rva >= 0x100 && rva < 0x106) return 0x20 + rva - 0x100;
  if (rva >= 0x106 && rva < 0x118) return 0x40 + rva - 0x106;
  return null;
};

const createMultiWindowLockPrefixTable = (): Uint8Array => {
  // 8,200 pointers exceed the production reader's documented 64-KiB window.
  const pointerCount = 8_200;
  const bytes = new Uint8Array(0x40 + (pointerCount + 1) * 8);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < pointerCount; index += 1) {
    view.setBigUint64(0x40 + index * 8, IMAGE_BASE + BigInt(index + 1), true);
  }
  return bytes;
};

// Referenced fixture layouts follow the Windows SDK structures and LLVM CHPE definitions.
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/Object/COFF.h
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64

const parseReferences = async (
  bytes: Uint8Array,
  configure: () => ReturnType<typeof createPeLoadConfigResult>,
  pointerBytes: PePointerBytes = PE32_PLUS_POINTER_BYTES
) => parseLoadConfigReferences(
  new MockFile(bytes, "load-config-references.bin"),
  [],
  bytes.length,
  value => value,
  IMAGE_BASE,
  pointerBytes,
  configure()
);

void test("parseLoadConfigReferences reads the complete null-terminated LockPrefixTable", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0x40, IMAGE_BASE + 0x100n, true);
  view.setBigUint64(0x48, IMAGE_BASE + 0x180n, true);

  const references = await parseReferences(bytes, () => {
    const loadConfig = createPeLoadConfigResult();
    loadConfig.LockPrefixTable = IMAGE_BASE + 0x40n;
    return loadConfig;
  });

  assert.deepEqual(references.lockPrefixTable?.values, [IMAGE_BASE + 0x100n, IMAGE_BASE + 0x180n]);
  assert.equal(references.lockPrefixTable?.terminated, true);
});

void test("parseLoadConfigReferences scans every bounded I/O window before the terminator", async () => {
  const bytes = createMultiWindowLockPrefixTable();
  const references = await parseReferences(bytes, () => {
    const loadConfig = createPeLoadConfigResult();
    loadConfig.LockPrefixTable = IMAGE_BASE + 0x40n;
    return loadConfig;
  });
  assert.equal(references.lockPrefixTable?.values.length, 8_200);
  assert.equal(references.lockPrefixTable?.values[0], IMAGE_BASE + 1n);
  assert.equal(references.lockPrefixTable?.values.at(-1), IMAGE_BASE + 8_200n);
  assert.equal(references.lockPrefixTable?.terminated, true);
  assert.deepEqual(references.warnings, undefined);
});

void test("parseLoadConfigReferences reports a LockPrefixTable that consumes its mapped span", async () => {
  const bytes = new Uint8Array(0x48).fill(0);
  new DataView(bytes.buffer).setBigUint64(0x40, IMAGE_BASE + 0x100n, true);

  const references = await parseReferences(bytes, () => {
    const loadConfig = createPeLoadConfigResult();
    loadConfig.LockPrefixTable = IMAGE_BASE + 0x40n;
    return loadConfig;
  });

  assert.equal(references.lockPrefixTable?.terminated, false);
  assert.ok(references.warnings?.some(warning => warning.includes("end of its raw-mapped region")));
});

void test("parseLoadConfigReferences dereferences documented loader pointer slots", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0x40, IMAGE_BASE + 0x200n, true);
  view.setBigUint64(0x48, IMAGE_BASE + 0x300n, true);

  const references = await parseReferences(bytes, () => {
    const loadConfig = createPeLoadConfigResult();
    loadConfig.GuardCFCheckFunctionPointer = IMAGE_BASE + 0x40n;
    loadConfig.GuardXFGDispatchFunctionPointer = IMAGE_BASE + 0x48n;
    return loadConfig;
  });

  assert.equal(references.pointerSlots?.GuardCFCheckFunctionPointer?.value, IMAGE_BASE + 0x200n);
  assert.equal(references.pointerSlots?.GuardXFGDispatchFunctionPointer?.value, IMAGE_BASE + 0x300n);
});

void test("parseLoadConfigReferences follows VolatileMetadataPointer and preserves opaque fields", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0x40, 24, true);
  view.setUint16(0x44, 1, true);
  view.setUint16(0x46, 1, true);

  const references = await parseReferences(bytes, () => {
    const loadConfig = createPeLoadConfigResult();
    loadConfig.VolatileMetadataPointer = IMAGE_BASE + 0x40n;
    loadConfig.EditList = IMAGE_BASE + 0x60n;
    loadConfig.UmaFunctionPointers = IMAGE_BASE + 0x70n;
    return loadConfig;
  });

  assert.equal(references.volatileMetadata?.minimumVersion, 1);
  assert.deepEqual(references.opaque?.map(reference => reference.name), ["EditList", "UmaFunctionPointers"]);
  assert.deepEqual(references.opaque?.map(reference => reference.reason), [
    "Reserved for use by the system; no target layout is published.",
    "No table layout, element count, or terminator is published."
  ]);
});

void test("parseLoadConfigReferences dispatches every structured reference parser", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0x20, 0x1234n, true);
  view.setUint32(0x40, 1, true);
  view.setUint32(0xa0, 80, true);
  view.setUint32(0x100, 1, true);
  view.setUint32(0x104, 20, true);
  view.setUint32(0x140, 24, true);
  const references = await parseReferences(bytes, () => {
    const loadConfig = createPeLoadConfigResult();
    loadConfig.SecurityCookie = IMAGE_BASE + 0x20n;
    loadConfig.CHPEMetadataPointer = IMAGE_BASE + 0x40n;
    loadConfig.EnclaveConfigurationPointer = IMAGE_BASE + 0xa0n;
    loadConfig.HotPatchTableOffset = 0x100;
    loadConfig.VolatileMetadataPointer = IMAGE_BASE + 0x140n;
    return loadConfig;
  });

  assert.equal(references.securityCookie?.value, 0x1234n);
  assert.equal(references.chpeMetadata?.kind, "arm64ec");
  assert.equal(references.enclaveConfiguration?.size, 80);
  assert.equal(references.hotPatch?.version, 1);
  assert.equal(references.volatileMetadata?.size, 24);
});

void test("parseLoadConfigReferences omits absent data and reports invalid LockPrefixTable pointers", async () => {
  const empty = await parseReferences(new Uint8Array(0x40), createPeLoadConfigResult);
  const invalid = await parseReferences(new Uint8Array(0x40), () => {
    const loadConfig = createPeLoadConfigResult();
    loadConfig.LockPrefixTable = IMAGE_BASE - 1n;
    loadConfig.GuardCFCheckFunctionPointer = IMAGE_BASE + 0x100n;
    return loadConfig;
  });
  const invalidCookie = await parseReferences(new Uint8Array(0x40), () => {
    const loadConfig = createPeLoadConfigResult();
    loadConfig.SecurityCookie = IMAGE_BASE - 1n;
    return loadConfig;
  });
  const unmapped = await parseReferences(new Uint8Array(0x40), () => {
    const loadConfig = createPeLoadConfigResult();
    loadConfig.LockPrefixTable = IMAGE_BASE + 0x100n;
    return loadConfig;
  });

  assert.deepEqual(empty, {});
  assert.ok(invalid.warnings?.some(warning => warning.includes("not a valid VA")));
  assert.ok(invalid.warnings?.some(warning => warning.includes("LockPrefixTable pointer")));
  assert.ok(invalidCookie.warnings?.some(warning => warning.includes("SecurityCookie pointer")));
  assert.ok(invalid.notes?.some(note => note.includes("GuardCFCheckFunctionPointer RVA")));
  assert.ok(unmapped.notes?.some(note => note.includes("LockPrefixTable RVA")));
});

void test("parseLoadConfigReferences reports a short LockPrefixTable read", async () => {
  const bytes = new Uint8Array(0x48);
  new DataView(bytes.buffer).setBigUint64(0x40, IMAGE_BASE + 0x100n, true);
  const file = new MockFile(bytes);
  const loadConfig = createPeLoadConfigResult();
  loadConfig.LockPrefixTable = IMAGE_BASE + 0x40n;
  const references = await parseLoadConfigReferences(
    {
      size: file.size,
      read: (offset, size) => offset === 0x40
        ? Promise.resolve(new DataView(bytes.buffer, 0x40, size / 2))
        : file.read(offset, size),
      readBytes: (offset, size) => file.readBytes(offset, size)
    },
    [],
    bytes.length,
    rva => rva,
    IMAGE_BASE,
    PE32_PLUS_POINTER_BYTES,
    loadConfig
  );
  assert.deepEqual(references.warnings, ["LOAD_CONFIG: LockPrefixTable is truncated."]);
  assert.equal(references.lockPrefixTable?.terminated, false);
});

void test("parseLoadConfigReferences reads a pointer split across adjacent RVA sections", async () => {
  const bytes = new Uint8Array(0x60);
  const pointer = new Uint8Array(8);
  new DataView(pointer.buffer).setBigUint64(0, IMAGE_BASE + 0x200n, true);
  bytes.set(pointer.subarray(0, 6), 0x20);
  bytes.set(pointer.subarray(6), 0x40);
  const loadConfig = createPeLoadConfigResult();
  loadConfig.LockPrefixTable = IMAGE_BASE + 0x100n;
  const sections = [{
    name: { kind: "inline" as const, value: ".one" }, virtualAddress: 0x100,
    virtualSize: 6, sizeOfRawData: 6, pointerToRawData: 0x20, characteristics: 0
  }, {
    name: { kind: "inline" as const, value: ".two" }, virtualAddress: 0x106,
    virtualSize: 18, sizeOfRawData: 18, pointerToRawData: 0x40, characteristics: 0
  }];
  const references = await parseLoadConfigReferences(
    new MockFile(bytes), sections, 0, splitTableRvaToOffset,
    IMAGE_BASE, PE32_PLUS_POINTER_BYTES, loadConfig
  );
  assert.deepEqual(references.lockPrefixTable?.values, [IMAGE_BASE + 0x200n]);
  assert.equal(references.lockPrefixTable?.terminated, true);
  assert.deepEqual(references.warnings, undefined);
});
