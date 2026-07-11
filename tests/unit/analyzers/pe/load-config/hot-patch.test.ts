"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseHotPatchInfo } from "../../../../../analyzers/pe/load-config/hot-patch.js";
import { createPeRvaMapping } from "../../../../../analyzers/pe/load-config/reference-reader.js";
import { expectDefined } from "../../../../helpers/expect-defined.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const INFO_RVA = 0x40;
const LIST_OFFSET = 0x40;

// Fixture layouts mirror Windows SDK 10.0.26100.0 winnt.h and the table-relative list recovered
// by Signal Labs: https://github.com/Signal-Labs/Hotpatching_PoC/blob/main/hotpatch_poc/src/main.rs
const createInfo = (version: number, size: number, byteLength = 0x300): Uint8Array => {
  const bytes = new Uint8Array(byteLength);
  const view = new DataView(bytes.buffer);
  view.setUint32(INFO_RVA, version, true);
  view.setUint32(INFO_RVA + 4, size, true);
  return bytes;
};

const setList = (bytes: Uint8Array, offsets: number[]): void => {
  const view = new DataView(bytes.buffer);
  view.setUint32(INFO_RVA + 12, LIST_OFFSET, true);
  view.setUint32(INFO_RVA + 16, offsets.length, true);
  offsets.forEach((offset, index) => view.setUint32(INFO_RVA + LIST_OFFSET + index * 4, offset, true));
};

const parseInfo = async (bytes: Uint8Array) => {
  const warnings: string[] = [];
  const notes: string[] = [];
  const info = await parseHotPatchInfo(
    new MockFile(bytes, "hot-patch.bin"),
    createPeRvaMapping(bytes.length, [], bytes.length, value => value),
    warnings,
    notes,
    INFO_RVA
  );
  return { info, warnings, notes };
};

void test("parseHotPatchInfo decodes v4 offsets, base records, and integrity hashes", async () => {
  const bytes = createInfo(4, 0x220);
  const view = new DataView(bytes.buffer);
  view.setUint32(INFO_RVA + 8, 17, true);
  view.setUint32(INFO_RVA + 20, 0x01020304, true);
  view.setUint32(INFO_RVA + 24, 0x02030405, true);
  view.setUint32(INFO_RVA + 28, 0x03040506, true);
  view.setUint32(INFO_RVA + 32, 0x04050607, true);
  setList(bytes, [0x50, 0x70]);
  view.setUint32(INFO_RVA + 0x50, 21, true);
  view.setUint32(INFO_RVA + 0x54, 0x01020304, true);
  view.setUint32(INFO_RVA + 0x58, 0x02030405, true);
  view.setUint32(INFO_RVA + 0x5c, 0x03040506, true);
  view.setUint32(INFO_RVA + 0x60, 0x100, true);
  view.setUint32(INFO_RVA + 0x64, 52, true);
  view.setUint32(INFO_RVA + 0x68, 0x180, true);
  view.setUint32(INFO_RVA + 0x6c, 0x04050607, true);
  view.setUint32(INFO_RVA + 0x70, 22, true);
  view.setUint32(INFO_RVA + 0x8c, 0x08090a0b, true);
  bytes.fill(0xaa, INFO_RVA + 0x100, INFO_RVA + 0x120);
  bytes.fill(0xbb, INFO_RVA + 0x120, INFO_RVA + 0x134);
  const { info, warnings, notes } = await parseInfo(bytes);
  const hotPatch = expectDefined(info);
  const base = expectDefined(hotPatch.baseImages[0]);
  assert.equal(hotPatch.sequenceNumber, 17);
  assert.equal(hotPatch.baseImageListOffset, LIST_OFFSET);
  assert.equal(hotPatch.bufferOffset, 0x01020304);
  assert.equal(hotPatch.extraPatchSize, 0x02030405);
  assert.equal(hotPatch.minSequenceNumber, 0x03040506);
  assert.equal(hotPatch.flags, 0x04050607);
  assert.deepEqual(base, {
    offset: 0x50, sequenceNumber: 21, flags: 0x01020304,
    originalTimeDateStamp: 0x02030405, originalCheckSum: 0x03040506,
    codeIntegrityInfoOffset: 0x100, codeIntegritySize: 52, patchTableOffset: 0x180,
    bufferOffset: 0x04050607,
    codeIntegrityHashes: {
      sha256: Array.from({ length: 32 }, () => 0xaa),
      sha1: Array.from({ length: 20 }, () => 0xbb)
    }
  });
  assert.equal(hotPatch.baseImages[1]?.sequenceNumber, 22);
  assert.equal(hotPatch.baseImages[1]?.bufferOffset, 0x08090a0b);
  assert.deepEqual(warnings, []);
  assert.deepEqual(notes, [
    "LOAD_CONFIG: HotPatch base image 0 PatchTable framing is unpublished; its offset is retained."
  ]);
});

void test("parseHotPatchInfo uses v1 field and base-record sizes", async () => {
  // 0x60 ends exactly after the 28-byte v1 base; a v2-sized read would leave the table.
  const bytes = createInfo(1, 0x60);
  setList(bytes, [0x44]);
  new DataView(bytes.buffer).setUint32(INFO_RVA + 0x44, 9, true);
  const { info, warnings, notes } = await parseInfo(bytes);
  assert.equal(info?.bufferOffset, undefined);
  assert.equal(info?.extraPatchSize, undefined);
  assert.equal(info?.baseImages[0]?.sequenceNumber, 9);
  assert.equal(info?.baseImages[0]?.bufferOffset, undefined);
  assert.deepEqual(warnings, []);
  assert.deepEqual(notes, []);
});

void test("parseHotPatchInfo rejects truncated and version-undersized headers", async () => {
  const truncated = await parseInfo(new Uint8Array(0x50));
  const undersized = await parseInfo(createInfo(4, 20));
  const truncatedV2 = await parseInfo(createInfo(2, 24, INFO_RVA + 20));
  assert.equal(truncated.info, null);
  assert.deepEqual(truncated.warnings, [
    "LOAD_CONFIG: HotPatchTableOffset IMAGE_HOT_PATCH_INFO is truncated or maps outside file data."
  ]);
  assert.equal(undersized.info, null);
  assert.deepEqual(undersized.warnings, [
    "LOAD_CONFIG: HotPatch version 4 Size 0x14 is too small."
  ]);
  assert.deepEqual(truncatedV2.warnings, [
    "LOAD_CONFIG: HotPatch declared Size extends beyond mapped raw file data.",
    "LOAD_CONFIG: HotPatchTableOffset IMAGE_HOT_PATCH_INFO is truncated or maps outside file data."
  ]);
});

void test("parseHotPatchInfo reports missing and truncated offset lists", async () => {
  const missingBytes = createInfo(4, 0x80);
  new DataView(missingBytes.buffer).setUint32(INFO_RVA + 16, 1, true);
  const truncatedBytes = createInfo(4, LIST_OFFSET + 6);
  setList(truncatedBytes, [0x48, 0x50]);
  const missing = await parseInfo(missingBytes);
  const truncated = await parseInfo(truncatedBytes);
  assert.ok(missing.warnings.some(warning => warning.includes("offset is zero")));
  assert.ok(truncated.warnings.some(warning => warning.includes("leaves the declared HotPatch table")));
});

void test("parseHotPatchInfo reports base records outside the declared table", async () => {
  const bytes = createInfo(2, 0x80);
  setList(bytes, [0x70]);
  const { info, warnings } = await parseInfo(bytes);
  assert.deepEqual(info?.baseImages, []);
  assert.deepEqual(warnings, [
    "LOAD_CONFIG: HotPatch base image 0 leaves the declared HotPatch table."
  ]);
});

void test("parseHotPatchInfo reports incomplete and extended hash records", async () => {
  const incompleteBytes = createInfo(2, 0x180);
  setList(incompleteBytes, [0x50]);
  const incompleteView = new DataView(incompleteBytes.buffer);
  incompleteView.setUint32(INFO_RVA + 0x60, 0x100, true);
  incompleteView.setUint32(INFO_RVA + 0x64, 51, true);
  const extendedBytes = incompleteBytes.slice();
  const extendedView = new DataView(extendedBytes.buffer);
  extendedView.setUint32(INFO_RVA + 4, 0x13c, true);
  extendedView.setUint32(INFO_RVA + 0x64, 60, true);
  const incomplete = await parseInfo(incompleteBytes);
  const extended = await parseInfo(extendedBytes);
  assert.ok(incomplete.warnings.some(warning => warning.includes("incomplete IMAGE_HOT_PATCH_HASHES")));
  assert.deepEqual(extended.notes, [
    "LOAD_CONFIG: HotPatch base image 0 hashes have 8 extension bytes."
  ]);
  assert.deepEqual(extended.warnings, []);
});

void test("parseHotPatchInfo validates the complete declared hash range", async () => {
  const bytes = createInfo(2, 0x114);
  setList(bytes, [0x50]);
  const view = new DataView(bytes.buffer);
  // The known 52-byte hashes end exactly at Size, but the declared 60 bytes do not.
  view.setUint32(INFO_RVA + 0x60, 0xe0, true);
  view.setUint32(INFO_RVA + 0x64, 60, true);
  const { info, warnings } = await parseInfo(bytes);
  assert.equal(info?.baseImages[0]?.codeIntegrityHashes?.sha256.length, 32);
  assert.deepEqual(warnings, [
    "LOAD_CONFIG: HotPatch base image 0 hashes leave the declared HotPatch table."
  ]);
});

void test("parseHotPatchInfo distinguishes absent and invalid table-relative references", async () => {
  const absentBytes = createInfo(2, 0x100);
  setList(absentBytes, [0x50]);
  const invalidBytes = absentBytes.slice();
  const invalidView = new DataView(invalidBytes.buffer);
  invalidView.setUint32(INFO_RVA + 0x60, 0xf0, true);
  invalidView.setUint32(INFO_RVA + 0x64, 52, true);
  invalidView.setUint32(INFO_RVA + 0x68, 0x100, true);
  const absent = await parseInfo(absentBytes);
  const invalid = await parseInfo(invalidBytes);
  assert.deepEqual(absent.warnings, []);
  assert.ok(invalid.warnings.some(warning => warning.includes("hashes leaves")));
  assert.ok(invalid.warnings.some(warning => warning.includes("PatchTable leaves")));
});

void test("parseHotPatchInfo distinguishes zero hash offsets from zero hash sizes", async () => {
  const missingOffsetBytes = createInfo(2, 0x100);
  setList(missingOffsetBytes, [0x50]);
  new DataView(missingOffsetBytes.buffer).setUint32(INFO_RVA + 0x64, 52, true);
  const zeroSizeBytes = missingOffsetBytes.slice();
  const zeroSizeView = new DataView(zeroSizeBytes.buffer);
  zeroSizeView.setUint32(INFO_RVA + 0x60, 0x80, true);
  zeroSizeView.setUint32(INFO_RVA + 0x64, 0, true);
  const missingOffset = await parseInfo(missingOffsetBytes);
  const zeroSize = await parseInfo(zeroSizeBytes);
  assert.ok(missingOffset.warnings.some(warning => warning.includes("incomplete")));
  assert.ok(zeroSize.warnings.some(warning => warning.includes("incomplete")));
});

void test("parseHotPatchInfo selects v2, v3, and unknown-version fields", async () => {
  const v2Bytes = createInfo(2, 0x80);
  const v2View = new DataView(v2Bytes.buffer);
  v2View.setUint32(INFO_RVA + 20, 0x01020304, true);
  setList(v2Bytes, [0x44]);
  v2View.setUint32(INFO_RVA + 0x60, 0x05060708, true);
  const v3Bytes = createInfo(3, 0x80);
  const v3View = new DataView(v3Bytes.buffer);
  v3View.setUint32(INFO_RVA + 20, 0x01020304, true);
  v3View.setUint32(INFO_RVA + 24, 0x02030405, true);
  const unknownBytes = createInfo(5, 0x80);
  const v2 = await parseInfo(v2Bytes);
  const v3 = await parseInfo(v3Bytes);
  const unknown = await parseInfo(unknownBytes);
  assert.equal(v2.info?.bufferOffset, 0x01020304);
  assert.equal(v2.info?.extraPatchSize, undefined);
  assert.equal(v2.info?.baseImages[0]?.bufferOffset, 0x05060708);
  assert.equal(v3.info?.extraPatchSize, 0x02030405);
  assert.equal(unknown.info?.minSequenceNumber, 0);
  assert.deepEqual(unknown.notes, [
    "LOAD_CONFIG: HotPatch version 5 parsed using the known v4 fields."
  ]);
});

void test("parseHotPatchInfo reads aliased v1 base records and its header only once", async () => {
  const bytes = createInfo(1, 0x80);
  setList(bytes, [0x48, 0x48]);
  const file = new MockFile(bytes, "hot-patch.bin");
  const readOffsets: number[] = [];
  const warnings: string[] = [];
  const info = await parseHotPatchInfo(
    {
      size: file.size,
      read: (offset, size) => {
        readOffsets.push(offset);
        return file.read(offset, size);
      },
      readBytes: (offset, size) => file.readBytes(offset, size)
    },
    createPeRvaMapping(bytes.length, [], bytes.length, value => value),
    warnings,
    [],
    INFO_RVA
  );
  assert.equal(info?.baseImages.length, 2);
  assert.equal(readOffsets.filter(offset => offset === INFO_RVA).length, 1);
  assert.equal(readOffsets.filter(offset => offset === INFO_RVA + 0x48).length, 1);
  assert.deepEqual(warnings, []);
});

void test("parseHotPatchInfo warns about version zero and a truncated declared span", async () => {
  const versionZero = await parseInfo(createInfo(0, 20));
  const truncatedSpan = await parseInfo(createInfo(1, 0x80, 0x80));
  assert.deepEqual(versionZero.warnings, ["LOAD_CONFIG: HotPatch version 0 is invalid."]);
  assert.ok(truncatedSpan.warnings.some(warning => warning.includes("declared Size extends")));
});

void test("parseHotPatchInfo rejects a table-relative RVA that overflows the PE address space", async () => {
  const bytes = createInfo(1, 0x80);
  setList(bytes, [0x44]);
  const warnings: string[] = [];
  const info = await parseHotPatchInfo(
    new MockFile(bytes, "hot-patch.bin"),
    {
      offset: () => INFO_RVA,
      rawSpan: () => [INFO_RVA, bytes.length - INFO_RVA],
      rawChunks: (_rva, size) => [[INFO_RVA, size]]
    },
    warnings,
    [],
    0xffff_ffc0
  );
  assert.deepEqual(info?.baseImages, []);
  assert.deepEqual(warnings, [
    "LOAD_CONFIG: HotPatch BaseImageList leaves the declared HotPatch table."
  ]);
});
