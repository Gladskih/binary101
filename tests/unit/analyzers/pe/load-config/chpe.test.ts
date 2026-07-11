"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseChpeMetadata } from "../../../../../analyzers/pe/load-config/chpe.js";
import type { PeChpeX86Metadata } from "../../../../../analyzers/pe/load-config/reference-types.js";
import {
  createPeRvaMapping,
  PE32_POINTER_BYTES,
  PE32_PLUS_POINTER_BYTES,
  type PePointerBytes
} from "../../../../../analyzers/pe/load-config/reference-reader.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { expectDefined } from "../../../../helpers/expect-defined.js";

const IMAGE_BASE = 0x140000000n;
const METADATA_RVA = 0x40;

// Fixture offsets mirror LLVM COFF CHPE metadata and System Informer IMAGE_CHPE_METADATA_X86.
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/Object/COFF.h
// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntimage.h

const parseMetadata = async (bytes: Uint8Array, pointerBytes: PePointerBytes) => {
  const warnings: string[] = [];
  const notes: string[] = [];
  const metadata = await parseChpeMetadata(
    new MockFile(bytes, "chpe.bin"),
    createPeRvaMapping(bytes.length, [], bytes.length, value => value),
    IMAGE_BASE,
    pointerBytes,
    warnings,
    notes,
    IMAGE_BASE + BigInt(METADATA_RVA)
  );
  return { metadata, warnings, notes };
};

const expectX86Metadata = (metadata: unknown): PeChpeX86Metadata => {
  const value = expectDefined(metadata as PeChpeX86Metadata | null);
  assert.equal(value.kind, "x86");
  return value;
};

void test("parseChpeMetadata decodes the complete ARM64EC v2 prefix and all three tables", async () => {
  const bytes = new Uint8Array(0x400).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(METADATA_RVA, 2, true);
  view.setUint32(METADATA_RVA + 4, 0x100, true);
  view.setUint32(METADATA_RVA + 8, 4, true);
  view.setUint32(METADATA_RVA + 12, 0x120, true);
  view.setUint32(METADATA_RVA + 16, 0x140, true);
  view.setUint32(METADATA_RVA + 20, 0x01020304, true);
  view.setUint32(METADATA_RVA + 24, 0x02030405, true);
  view.setUint32(METADATA_RVA + 28, 0x03040506, true);
  view.setUint32(METADATA_RVA + 32, 0x04050607, true);
  view.setUint32(METADATA_RVA + 36, 0x05060708, true);
  view.setUint32(METADATA_RVA + 40, 0x06070809, true);
  view.setUint32(METADATA_RVA + 44, 0x0708090a, true);
  view.setUint32(METADATA_RVA + 48, 2, true);
  view.setUint32(METADATA_RVA + 52, 2, true);
  view.setUint32(METADATA_RVA + 56, 0x08090a0b, true);
  view.setUint32(METADATA_RVA + 60, 0x090a0b0c, true);
  view.setUint32(METADATA_RVA + 64, 0x180, true);
  view.setUint32(METADATA_RVA + 68, 16, true);
  view.setUint32(METADATA_RVA + 72, 0x0a0b0c0d, true);
  view.setUint32(METADATA_RVA + 76, 0x1a0, true);
  view.setUint32(METADATA_RVA + 80, 0x1c0, true);
  view.setUint32(METADATA_RVA + 84, 0x1e0, true);
  view.setUint32(METADATA_RVA + 88, 3, true);
  view.setUint32(0x100, 0x202, true);
  view.setUint32(0x104, 0x30, true);
  view.setUint32(0x108, 0x240, true);
  view.setUint32(0x10c, 0x10, true);
  view.setUint32(0x110, 0x281, true);
  view.setUint32(0x114, 0x10, true);
  view.setUint32(0x118, 0x2c3, true);
  view.setUint32(0x11c, 0x10, true);
  view.setUint32(0x120, 0x200, true);
  view.setUint32(0x124, 0x230, true);
  view.setUint32(0x128, 0x210, true);
  view.setUint32(0x12c, 0x240, true);
  view.setUint32(0x130, 0x260, true);
  view.setUint32(0x134, 0x244, true);
  view.setUint32(0x140, 0x200, true);
  view.setUint32(0x144, 0x300, true);
  view.setUint32(0x148, 0x240, true);
  view.setUint32(0x14c, 0x340, true);
  view.setUint32(0x180, 0x600, true);
  view.setUint32(0x184, 0x700, true);
  view.setUint32(0x188, 0x800, true);
  view.setUint32(0x18c, 1, true);

  const { metadata, notes } = await parseMetadata(bytes, PE32_PLUS_POINTER_BYTES);
  const chpe = expectDefined(metadata);

  assert.equal(chpe.kind, "arm64ec");
  assert.deepEqual(chpe.codeMap, [
    { startRva: 0x200, length: 0x30, kind: "AMD64" },
    { startRva: 0x240, length: 0x10, kind: "ARM64" },
    { startRva: 0x280, length: 0x10, kind: "ARM64EC" },
    { startRva: 0x2c0, length: 0x10, kind: "UNKNOWN" }
  ]);
  assert.deepEqual(chpe.entryPointRanges, [
    { startRva: 0x200, endRva: 0x230, entryPointRva: 0x210 },
    { startRva: 0x240, endRva: 0x260, entryPointRva: 0x244 }
  ]);
  assert.deepEqual(chpe.redirections, [
    { sourceRva: 0x200, destinationRva: 0x300 },
    { sourceRva: 0x240, destinationRva: 0x340 }
  ]);
  assert.equal(chpe.extraRfeTableSize, 16);
  assert.equal(chpe.extraRfeEntries[0]?.unwindKind, "exception");
  assert.equal(chpe.extraRfeEntries[1]?.unwindKind, "packed");
  assert.equal(chpe.osArm64xDispatchCallNoRedirectRva, 0x01020304);
  assert.equal(chpe.osArm64xDispatchRetRva, 0x02030405);
  assert.equal(chpe.osArm64xDispatchCallRva, 0x03040506);
  assert.equal(chpe.osArm64xDispatchIcallRva, 0x04050607);
  assert.equal(chpe.osArm64xDispatchIcallCfgRva, 0x05060708);
  assert.equal(chpe.alternateEntryPointRva, 0x06070809);
  assert.equal(chpe.auxiliaryIatRva, 0x0708090a);
  assert.equal(chpe.getX64InformationFunctionPointerRva, 0x08090a0b);
  assert.equal(chpe.setX64InformationFunctionPointerRva, 0x090a0b0c);
  assert.equal(chpe.osArm64xDispatchFptrRva, 0x0a0b0c0d);
  assert.equal(chpe.auxiliaryIatCopyRva, 0x1a0);
  assert.equal(chpe.auxiliaryDelayloadIatRva, 0x1c0);
  assert.equal(chpe.auxiliaryDelayloadIatCopyRva, 0x1e0);
  assert.equal(chpe.hybridImageInfoBitfield, 3);
  assert.deepEqual(notes, []);
});

void test("parseChpeMetadata decodes x86 v3 fields and the native-code bit", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(METADATA_RVA, 3, true);
  view.setUint32(METADATA_RVA + 4, 0x80, true);
  view.setUint32(METADATA_RVA + 8, 2, true);
  view.setUint32(METADATA_RVA + 12, 0x01020304, true);
  view.setUint32(METADATA_RVA + 16, 0x02030405, true);
  view.setUint32(METADATA_RVA + 20, 0x03040506, true);
  view.setUint32(METADATA_RVA + 24, 0x04050607, true);
  view.setUint32(METADATA_RVA + 28, 0x05060708, true);
  view.setUint32(METADATA_RVA + 32, 0x06070809, true);
  view.setUint32(METADATA_RVA + 36, 0x0708090a, true);
  view.setUint32(METADATA_RVA + 40, 0x120, true);
  view.setUint32(METADATA_RVA + 44, 0x140, true);
  view.setUint32(0x80, 0x101, true);
  view.setUint32(0x84, 0x20, true);
  view.setUint32(0x88, 0x180, true);
  view.setUint32(0x8c, 0x10, true);

  const { metadata, notes } = await parseMetadata(bytes, PE32_POINTER_BYTES);
  const chpe = expectDefined(metadata);

  assert.equal(chpe.kind, "x86");
  assert.deepEqual(chpe.codeMap, [
    { startRva: 0x100, length: 0x20, kind: "ARM64" },
    { startRva: 0x180, length: 0x10, kind: "X86" }
  ]);
  assert.equal(chpe.compilerIatRva, 0x120);
  assert.equal(chpe.wowA64RdtscRva, 0x140);
  assert.equal(chpe.wowA64ExceptionHandlerRva, 0x01020304);
  assert.equal(chpe.wowA64DispatchCallRva, 0x02030405);
  assert.equal(chpe.wowA64DispatchIndirectCallRva, 0x03040506);
  assert.equal(chpe.wowA64DispatchIndirectCallCfgRva, 0x04050607);
  assert.equal(chpe.wowA64DispatchRetRva, 0x05060708);
  assert.equal(chpe.wowA64DispatchRetLeafRva, 0x06070809);
  assert.equal(chpe.wowA64DispatchJumpRva, 0x0708090a);
  assert.deepEqual(notes, []);
});

void test("parseChpeMetadata reports missing, overflowing, and truncated referenced data", async () => {
  const bytes = new Uint8Array(0x90).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(METADATA_RVA, 2, true);
  view.setUint32(METADATA_RVA + 8, 1, true);
  view.setUint32(METADATA_RVA + 12, 0xfffffff8, true);
  view.setUint32(METADATA_RVA + 48, 2, true);

  const { metadata, warnings } = await parseMetadata(bytes, PE32_PLUS_POINTER_BYTES);

  assert.equal(metadata?.kind, "arm64ec");
  assert.deepEqual(metadata?.codeMap, []);
  assert.deepEqual(metadata?.entryPointRanges, []);
  assert.ok(warnings.some(warning => warning.includes("CHPE CodeMap has entries but no valid table RVA")));
  assert.ok(warnings.some(warning => warning.includes("CHPE entry point ranges exceeds")));
  assert.ok(warnings.some(warning => warning.includes("CHPE ARM64EC v2 metadata is truncated")));
});

void test("parseChpeMetadata marks versions newer than the known prefixes", async () => {
  const armBytes = new Uint8Array(0x100).fill(0);
  new DataView(armBytes.buffer).setUint32(METADATA_RVA, 3, true);
  const x86Bytes = new Uint8Array(0x100).fill(0);
  new DataView(x86Bytes.buffer).setUint32(METADATA_RVA, 4, true);

  const arm = await parseMetadata(armBytes, PE32_PLUS_POINTER_BYTES);
  const x86 = await parseMetadata(x86Bytes, PE32_POINTER_BYTES);

  assert.ok(arm.notes.some(note => note.includes("ARM64EC v3")));
  assert.ok(x86.notes.some(note => note.includes("x86 v4")));
});

void test("parseChpeMetadata handles x86 v1, v2, invalid pointers, and truncated prefixes", async () => {
  const v1Bytes = new Uint8Array(0x68).fill(0);
  new DataView(v1Bytes.buffer).setUint32(METADATA_RVA + 8, 1, true);
  const v2Bytes = new Uint8Array(0x6c).fill(0);
  new DataView(v2Bytes.buffer).setUint32(METADATA_RVA, 2, true);
  const armV1Bytes = new Uint8Array(0x90).fill(0);
  const invalidWarnings: string[] = [];
  const invalid = await parseChpeMetadata(
    new MockFile(v1Bytes, "invalid-chpe.bin"),
    createPeRvaMapping(v1Bytes.length, [], v1Bytes.length, value => value),
    IMAGE_BASE,
    PE32_POINTER_BYTES,
    invalidWarnings,
    [],
    IMAGE_BASE - 1n
  );
  const v1 = await parseMetadata(v1Bytes, PE32_POINTER_BYTES);
  const v2 = await parseMetadata(v2Bytes, PE32_POINTER_BYTES);
  const armV1 = await parseMetadata(armV1Bytes, PE32_PLUS_POINTER_BYTES);
  const truncatedX86 = await parseMetadata(new Uint8Array(0x50), PE32_POINTER_BYTES);
  const truncatedArm = await parseMetadata(new Uint8Array(0x50), PE32_PLUS_POINTER_BYTES);

  assert.equal(invalid, null);
  assert.deepEqual(invalidWarnings, [
    "LOAD_CONFIG: CHPEMetadataPointer pointer 0x13fffffff is not a valid VA."
  ]);
  assert.equal(expectX86Metadata(v1.metadata).compilerIatRva, undefined);
  assert.equal(expectX86Metadata(v2.metadata).compilerIatRva, 0);
  assert.ok(v1.warnings.some(warning => warning ===
    "LOAD_CONFIG: CHPE x86 CodeMap has entries but no valid table RVA."));
  assert.equal(armV1.metadata?.kind, "arm64ec");
  assert.equal(armV1.metadata?.auxiliaryDelayloadIatRva, undefined);
  assert.deepEqual(armV1.notes, []);
  assert.equal(truncatedX86.metadata, null);
  assert.equal(truncatedArm.metadata, null);
  assert.ok(truncatedX86.warnings.some(warning => warning.includes("CHPE x86 metadata is truncated")));
  assert.ok(truncatedArm.warnings.some(warning => warning.includes("CHPE ARM64EC metadata is truncated")));
});
