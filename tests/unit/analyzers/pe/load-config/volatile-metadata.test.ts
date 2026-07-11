"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeRvaMapping } from "../../../../../analyzers/pe/load-config/reference-reader.js";
import { parseVolatileMetadata } from "../../../../../analyzers/pe/load-config/volatile-metadata.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const IMAGE_BASE = 0x140000000n;

// Fixture offsets follow the independently implemented LIEF/FEX volatile metadata layout.
// https://github.com/lief-project/LIEF/blob/main/src/PE/LoadConfigurations/VolatileMetadata.cpp

const parseMetadata = async (bytes: Uint8Array, pointerVa = IMAGE_BASE + 0x40n) => {
  const warnings: string[] = [];
  const notes: string[] = [];
  const result = await parseVolatileMetadata(
    new MockFile(bytes, "volatile-metadata.bin"),
    createPeRvaMapping(bytes.length, [], bytes.length, value => value),
    IMAGE_BASE,
    warnings,
    notes,
    pointerVa
  );
  return { result, warnings, notes };
};

void test("parseVolatileMetadata decodes access RVAs and covered ranges", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0x40, 24, true); // Recovered IMAGE_VOLATILE_METADATA header size.
  view.setUint16(0x44, 1, true);
  view.setUint16(0x46, 2, true);
  view.setUint32(0x48, 0x80, true);
  view.setUint32(0x4c, 8, true);
  view.setUint32(0x50, 0xa0, true);
  view.setUint32(0x54, 16, true);
  view.setUint32(0x80, 0x1010, true);
  view.setUint32(0x84, 0x2020, true);
  view.setUint32(0xa0, 0x1000, true);
  view.setUint32(0xa4, 0x40, true);
  view.setUint32(0xa8, 0x2000, true);
  view.setUint32(0xac, 0x80, true);

  const { result, warnings, notes } = await parseMetadata(bytes);

  assert.deepEqual(result?.accessRvas, [0x1010, 0x2020]);
  assert.equal(result?.minimumVersion, 1);
  assert.equal(result?.maximumVersion, 2);
  assert.deepEqual(result?.infoRanges, [
    { rva: 0x1000, size: 0x40 },
    { rva: 0x2000, size: 0x80 }
  ]);
  assert.deepEqual(warnings, []);
  assert.deepEqual(notes, []);
});

void test("parseVolatileMetadata rejects a header smaller than its recovered fixed prefix", async () => {
  const bytes = new Uint8Array(0x80).fill(0);
  new DataView(bytes.buffer).setUint32(0x40, 20, true);

  const { result, warnings } = await parseMetadata(bytes);

  assert.equal(result, null);
  assert.ok(warnings.some(warning => warning.includes("Size 20 is smaller than 24")));
});

void test("parseVolatileMetadata reports misaligned and missing tables without over-reading", async () => {
  const bytes = new Uint8Array(0x80).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0x40, 24, true);
  view.setUint16(0x44, 7, true);
  view.setUint16(0x46, 9, true);
  view.setUint32(0x48, 0x70, true);
  view.setUint32(0x4c, 6, true);
  view.setUint32(0x54, 8, true);
  view.setUint32(0x70, 0x1000, true);

  const { result, warnings } = await parseMetadata(bytes);

  assert.deepEqual(result?.accessRvas, [0x1000]);
  assert.deepEqual(result?.infoRanges, []);
  assert.ok(warnings.some(warning => warning.includes("access table size 6 is not divisible by 4")));
  assert.ok(warnings.some(warning => warning.includes("range table has entries but no valid table RVA")));
  assert.equal(result?.minimumVersion, 7);
  assert.equal(result?.maximumVersion, 9);
});

void test("parseVolatileMetadata warns when a covered range overflows the RVA address space", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0x40, 24, true);
  view.setUint32(0x44, 1, true);
  view.setUint32(0x50, 0x80, true);
  view.setUint32(0x54, 8, true);
  view.setUint32(0x80, 0xfffffff0, true);
  view.setUint32(0x84, 0x40, true);

  const { result, warnings } = await parseMetadata(bytes);

  assert.deepEqual(result?.infoRanges, []);
  assert.ok(warnings.some(warning => warning.includes("range exceeds the 32-bit RVA address space")));
});

void test("parseVolatileMetadata rejects an invalid VA and a truncated fixed header", async () => {
  const bytes = new Uint8Array(0x50).fill(0);

  const invalidPointer = await parseMetadata(bytes, IMAGE_BASE - 1n);
  const truncatedHeader = await parseMetadata(bytes);

  assert.equal(invalidPointer.result, null);
  assert.ok(invalidPointer.warnings.some(warning =>
    warning.includes("VolatileMetadataPointer") && warning.includes("is not a valid VA")));
  assert.equal(truncatedHeader.result, null);
  assert.ok(truncatedHeader.warnings.some(warning => warning.includes("header is truncated")));
});

void test("parseVolatileMetadata reports a truncated referenced table", async () => {
  const bytes = new Uint8Array(0x84).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0x40, 24, true);
  view.setUint32(0x48, 0x80, true);
  view.setUint32(0x4c, 8, true);

  const { result, warnings } = await parseMetadata(bytes);

  assert.deepEqual(result?.accessRvas, []);
  assert.ok(warnings.some(warning => warning.includes("access table is truncated")));
});

void test("parseVolatileMetadata rejects a table larger than raw data and identifies extension bytes", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0x40, 32, true);
  view.setUint32(0x48, 0x80, true);
  view.setUint32(0x4c, 0x40004, true);

  const { result, warnings, notes } = await parseMetadata(bytes);

  assert.deepEqual(result?.accessRvas, []);
  assert.ok(warnings.some(warning => warning.includes("access table is truncated")));
  assert.ok(notes.some(note => note.includes("8 extension bytes with no known layout")));
});

void test("parseVolatileMetadata accepts empty tables and a range ending at the RVA limit", async () => {
  const emptyBytes = new Uint8Array(0x80).fill(0);
  const emptyView = new DataView(emptyBytes.buffer);
  emptyView.setUint32(0x40, 0x40, true); // Declared structure ends exactly at EOF.
  const boundaryBytes = new Uint8Array(0x100).fill(0);
  const boundaryView = new DataView(boundaryBytes.buffer);
  boundaryView.setUint32(0x40, 24, true);
  boundaryView.setUint32(0x50, 0x80, true);
  boundaryView.setUint32(0x54, 8, true);
  boundaryView.setUint32(0x80, 0xfffffff0, true);
  boundaryView.setUint32(0x84, 0x10, true);

  const empty = await parseMetadata(emptyBytes);
  const boundary = await parseMetadata(boundaryBytes);

  assert.deepEqual(empty.result?.accessRvas, []);
  assert.deepEqual(empty.warnings, []);
  assert.deepEqual(boundary.result?.infoRanges, [{ rva: 0xfffffff0, size: 0x10 }]);
  assert.deepEqual(boundary.warnings, []);
});

void test("parseVolatileMetadata warns when declared extension bytes leave raw file data", async () => {
  const bytes = new Uint8Array(0x80).fill(0);
  new DataView(bytes.buffer).setUint32(0x40, 0x80, true);

  const { result, warnings } = await parseMetadata(bytes);

  assert.equal(result?.size, 0x80);
  assert.ok(warnings.some(warning => warning.includes("declared Size extends beyond raw file data")));
});
