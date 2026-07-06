"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCoffObject } from "../../../../analyzers/coff/index.js";
import {
  COFF_RELOCATION_EXTENDED_COUNT_SENTINEL,
  COFF_RELOCATION_FIELDS,
  COFF_RELOCATION_RECORD_BYTE_LENGTH,
  COFF_SECTION_CHARACTERISTICS,
  type CoffNumericField
} from "../../../../analyzers/coff/layout.js";
import { parseCoffRelocations } from "../../../../analyzers/coff/relocations.js";
import { inlineCoffSectionName } from "../../../../analyzers/coff/section-name.js";
import type { CoffSection } from "../../../../analyzers/coff/types.js";
import type { FileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { createCoffObjectFile } from "../../../fixtures/coff-object-fixture.js";
import { MockFile } from "../../../helpers/mock-file.js";

// Project I/O policy: FileRangeReader uses a measured 64 KiB cache window
// (see analyzers/file-range-reader.ts); this fixture crosses that read boundary.
const CHUNK_BOUNDARY_RECORD_COUNT = Math.floor((64 * 1024) / COFF_RELOCATION_RECORD_BYTE_LENGTH);

const createSection = (
  pointerToRelocations: number,
  numberOfRelocations: number,
  characteristics = 0
): CoffSection => ({
  name: inlineCoffSectionName(".text"),
  virtualSize: 0,
  virtualAddress: 0,
  sizeOfRawData: 0,
  pointerToRawData: 0,
  pointerToRelocations,
  numberOfRelocations,
  characteristics
});

const createExtendedSection = (
  pointerToRelocations: number,
  numberOfRelocations = COFF_RELOCATION_EXTENDED_COUNT_SENTINEL
): CoffSection =>
  createSection(pointerToRelocations, numberOfRelocations, COFF_SECTION_CHARACTERISTICS.LNK_NRELOC_OVFL);

const writeField = (
  view: DataView,
  base: number,
  field: CoffNumericField,
  value: number
): void => {
  const offset = base + field.offset;
  if (field.width === "u16") view.setUint16(offset, value, true);
  else view.setUint32(offset, value, true);
};

const writeRelocationRecord = (
  view: DataView,
  offset: number,
  virtualAddress: number,
  symbolTableIndex: number,
  type: number
): void => {
  writeField(view, offset, COFF_RELOCATION_FIELDS.VirtualAddress, virtualAddress);
  writeField(view, offset, COFF_RELOCATION_FIELDS.SymbolTableIndex, symbolTableIndex);
  writeField(view, offset, COFF_RELOCATION_FIELDS.Type, type);
};

const createBoundedReader = (
  bytes: Uint8Array,
  reads: Array<[number, number]> = []
): FileRangeReader => ({
  size: bytes.length,
  read: (offset, length) => {
    reads.push([offset, length]);
    if (offset < 0 || length < 0 || offset + length > bytes.length) {
      throw new Error(`out-of-bounds relocation read at ${offset} for ${length}`);
    }
    return Promise.resolve(new DataView(bytes.buffer, bytes.byteOffset + offset, length));
  },
  readBytes: (offset, length) => Promise.resolve(bytes.subarray(offset, offset + length))
});

void test("parseCoffObject parses COFF section relocation records from object files", async () => {
  const parsed = await parseCoffObject(createCoffObjectFile());
  if (!parsed) assert.fail("expected parsed COFF object");

  assert.equal(parsed.relocations?.length, 1);
  assert.deepEqual(parsed.relocations?.[0]?.records[0], {
    index: 0,
    virtualAddress: 0,
    symbolTableIndex: 2,
    // Microsoft PE/COFF: IMAGE_REL_I386_REL32 is the x86 rel32 relocation type.
    type: 0x0014
  });
  assert.deepEqual(parsed.warnings ?? [], []);
});

void test("parseCoffRelocations warns and keeps whole records when a table is truncated", async () => {
  const bytes = new Uint8Array(12);
  const view = new DataView(bytes.buffer);
  writeRelocationRecord(view, 2, 4, 1, 0x0014);
  const warnings: string[] = [];

  const blocks = await parseCoffRelocations(
    new MockFile(bytes.slice(0, 7)),
    [createSection(2, 1)],
    warning => warnings.push(warning)
  );

  assert.equal(blocks.length, 1);
  assert.deepEqual(blocks[0]?.records, []);
  assert.match(warnings.join("\n"), /truncated/i);
  assert.match(blocks[0]?.warnings?.join("\n") ?? "", /truncated/i);
});

void test("parseCoffRelocations handles extended relocation count markers", async () => {
  const bytes = new Uint8Array(2 + COFF_RELOCATION_RECORD_BYTE_LENGTH * 2);
  const view = new DataView(bytes.buffer);
  writeRelocationRecord(view, 2, 2, 0, 0);
  writeRelocationRecord(view, 2 + COFF_RELOCATION_RECORD_BYTE_LENGTH, 8, 3, 0x0004);
  const warnings: string[] = [];

  const blocks = await parseCoffRelocations(
    new MockFile(bytes),
    [createExtendedSection(2)],
    warning => warnings.push(warning)
  );

  assert.equal(blocks[0]?.extendedRelocationCount, 2);
  assert.deepEqual(blocks[0]?.records, [
    { index: 0, virtualAddress: 8, symbolTableIndex: 3, type: 0x0004 }
  ]);
  assert.deepEqual(warnings, []);
});

void test("parseCoffRelocations keeps inconsistent section pointers visible as warnings", async () => {
  const warnings: string[] = [];

  const blocks = await parseCoffRelocations(
    new MockFile(new Uint8Array(16)),
    [createSection(4, 0), createSection(0, 1)],
    warning => warnings.push(warning)
  );

  assert.equal(blocks.length, 2);
  assert.deepEqual(blocks.map(block => block.records.length), [0, 0]);
  assert.match(warnings.join("\n"), /pointer is set but count is 0/i);
  assert.match(warnings.join("\n"), /count is set but pointer is 0/i);
});

void test("parseCoffRelocations warns when the relocation table starts past EOF", async () => {
  const warnings: string[] = [];

  const blocks = await parseCoffRelocations(
    new MockFile(new Uint8Array(16)),
    [createSection(24, 1)],
    warning => warnings.push(warning)
  );

  assert.equal(blocks[0]?.records.length, 0);
  assert.match(warnings.join("\n"), /past end of file/i);
});

void test("parseCoffRelocations warns when the relocation table starts exactly at EOF", async () => {
  const warnings: string[] = [];

  const blocks = await parseCoffRelocations(
    new MockFile(new Uint8Array(16)),
    [createSection(16, 1)],
    warning => warnings.push(warning)
  );

  assert.equal(blocks[0]?.records.length, 0);
  assert.match(warnings.join("\n"), /starts past end of file/i);
});

void test("parseCoffRelocations reads records across chunk boundaries", async () => {
  const recordCount = CHUNK_BOUNDARY_RECORD_COUNT + 2;
  const bytes = new Uint8Array(2 + COFF_RELOCATION_RECORD_BYTE_LENGTH * recordCount);
  const view = new DataView(bytes.buffer);
  writeRelocationRecord(view, 2, 1, 2, 3);
  writeRelocationRecord(view, 2 + COFF_RELOCATION_RECORD_BYTE_LENGTH, 7, 8, 9);
  writeRelocationRecord(view, 2 + COFF_RELOCATION_RECORD_BYTE_LENGTH * (recordCount - 1), 4, 5, 6);
  const chunkBytes = COFF_RELOCATION_RECORD_BYTE_LENGTH * CHUNK_BOUNDARY_RECORD_COUNT;
  const tailBytes = COFF_RELOCATION_RECORD_BYTE_LENGTH * 2;
  const reads: Array<[number, number]> = [];

  const blocks = await parseCoffRelocations(
    createBoundedReader(bytes, reads),
    [createSection(2, recordCount)],
    assert.fail
  );

  assert.equal(blocks[0]?.records.length, recordCount);
  assert.deepEqual(blocks[0]?.records[0], { index: 0, virtualAddress: 1, symbolTableIndex: 2, type: 3 });
  const finalRecord = blocks[0]?.records[recordCount - 1];
  assert.deepEqual(finalRecord, { index: recordCount - 1, virtualAddress: 4, symbolTableIndex: 5, type: 6 });
  assert.deepEqual(reads, [[2, chunkBytes], [2 + chunkBytes, tailBytes]]);
});

void test("parseCoffRelocations warns when the extended relocation marker is truncated", async () => {
  const warnings: string[] = [];

  const blocks = await parseCoffRelocations(
    new MockFile(new Uint8Array(8)),
    [createExtendedSection(2)],
    warning => warnings.push(warning)
  );

  assert.equal(blocks[0]?.records.length, 0);
  assert.match(warnings.join("\n"), /count record is truncated/i);
});

void test("parseCoffRelocations warns when an extended relocation count is zero", async () => {
  const bytes = new Uint8Array(2 + COFF_RELOCATION_RECORD_BYTE_LENGTH);
  const warnings: string[] = [];

  const blocks = await parseCoffRelocations(
    new MockFile(bytes),
    [createExtendedSection(2)],
    warning => warnings.push(warning)
  );

  assert.equal(blocks[0]?.extendedRelocationCount, 0);
  assert.equal(blocks[0]?.records.length, 0);
  assert.match(warnings.join("\n"), /count is zero/i);
});

void test("parseCoffRelocations warns when an extended table has no records after marker", async () => {
  const bytes = new Uint8Array(2 + COFF_RELOCATION_RECORD_BYTE_LENGTH);
  const view = new DataView(bytes.buffer);
  writeRelocationRecord(view, 2, 2, 0, 0);
  const warnings: string[] = [];

  const blocks = await parseCoffRelocations(
    new MockFile(bytes),
    [createExtendedSection(2)],
    warning => warnings.push(warning)
  );

  assert.equal(blocks[0]?.extendedRelocationCount, 2);
  assert.equal(blocks[0]?.records.length, 0);
  assert.match(warnings.join("\n"), /relocation table is truncated/i);
});

void test("parseCoffRelocations warns when the extended flag lacks its sentinel", async () => {
  const bytes = new Uint8Array(2 + COFF_RELOCATION_RECORD_BYTE_LENGTH);
  const view = new DataView(bytes.buffer);
  writeRelocationRecord(view, 2, 4, 1, 0x0014);
  const warnings: string[] = [];

  const blocks = await parseCoffRelocations(
    new MockFile(bytes),
    [createExtendedSection(2, 1)],
    warning => warnings.push(warning)
  );

  assert.equal(blocks[0]?.records.length, 1);
  assert.match(warnings.join("\n"), /without the 0xffff relocation count sentinel/i);
});

void test("parseCoffRelocations omits sections with no relocation pointer and count", async () => {
  const blocks = await parseCoffRelocations(
    new MockFile(new Uint8Array()),
    [createSection(0, 0)],
    assert.fail
  );

  assert.deepEqual(blocks, []);
});

void test("parseCoffRelocations keeps clean relocation blocks warning-free", async () => {
  const relocationOffset = 4;
  const bytes = new Uint8Array(relocationOffset + COFF_RELOCATION_RECORD_BYTE_LENGTH);
  const view = new DataView(bytes.buffer);
  writeRelocationRecord(view, relocationOffset, 1, 2, 3);

  const blocks = await parseCoffRelocations(
    new MockFile(bytes),
    [createSection(relocationOffset, 1)],
    assert.fail
  );

  assert.equal("warnings" in blocks[0]!, false);
});

void test("parseCoffRelocations bounds readable records from non-zero offsets", async () => {
  const relocationOffset = COFF_RELOCATION_RECORD_BYTE_LENGTH * 2;
  const bytes = new Uint8Array(relocationOffset + COFF_RELOCATION_RECORD_BYTE_LENGTH);
  const warnings: string[] = [];
  const view = new DataView(bytes.buffer);
  writeRelocationRecord(view, relocationOffset, 1, 2, 3);

  const blocks = await parseCoffRelocations(
    createBoundedReader(bytes),
    [createSection(relocationOffset, 2)],
    warning => warnings.push(warning)
  );

  assert.equal(blocks[0]?.records.length, 1);
  assert.match(warnings.join("\n"), /relocation table is truncated/i);
});
