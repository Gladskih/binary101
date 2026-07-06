"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  COFF_LINE_NUMBER_FIELDS,
  COFF_LINE_NUMBER_RECORD_BYTE_LENGTH,
  type CoffNumericField
} from "../../../../analyzers/coff/layout.js";
import { parseCoffLineNumberBlock, parseSectionCoffLineNumbers } from "../../../../analyzers/coff/lines.js";
import { inlineCoffSectionName } from "../../../../analyzers/coff/section-name.js";
import type { CoffSection } from "../../../../analyzers/coff/types.js";
import { MockFile } from "../../../helpers/mock-file.js";

const writeField = (view: DataView, base: number, field: CoffNumericField, value: number): void => {
  const offset = base + field.offset;
  if (field.width === "u16") view.setUint16(offset, value, true);
  else view.setUint32(offset, value, true);
};

const createLineRecord = (typeField: number, lineNumber: number): Uint8Array => {
  const bytes = new Uint8Array(COFF_LINE_NUMBER_RECORD_BYTE_LENGTH);
  const view = new DataView(bytes.buffer);
  writeField(view, 0, COFF_LINE_NUMBER_FIELDS.SymbolTableIndexOrVirtualAddress, typeField);
  writeField(view, 0, COFF_LINE_NUMBER_FIELDS.LineNumber, lineNumber);
  return bytes;
};

const section = (pointerToLinenumbers: number, numberOfLinenumbers: number): CoffSection => ({
  name: inlineCoffSectionName(".text"),
  virtualSize: 0,
  virtualAddress: 0,
  sizeOfRawData: 0,
  pointerToRawData: 0,
  pointerToLinenumbers,
  numberOfLinenumbers,
  characteristics: 0
});

void test("parseCoffLineNumberBlock keeps whole records and warns for truncation", async () => {
  const bytes = new Uint8Array(COFF_LINE_NUMBER_RECORD_BYTE_LENGTH * 2 - 1);
  bytes.set(createLineRecord(7, 0));
  const warnings: string[] = [];

  const records = await parseCoffLineNumberBlock(new MockFile(bytes), 0, 2, warnings.push.bind(warnings));

  assert.deepEqual(records, [{ symbolTableIndexOrVirtualAddress: 7, lineNumber: 0 }]);
  assert.match(warnings.join(" | "), /truncated/i);
});

void test("parseCoffLineNumberBlock computes available bytes from non-zero offsets", async () => {
  const offset = 3;
  const bytes = new Uint8Array(offset + COFF_LINE_NUMBER_RECORD_BYTE_LENGTH + 1);
  bytes.set(createLineRecord(9, 10), offset);
  const warnings: string[] = [];

  const records = await parseCoffLineNumberBlock(new MockFile(bytes), offset, 2, warnings.push.bind(warnings));

  assert.deepEqual(records, [{ symbolTableIndexOrVirtualAddress: 9, lineNumber: 10 }]);
  assert.match(warnings.join(" | "), /truncated/i);
});

void test("parseCoffLineNumberBlock returns no records for empty and past-end tables", async () => {
  const warnings: string[] = [];
  const empty = await parseCoffLineNumberBlock(new MockFile(new Uint8Array()), 0, 0, assert.fail);
  const pastEnd = await parseCoffLineNumberBlock(new MockFile(new Uint8Array(4)), 4, 1, warnings.push.bind(warnings));

  assert.deepEqual(empty, []);
  assert.deepEqual(pastEnd, []);
  assert.match(warnings.join(" | "), /past end/i);
});

void test("parseSectionCoffLineNumbers builds blocks only for sections with count and pointer", async () => {
  const bytes = new Uint8Array(16);
  bytes.set(createLineRecord(0x1234, 9), 4);
  const warnings: string[] = [];

  const blocks = await parseSectionCoffLineNumbers(
    new MockFile(bytes),
    [section(4, 1), section(8, 0), section(0, 1)],
    warnings.push.bind(warnings)
  );

  assert.equal(blocks.length, 1);
  assert.equal(blocks[0]?.sectionIndex, 1);
  assert.equal(blocks[0]?.sectionName, ".text");
  assert.deepEqual(blocks[0]?.records, [{ symbolTableIndexOrVirtualAddress: 0x1234, lineNumber: 9 }]);
  assert.deepEqual(warnings, []);
});
