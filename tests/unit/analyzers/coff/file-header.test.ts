"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  COFF_FILE_HEADER_BYTE_LENGTH,
  COFF_FILE_HEADER_FIELDS,
  type CoffNumericField
} from "../../../../analyzers/coff/layout.js";
import { IMAGE_FILE_MACHINE_I386 } from "../../../../analyzers/coff/machine.js";
import { parseCoffFileHeaderAt } from "../../../../analyzers/coff/file-header.js";
import { MockFile } from "../../../helpers/mock-file.js";

const writeField = (view: DataView, base: number, field: CoffNumericField, value: number): void => {
  const offset = base + field.offset;
  if (field.width === "u16") view.setUint16(offset, value, true);
  else view.setUint32(offset, value, true);
};

void test("parseCoffFileHeaderAt returns null for truncated headers", async () => {
  const parsed = await parseCoffFileHeaderAt(new MockFile(new Uint8Array(COFF_FILE_HEADER_BYTE_LENGTH - 1)), 0);

  assert.equal(parsed, null);
});

void test("parseCoffFileHeaderAt reads a COFF header at a non-zero offset", async () => {
  const headerOffset = 3;
  const bytes = new Uint8Array(headerOffset + COFF_FILE_HEADER_BYTE_LENGTH);
  const view = new DataView(bytes.buffer);
  writeField(view, headerOffset, COFF_FILE_HEADER_FIELDS.Machine, IMAGE_FILE_MACHINE_I386);
  writeField(view, headerOffset, COFF_FILE_HEADER_FIELDS.NumberOfSections, 2);
  writeField(view, headerOffset, COFF_FILE_HEADER_FIELDS.PointerToSymbolTable, 0x80);
  writeField(view, headerOffset, COFF_FILE_HEADER_FIELDS.NumberOfSymbols, 4);
  writeField(view, headerOffset, COFF_FILE_HEADER_FIELDS.SizeOfOptionalHeader, 0);
  writeField(view, headerOffset, COFF_FILE_HEADER_FIELDS.Characteristics, 0);

  const parsed = await parseCoffFileHeaderAt(new MockFile(bytes), headerOffset);

  assert.deepEqual(parsed, {
    Machine: IMAGE_FILE_MACHINE_I386,
    NumberOfSections: 2,
    TimeDateStamp: 0,
    PointerToSymbolTable: 0x80,
    NumberOfSymbols: 4,
    SizeOfOptionalHeader: 0,
    Characteristics: 0
  });
});
