"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCoffDebugInfo } from "../../../../../../analyzers/pe/debug/coff.js";
import { parseCoffDebugInfoFromFileHeader } from "../../../../../../analyzers/coff/debug.js";
import { createCoffDebugStringTable } from "../../../../../../analyzers/coff/debug-string-table.js";
import { parseCoffLineNumberBlock } from "../../../../../../analyzers/coff/lines.js";
import {
  COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH,
  COFF_SYMBOL_RECORD_BYTE_LENGTH
} from "../../../../../../analyzers/coff/layout.js";
import type { FileRangeReader } from "../../../../../../analyzers/file-range-reader.js";
import { inlinePeSectionName } from "../../../../../../analyzers/pe/sections/name.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import {
  TEST_COFF_STORAGE_CLASS,
  createOffsetFile,
  createSymbolTable,
  writeU32
} from "../../../../../fixtures/pe-coff-debug-fixtures.js";

void test("parseCoffDebugInfoFromFileHeader warns for malformed string tables and line tables", async () => {
  const bytes = new Uint8Array(COFF_SYMBOL_RECORD_BYTE_LENGTH + 6);
  writeU32(bytes, 4, 4);
  bytes[16] = 2;
  writeU32(bytes, COFF_SYMBOL_RECORD_BYTE_LENGTH, 6);
  bytes[COFF_SYMBOL_RECORD_BYTE_LENGTH + 4] = 0x61;
  bytes[COFF_SYMBOL_RECORD_BYTE_LENGTH + 5] = 0x62;
  const warnings: string[] = [];

  const result = await parseCoffDebugInfoFromFileHeader(
    createOffsetFile(bytes),
    1,
    1,
    [{
      name: inlinePeSectionName(".text"),
      virtualSize: 0,
      virtualAddress: 0,
      sizeOfRawData: 0,
      pointerToRawData: 0,
      pointerToLinenumbers: bytes.length + 1,
      numberOfLinenumbers: 1,
      characteristics: 0
    }],
    message => warnings.push(message)
  );

  assert.equal(result?.symbols[0]?.name, "ab");
  assert.match(warnings.join(" | "), /not NUL-terminated/i);
  assert.match(warnings.join(" | "), /starts past end of file/i);
});

void test("parseCoffDebugInfoFromFileHeader warns for unsafe and past-end symbol tables", async () => {
  const unsafeWarnings: string[] = [];
  const unsafe = await parseCoffDebugInfoFromFileHeader(
    new MockFile(new Uint8Array(8)),
    1,
    Number.MAX_SAFE_INTEGER,
    [],
    message => unsafeWarnings.push(message)
  );
  const pastEndWarnings: string[] = [];
  const pastEnd = await parseCoffDebugInfoFromFileHeader(
    new MockFile(new Uint8Array(1)),
    1,
    1,
    [],
    message => pastEndWarnings.push(message)
  );

  assert.equal(unsafe?.symbols.length, 0);
  assert.match(unsafeWarnings.join(" | "), /overflows/i);
  assert.equal(pastEnd?.symbols.length, 0);
  assert.deepEqual(pastEnd?.warnings, ["COFF symbol table starts past end of file."]);
  assert.match(pastEndWarnings.join(" | "), /starts past end/i);
});

void test("parseCoffDebugInfo reports truncated headers and unmapped tables", async () => {
  const shortWarnings: string[] = [];
  const shortResult = await parseCoffDebugInfo(
    new MockFile(new Uint8Array(COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH - 1)),
    COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH - 1,
    value => value,
    0,
    1,
    COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH - 1,
    message => shortWarnings.push(message)
  );
  const payload = new Uint8Array(COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH);
  writeU32(payload, 0, 1);
  writeU32(payload, 4, 0xfff0);
  const unmappedWarnings: string[] = [];
  const unmappedResult = await parseCoffDebugInfo(
    createOffsetFile(payload),
    payload.length + 1,
    () => null,
    0,
    1,
    payload.length,
    message => unmappedWarnings.push(message)
  );

  assert.equal(shortResult, null);
  assert.match(shortWarnings.join(" | "), /smaller than IMAGE_COFF_SYMBOLS_HEADER/i);
  assert.equal(unmappedResult, null);
  assert.match(unmappedWarnings.join(" | "), /symbol table LVA/i);
});

void test("parseCoffDebugInfo reports unmapped line tables", async () => {
  const symbolTable = createSymbolTable([{ name: ".text", storageClass: TEST_COFF_STORAGE_CLASS.STATIC }], []);
  const payload = new Uint8Array(COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH + symbolTable.bytes.length);
  writeU32(payload, 0, symbolTable.recordCount);
  writeU32(payload, 4, COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH);
  writeU32(payload, 8, 1);
  writeU32(payload, 12, 0xfff0);
  payload.set(symbolTable.bytes, COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH);
  const warnings: string[] = [];

  const result = await parseCoffDebugInfo(
    createOffsetFile(payload),
    payload.length + 1,
    () => null,
    0,
    1,
    payload.length,
    message => warnings.push(message)
  );

  assert.equal(result?.lineNumberBlocks.length, 0);
  assert.match(warnings.join(" | "), /line-number table LVA/i);
});

void test("COFF low-level readers warn for malformed string and line tables", async () => {
  const shortSizeReader: FileRangeReader = {
    size: 8,
    read: () => Promise.resolve(new DataView(new ArrayBuffer(2))),
    readBytes: () => Promise.resolve(new Uint8Array())
  };
  const shortWarnings: string[] = [];
  const undersized = new Uint8Array(4);
  writeU32(undersized, 0, 3);
  const undersizedWarnings: string[] = [];
  const outsideWarnings: string[] = [];

  const shortTable = await createCoffDebugStringTable(shortSizeReader, 0, message => shortWarnings.push(message));
  const undersizedTable = await createCoffDebugStringTable(
    new MockFile(undersized),
    0,
    message => undersizedWarnings.push(message)
  );
  const outsideTable = await createCoffDebugStringTable(
    new MockFile(Uint8Array.from([8, 0, 0, 0, 0x61, 0])),
    0,
    message => outsideWarnings.push(message)
  );
  const outside = await outsideTable?.resolve(8);
  const zeroLines = await parseCoffLineNumberBlock(new MockFile(new Uint8Array()), 0, 0, assert.fail);

  assert.equal(shortTable, null);
  assert.match(shortWarnings.join(" | "), /size field is truncated/i);
  assert.equal(undersizedTable, null);
  assert.match(undersizedWarnings.join(" | "), /smaller than/i);
  assert.equal(outside?.value, "/8");
  assert.match(outside?.warning ?? "", /outside the string table/i);
  assert.deepEqual(zeroLines, []);
});

void test("parseCoffDebugInfo resolves mapped symbol LVAs and truncated header reads", async () => {
  const symbolTable = createSymbolTable([{ name: ".text", storageClass: TEST_COFF_STORAGE_CLASS.STATIC }], []);
  const payload = new Uint8Array(COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH + symbolTable.bytes.length);
  writeU32(payload, 0, symbolTable.recordCount);
  writeU32(payload, 4, 0x1000);
  payload.set(symbolTable.bytes, COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH);
  const warnings: string[] = [];
  const mapped = await parseCoffDebugInfo(
    createOffsetFile(payload),
    payload.length + 1,
    rva => rva === 0x1000 ? COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH + 1 : null,
    0,
    1,
    COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH,
    message => warnings.push(message)
  );
  const shortReadReader: FileRangeReader = {
    size: COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH + 1,
    read: () => Promise.resolve(new DataView(new ArrayBuffer(COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH - 1))),
    readBytes: () => Promise.resolve(new Uint8Array())
  };
  const shortReadWarnings: string[] = [];
  const shortRead = await parseCoffDebugInfo(
    shortReadReader,
    shortReadReader.size,
    value => value,
    0,
    1,
    COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH,
    message => shortReadWarnings.push(message)
  );

  assert.equal(mapped?.symbols[0]?.name, ".text");
  assert.deepEqual(warnings, []);
  assert.equal(shortRead, null);
  assert.match(shortReadWarnings.join(" | "), /symbols header is truncated/i);
});

void test("parseCoffDebugInfoFromFileHeader warns when long symbol names lack a string table", async () => {
  const symbol = new Uint8Array(COFF_SYMBOL_RECORD_BYTE_LENGTH);
  writeU32(symbol, 4, 4);
  symbol[16] = 2;
  const warnings: string[] = [];

  const result = await parseCoffDebugInfoFromFileHeader(
    createOffsetFile(symbol),
    1,
    1,
    [],
    message => warnings.push(message)
  );

  assert.equal(result?.symbols[0]?.name, "/4");
  assert.match(warnings.join(" | "), /cannot be resolved without a string table/i);
});
