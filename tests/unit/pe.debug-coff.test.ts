"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";
import { parseCoffDebugInfoFromFileHeader } from "../../analyzers/pe/debug/coff.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";
import { MockFile } from "../helpers/mock-file.js";
import { createDebugDirectorySubject } from "../fixtures/pe-debug-payload-subject.js";
import { expectDefined } from "../helpers/expect-defined.js";
import {
  IMAGE_COFF_SYMBOLS_HEADER_SIZE,
  IMAGE_SYMBOL_SIZE,
  TEST_COFF_LINE_NUMBERS,
  TEST_COFF_STORAGE_CLASS,
  createAuxRecord,
  createFileAuxRecord,
  createFunctionAuxRecord,
  createLineNumbers,
  createOffsetFile,
  createSymbolTable,
  writeU32
} from "../fixtures/pe-coff-debug-fixtures.js";

const IMAGE_FILE_MACHINE_AMD64 = 0x8664;

void test("parseCoffDebugInfoFromFileHeader decodes symbols, aux records, strings, and line numbers", async () => {
  const symbolTable = createSymbolTable(
    [
      {
        name: ".file",
        sectionNumber: -2,
        storageClass: TEST_COFF_STORAGE_CLASS.FILE,
        auxRecords: [createFileAuxRecord("main.c")]
      },
      {
        name: "long_function_name",
        value: 0x10,
        type: 0x20,
        storageClass: TEST_COFF_STORAGE_CLASS.EXTERNAL,
        auxRecords: [createFunctionAuxRecord()]
      }
    ],
    ["long_function_name"]
  );
  const pointerToSymbolTable = 0x40;
  const lineNumbers = createLineNumbers();
  const bytes = new Uint8Array(pointerToSymbolTable + symbolTable.bytes.length + lineNumbers.length);
  bytes.set(symbolTable.bytes, pointerToSymbolTable);
  bytes.set(lineNumbers, pointerToSymbolTable + symbolTable.bytes.length);
  const warnings: string[] = [];

  const result = await parseCoffDebugInfoFromFileHeader(
    new MockFile(bytes),
    pointerToSymbolTable,
    symbolTable.recordCount,
    [{
      name: inlinePeSectionName(".text"),
      virtualSize: 0,
      virtualAddress: 0x1000,
      sizeOfRawData: 0,
      pointerToRawData: 0,
      pointerToLinenumbers: pointerToSymbolTable + symbolTable.bytes.length,
      numberOfLinenumbers: 2,
      characteristics: 0
    }],
    message => warnings.push(message)
  );

  assert.deepEqual(warnings, []);
  assert.equal(result?.source, "coff-header");
  assert.equal(result?.symbols.length, 2);
  assert.equal(result?.symbols[0]?.auxiliaryRecords[0]?.kind, "file");
  assert.equal(result?.symbols[1]?.name, "long_function_name");
  assert.equal(result?.symbols[1]?.auxiliaryRecords[0]?.kind, "function-definition");
  assert.equal(result?.lineNumberBlocks[0]?.records[1]?.lineNumber, 42);
});

void test("parseDebugDirectory decodes IMAGE_DEBUG_TYPE_COFF payloads", async () => {
  const symbolTable = createSymbolTable([{ name: ".text", storageClass: TEST_COFF_STORAGE_CLASS.STATIC }], []);
  const lineNumbers = createLineNumbers();
  const payload = new Uint8Array(
    IMAGE_COFF_SYMBOLS_HEADER_SIZE + symbolTable.bytes.length + lineNumbers.length
  );
  writeU32(payload, 0, symbolTable.recordCount);
  writeU32(payload, 4, IMAGE_COFF_SYMBOLS_HEADER_SIZE);
  writeU32(payload, 8, TEST_COFF_LINE_NUMBERS.length);
  writeU32(payload, 12, IMAGE_COFF_SYMBOLS_HEADER_SIZE + symbolTable.bytes.length);
  writeU32(payload, 16, 0x1000);
  writeU32(payload, 20, TEST_COFF_LINE_NUMBERS[1].symbolTableIndexOrVirtualAddress);
  payload.set(symbolTable.bytes, IMAGE_COFF_SYMBOLS_HEADER_SIZE);
  payload.set(lineNumbers, IMAGE_COFF_SYMBOLS_HEADER_SIZE + symbolTable.bytes.length);
  // Microsoft PE/COFF debug type 1 is IMAGE_DEBUG_TYPE_COFF.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
  const subject = createDebugDirectorySubject([{ payload, type: 1 }]);

  const result = await parseDebugDirectory(
    subject.file,
    subject.dataDirs,
    value => value,
    IMAGE_FILE_MACHINE_AMD64
  );

  const coff = expectDefined(result.entries[0]?.coff);
  assert.equal(coff.header?.numberOfSymbols, 1);
  assert.equal(coff.symbols[0]?.name, ".text");
  assert.equal(coff.lineNumberBlocks[0]?.records.length, 2);
});

void test("parseCoffDebugInfoFromFileHeader keeps whole symbols from truncated tables", async () => {
  const symbolTable = createSymbolTable([
    { name: ".text", storageClass: TEST_COFF_STORAGE_CLASS.STATIC },
    { name: "missing", storageClass: TEST_COFF_STORAGE_CLASS.EXTERNAL }
  ], []);
  const bytes = symbolTable.bytes.slice(0, IMAGE_SYMBOL_SIZE + 2);
  const warnings: string[] = [];

  const result = await parseCoffDebugInfoFromFileHeader(
    new MockFile(bytes),
    0,
    symbolTable.recordCount,
    [],
    message => warnings.push(message)
  );
  const truncatedWarnings: string[] = [];
  const parsed = await parseCoffDebugInfoFromFileHeader(
    new MockFile(bytes),
    1,
    symbolTable.recordCount,
    [],
    message => truncatedWarnings.push(message)
  );

  assert.equal(result, null);
  assert.deepEqual(warnings, []);
  assert.equal(parsed?.symbols.length, 1);
  assert.match(truncatedWarnings.join(" | "), /truncated/i);
});

void test("parseCoffDebugInfoFromFileHeader decodes remaining auxiliary record formats", async () => {
  const symbolTable = createSymbolTable([
    {
      name: ".bf",
      storageClass: TEST_COFF_STORAGE_CLASS.FUNCTION,
      auxRecords: [createAuxRecord()]
    },
    {
      name: "weak",
      sectionNumber: 0,
      storageClass: TEST_COFF_STORAGE_CLASS.EXTERNAL,
      auxRecords: [createAuxRecord()]
    },
    {
      name: ".text",
      sectionNumber: 1,
      storageClass: TEST_COFF_STORAGE_CLASS.STATIC,
      auxRecords: [createAuxRecord()]
    },
    {
      name: "auto",
      storageClass: TEST_COFF_STORAGE_CLASS.AUTOMATIC,
      auxRecords: [createAuxRecord()]
    }
  ], []);
  const warnings: string[] = [];

  const result = await parseCoffDebugInfoFromFileHeader(
    createOffsetFile(symbolTable.bytes),
    1,
    symbolTable.recordCount,
    [],
    message => warnings.push(message)
  );

  assert.equal(result?.symbols[0]?.auxiliaryRecords[0]?.kind, "begin-end-function");
  assert.equal(result?.symbols[1]?.auxiliaryRecords[0]?.kind, "weak-external");
  assert.equal(result?.symbols[2]?.auxiliaryRecords[0]?.kind, "section-definition");
  assert.equal(result?.symbols[3]?.auxiliaryRecords[0]?.kind, "raw");
  assert.deepEqual(warnings, []);
});
