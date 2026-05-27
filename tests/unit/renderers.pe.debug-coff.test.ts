"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeCoffDebugInfo, PeCoffSymbol } from "../../analyzers/pe/debug/directory.js";
import { renderCoffDebugInfo } from "../../renderers/pe/debug-coff.js";
import { TEST_COFF_STORAGE_CLASS } from "../fixtures/pe-coff-debug-fixtures.js";

const createSymbol = (
  index: number,
  overrides: Partial<PeCoffSymbol> = {}
): PeCoffSymbol => ({
  index,
  name: `s${index}`,
  nameSource: "short",
  value: index,
  sectionNumber: 1,
  type: 0,
  storageClass: TEST_COFF_STORAGE_CLASS.EXTERNAL,
  auxiliarySymbolCount: 0,
  auxiliaryRecords: [],
  ...overrides
});

const render = (info: PeCoffDebugInfo): string => {
  const out: string[] = [];
  renderCoffDebugInfo(info, out);
  return out.join("");
};

void test("renderCoffDebugInfo renders headers, warnings, all rows, and aux summaries", () => {
  const symbols = Array.from({ length: 201 }, (_, index) => createSymbol(index));
  symbols[0] = createSymbol(0, {
    type: 0x32,
    // Deliberately not a Microsoft-defined PE/COFF storage class; exercises renderer fallback.
    storageClass: 0xee,
    auxiliaryRecords: [
      { kind: "begin-end-function", lineNumber: 9, pointerToNextFunction: 0 },
      { kind: "weak-external", tagIndex: 3, characteristics: 1 },
      { kind: "section-definition", length: 0x20, numberOfRelocations: 1, numberOfLineNumbers: 2, checkSum: 3, number: 4, selection: 5 },
      { kind: "raw", bytes: [1, 2, 3] }
    ]
  });
  const html = render({
    source: "debug-directory",
    header: {
      numberOfSymbols: symbols.length,
      lvaToFirstSymbol: 0,
      numberOfLineNumbers: 201,
      lvaToFirstLineNumber: 0,
      rvaToFirstByteOfCode: 0x1000,
      rvaToLastByteOfCode: 0x1010,
      rvaToFirstByteOfData: 0x2000,
      rvaToLastByteOfData: 0x2010
    },
    symbolTableOffset: 0x80,
    stringTableOffset: 0x200,
    stringTableSize: 0x20,
    symbols,
    lineNumberBlocks: [{
      offset: 0x300,
      sectionName: ".text",
      records: Array.from({ length: 201 }, (_, index) => ({
        symbolTableIndexOrVirtualAddress: 0x1000 + index,
        lineNumber: index + 1
      }))
    }],
    warnings: ["COFF warning"]
  });

  assert.match(html, /Code RVA range/);
  assert.match(html, /CLASS_0xee/);
  assert.match(html, /array CHAR/);
  assert.match(html, /line 9/);
  assert.match(html, /weak -> #3/);
  assert.match(html, /section 32 B/);
  assert.match(html, /3 raw bytes/);
  assert.match(html, /<td>s200<\/td>/);
  assert.match(html, /<td>201<\/td>/);
  assert.doesNotMatch(html, /Showing first/);
  assert.match(html, /COFF warning/);
});

void test("renderCoffDebugInfo omits empty optional tables", () => {
  const html = render({
    source: "coff-header",
    symbolTableOffset: 0,
    stringTableOffset: null,
    symbols: [],
    lineNumberBlocks: []
  });

  assert.match(html, /COFF file header/);
  assert.match(html, /not present/);
  assert.doesNotMatch(html, /<table/);
});

void test("renderCoffDebugInfo labels IMAGE_SYM_CLASS_BLOCK storage class", () => {
  const html = render({
    source: "coff-header",
    symbolTableOffset: 0,
    stringTableOffset: null,
    symbols: [createSymbol(0, {
      name: ".bb",
      // Microsoft PE/COFF: IMAGE_SYM_CLASS_BLOCK has value 100.
      storageClass: 100
    })],
    lineNumberBlocks: []
  });

  assert.match(html, /BLOCK/);
});
