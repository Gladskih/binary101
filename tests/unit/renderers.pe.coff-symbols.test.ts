"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderCoffSymbols } from "../../renderers/pe/coff-symbols.js";
import { createBasePe } from "../fixtures/pe-renderer-headers-fixture.js";
import { TEST_COFF_STORAGE_CLASS } from "../fixtures/pe-coff-debug-fixtures.js";

const render = (pe: ReturnType<typeof createBasePe>): string => {
  const out: string[] = [];
  renderCoffSymbols(pe, out);
  return out.join("");
};

void test("renderCoffSymbols renders file-header COFF symbols as a top-level section", () => {
  const pe = createBasePe();
  pe.coffDebug = {
    source: "coff-header",
    symbolTableOffset: 0x300,
    stringTableOffset: null,
    symbols: [{
      index: 0,
      name: ".file",
      nameSource: "short",
      value: 0,
      sectionNumber: -2,
      type: 0,
      storageClass: TEST_COFF_STORAGE_CLASS.FILE,
      auxiliarySymbolCount: 1,
      auxiliaryRecords: [{ kind: "file", fileName: "main.c" }]
    }],
    lineNumberBlocks: []
  };

  const html = render(pe);

  assert.match(html, /COFF symbols/);
  assert.match(html, /1 symbol/);
  assert.match(html, /PointerToSymbolTable\/NumberOfSymbols/);
  assert.match(html, /COFF file header/);
  assert.match(html, /main\.c/);
  assert.doesNotMatch(html, /Debug directory/);
});

void test("renderCoffSymbols renders standalone COFF warnings", () => {
  const pe = createBasePe();
  pe.coffDebug = {
    source: "coff-header",
    symbolTableOffset: 0xffff,
    stringTableOffset: null,
    symbols: [],
    lineNumberBlocks: [],
    warnings: ["COFF symbol table starts past end of file."]
  };

  const html = render(pe);

  assert.match(html, /0 symbols/);
  assert.match(html, /COFF symbol table starts past end of file/);
});
