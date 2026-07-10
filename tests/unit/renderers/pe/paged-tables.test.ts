"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { CoffDebugInfo, CoffSymbol } from "../../../../analyzers/coff/debug-types.js";
import type { PeDebugDirectoryEntry } from "../../../../analyzers/pe/debug/directory.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { MSVC_RTTI_LAYOUT } from "../../../../analyzers/pe/msvc-rtti/layout.js";
import { TEST_COFF_STORAGE_CLASS } from "../../../fixtures/pe-coff-debug-fixtures.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";

const createSymbol = (index: number): CoffSymbol => ({
  auxiliaryRecords: [],
  auxiliarySymbolCount: 0,
  index,
  name: `s${index}`,
  nameSource: "short",
  sectionNumber: 1,
  storageClass: TEST_COFF_STORAGE_CLASS.EXTERNAL,
  type: 0,
  value: index
});

const createCoffDebug = (): CoffDebugInfo => ({
  lineNumberBlocks: [],
  source: "coff-header",
  stringTableOffset: null,
  symbolTableOffset: 0x80,
  symbols: [createSymbol(0), createSymbol(1)]
});

const createDebugEntry = (coff: CoffDebugInfo): PeDebugDirectoryEntry => ({
  addressOfRawData: 0,
  characteristics: 0,
  coff,
  pointerToRawData: 0,
  sizeOfData: 0,
  type: 1,
  typeName: "COFF"
});

void test("getPePagedTableModel resolves file-header COFF symbol tables", () => {
  const pe = createBasePe();
  pe.coffDebug = createCoffDebug();

  const model = getPePagedTableModel(pe, "pe-coff-symbols-symbols");

  assert.equal(model?.id, "pe-coff-symbols-symbols");
  assert.equal(model?.rowCount, 2);
  assert.equal(model?.sortValueAt(1, 1), "s1");
});

void test("getPePagedTableModel resolves COFF tables inside debug entries", () => {
  const pe = createBasePe();
  pe.debug = {
    entries: [createDebugEntry({ ...createCoffDebug(), source: "debug-directory" })],
    entry: null,
    rawDataRanges: []
  };

  const model = getPePagedTableModel(pe, "pe-debug-entry-0-coff-symbols");

  assert.equal(model?.id, "pe-debug-entry-0-coff-symbols");
  assert.equal(model?.rowCount, 2);
  assert.equal(model?.sortValueAt(0, 1), "s0");
});

void test("getPePagedTableModel resolves Microsoft C++ RTTI main and detail tables", () => {
  const pe = createBasePe();
  pe.msvcRtti = {
    layout: MSVC_RTTI_LAYOUT,
    classHierarchies: [],
    completeObjectLocators: [{
      cdOffset: 0,
      classHierarchyDescriptorRva: 0x2200,
      offset: 0,
      rva: 0x2300,
      typeDescriptorRva: 0x2100
    }],
    types: [{ decoratedName: ".?AVPagedType@@", rva: 0x2100 }],
    vftables: [{
      completeObjectLocatorRva: 0x2300,
      functionTargetRvas: [0x1000, 0x1010],
      locatorSlotRva: 0x2400,
      rva: 0x2408
    }]
  };

  const main = getPePagedTableModel(pe, "pe-msvc-rtti-vftables");
  const slots = getPePagedTableModel(pe, "pe-msvc-rtti-vftable-0-slots");

  assert.equal(main?.rowCount, 1);
  assert.equal(slots?.rowCount, 2);
  assert.equal(slots?.sortValueAt(1, 2), "4112");
});
