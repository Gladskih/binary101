"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { MSVC_RTTI_LAYOUT } from "../../../../analyzers/pe/msvc-rtti/layout.js";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/core/parse-result.js";
import { renderAutoPagedSortableTable } from "../../../../renderers/paged-sortable-table.js";
import {
  formatMsvcRttiBaseAttributes,
  formatMsvcRttiHierarchyAttributes,
  formatMsvcRttiRva,
  formatMsvcRttiVa
} from "../../../../renderers/pe/msvc-rtti-details.js";
import {
  getMsvcRttiPagedTableModel,
  MSVC_RTTI_VFTABLE_TABLE_ID
} from "../../../../renderers/pe/msvc-rtti-table.js";
import { collectPeExactSymbolNames } from "../../../../renderers/pe/msvc-rtti-symbols.js";
import {
  getMsvcRttiSummaryCounts,
  renderMsvcRtti
} from "../../../../renderers/pe/msvc-rtti.js";
import {
  createBasePe,
  createPeSection
} from "../../../fixtures/pe-renderer-headers-fixture.js";

const createMsvcRttiPe = (): PeWindowsParseResult => {
  const pe = createBasePe();
  pe.coff.Machine = 0x8664;
  pe.opt.Magic = 0x20b;
  pe.opt.ImageBase = 0x1_4000_0000n;
  pe.opt.SizeOfImage = 0x5000;
  pe.sections = [createPeSection(".text", {
    characteristics: 0x60000020,
    virtualAddress: 0x1000,
    virtualSize: 0x1000
  })];
  pe.exports = {
    entries: [
      { forwarder: null, name: "export<target>", ordinal: 1, rva: 0x1010 },
      { forwarder: "other.dll.Target", name: "forwarded", ordinal: 2, rva: 0x1020 }
    ]
  } as PeWindowsParseResult["exports"];
  pe.debug = {
    entry: null,
    entries: [{
      addressOfRawData: 0,
      characteristics: 0,
      pointerToRawData: 0,
      pogo: {
        entries: [{ name: "pogo<target>", size: 16, startRva: 0x1020 }],
        signature: 0x50474f00,
        signatureName: "PGO"
      },
      sizeOfData: 0,
      type: 13,
      typeName: "POGO"
    }],
    rawDataRanges: []
  };
  pe.msvcRtti = {
    layout: MSVC_RTTI_LAYOUT,
    types: [
      { decoratedName: ".?AVDerived<Widget>@@", rva: 0x3000 },
      { decoratedName: ".?AVBase@@", rva: 0x3040 }
    ],
    classHierarchies: [{
      attributes: 0x3,
      root: {
        attributes: 0x40,
        children: [{
          attributes: 0x54,
          children: [],
          classHierarchyDescriptorRva: 0x3100,
          descriptorRva: 0x3220,
          numContainedBases: 0,
          pmd: { mdisp: 16, pdisp: -1, vdisp: 4 },
          typeDescriptorRva: 0x3040
        }],
        classHierarchyDescriptorRva: 0x3100,
        descriptorRva: 0x3200,
        numContainedBases: 1,
        pmd: { mdisp: 0, pdisp: -1, vdisp: 0 },
        typeDescriptorRva: 0x3000
      },
      rva: 0x3100
    }],
    completeObjectLocators: [{
      cdOffset: 4,
      classHierarchyDescriptorRva: 0x3100,
      offset: 8,
      rva: 0x3300,
      typeDescriptorRva: 0x3000
    }],
    vftables: [{
      completeObjectLocatorRva: 0x3300,
      functionTargetRvas: [0x1010, 0x1020, 0x1010],
      locatorSlotRva: 0x3400,
      rva: 0x3408
    }]
  };
  return pe;
};

void test("renderMsvcRtti renders summary, COL relationships, bases, slots, and escapes names", () => {
  const out: string[] = [];

  renderMsvcRtti(createMsvcRttiPe(), out);
  const html = out.join("");

  assert.match(html, /Microsoft C\+\+ RTTI/);
  assert.match(html, /microsoft-cxx-amd64-image-relative-rtti-rev1/);
  assert.match(html, /Unique types<\/dt><dd>2/);
  assert.match(html, /Unique virtual function targets<\/dt><dd>2/);
  assert.match(html, /0x140003300/);
  assert.match(html, /0x00003300/);
  assert.match(html, /vfptr offset/);
  assert.match(html, /multiple inheritance, virtual inheritance/);
  assert.match(html, /Base classes \(preorder\)/);
  assert.match(html, /private\/protected base, virtual base of complete object/);
  assert.match(html, /<td class="peNumeric" data-sort-value="-1">-1<\/td>/);
  assert.match(html, /export&lt;target>/);
  assert.match(html, /pogo&lt;target>/);
  assert.match(html, /\.\?AVDerived&lt;Widget>@@/);
  assert.ok(!html.includes("<Widget>"));
  assert.ok(!html.includes("export<target>"));
});

void test("RTTI table models preserve preorder rows and ordered duplicate slots", () => {
  const pe = createMsvcRttiPe();

  const main = getMsvcRttiPagedTableModel(pe, MSVC_RTTI_VFTABLE_TABLE_ID);
  const bases = getMsvcRttiPagedTableModel(pe, "pe-msvc-rtti-vftable-0-bases");
  const slots = getMsvcRttiPagedTableModel(pe, "pe-msvc-rtti-vftable-0-slots");

  assert.equal(main?.rowCount, 1);
  assert.equal(main?.pageSize, 250);
  assert.match(main?.rowAt(0)?.additionalRowsHtml ?? "", /Show inheritance and 3 vftable slot/);
  assert.equal(bases?.rowCount, 2);
  assert.equal(bases?.sortValueAt(0, 1), "0");
  assert.equal(bases?.sortValueAt(1, 1), "1");
  assert.equal(slots?.rowCount, 3);
  assert.equal(slots?.sortValueAt(0, 2), "4112");
  assert.equal(slots?.sortValueAt(2, 2), "4112");
  assert.equal(getMsvcRttiPagedTableModel(pe, "pe-msvc-rtti-vftable-4-slots"), null);
  assert.equal(getMsvcRttiPagedTableModel(pe, "unrelated"), null);
});

void test("RTTI main table switches to paging only above its UI page size", () => {
  const pe = createMsvcRttiPe();
  const original = pe.msvcRtti!.vftables[0]!;
  pe.msvcRtti!.vftables = Array.from({ length: 251 }, (_, index) => ({
    ...original,
    locatorSlotRva: original.locatorSlotRva + index * 8,
    rva: original.rva + index * 8
  }));

  const model = getMsvcRttiPagedTableModel(pe, MSVC_RTTI_VFTABLE_TABLE_ID);
  const html = model ? renderAutoPagedSortableTable(model) : "";

  assert.match(html, /data-paged-sortable-table-id="pe-msvc-rtti-vftables"/);
  assert.match(html, /Showing 1-250 of 251/);
});

void test("RTTI attribute and address formatters retain signed PMD context and known bits", () => {
  // MSVC rttidata.h: CHD_MULTINH | CHD_AMBIGUOUS.
  assert.equal(formatMsvcRttiHierarchyAttributes(0x5), "multiple inheritance, ambiguous");
  assert.equal(formatMsvcRttiHierarchyAttributes(0), "none");
  assert.equal(formatMsvcRttiHierarchyAttributes(0x8), "unknown 0x00000008");
  // MSVC rttidata.h: BCD_PRIVORPROTBASE | BCD_VBOFCONTOBJ.
  assert.equal(
    formatMsvcRttiBaseAttributes(0x14),
    "private/protected base, virtual base of complete object"
  );
  assert.equal(formatMsvcRttiRva(0x1234), "0x00001234");
  assert.equal(formatMsvcRttiVa(0x1_4000_0000n, 0x1234), "0x140001234");
});

void test("RTTI summary counts addresses and function targets uniquely", () => {
  const analysis = createMsvcRttiPe().msvcRtti!;
  analysis.types.push({ ...analysis.types[0]! });
  analysis.completeObjectLocators.push({ ...analysis.completeObjectLocators[0]! });
  analysis.vftables.push({ ...analysis.vftables[0]! });

  assert.deepEqual(getMsvcRttiSummaryCounts(analysis), {
    completeObjectLocators: 1,
    types: 2,
    vftables: 1,
    virtualFunctionTargets: 2
  });
});

void test("collectPeExactSymbolNames uses exact export, POGO, COFF, and Go RVAs", () => {
  const pe = createMsvcRttiPe();
  pe.coffDebug = {
    lineNumberBlocks: [],
    source: "coff-header",
    stringTableOffset: null,
    symbolTableOffset: 0,
    symbols: [{
      auxiliaryRecords: [],
      auxiliarySymbolCount: 0,
      index: 0,
      name: "coffSymbol",
      nameSource: "short",
      sectionNumber: 1,
      storageClass: 2,
      type: 0x20,
      value: 0x30
    }]
  };
  pe.goRuntime = {
    fileCount: 0,
    functions: [{ name: "goSymbol", start: 0x1_4000_1050n, end: 0x1_4000_1060n }],
    layout: "go1.20+",
    moduleDataAddress: 0x1_4000_2000n,
    pcHeaderAddress: 0x1_4000_2100n,
    pointerSize: 8,
    textRange: { start: 0x1_4000_1000n, end: 0x1_4000_2000n }
  };

  const names = collectPeExactSymbolNames(pe);

  assert.deepEqual(names.get(0x1010), ["export<target>"]);
  assert.deepEqual(names.get(0x1020), ["pogo<target>"]);
  assert.deepEqual(names.get(0x1030), ["coffSymbol"]);
  assert.deepEqual(names.get(0x1050), ["goSymbol"]);
  assert.equal(names.has(0x1020) && names.get(0x1020)?.includes("forwarded"), false);
});
