"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPe } from "../../../../renderers/pe/index.js";
import { MSVC_RTTI_LAYOUT } from "../../../../analyzers/pe/msvc-rtti/layout.js";
import {
  getPeLazySectionDescriptors,
  PE_LAZY_SECTION_KEYS,
  type PeLazySectionKey
} from "../../../../renderers/pe/lazy-section-shells.js";
import { createPeWithImportLinking } from "../../../fixtures/pe-import-linking-fixture.js";
import {
  createBasePe,
  createPeSection
} from "../../../fixtures/pe-renderer-headers-fixture.js";

void test("renderPe emits PE section shells without eager heavy section rows", () => {
  const pe = createPeWithImportLinking();

  const html = renderPe(pe);

  assert.ok(html.includes('data-pe-lazy-section="imports"'));
  assert.ok(html.includes("imports: 2 DLL / 2 functions"));
  assert.match(
    html,
    /data-pe-lazy-section="imports"[\s\S]*data-pe-lazy-section-body><\/div>/
  );
  assert.ok(!html.includes("OriginalFirstThunk"));
  assert.ok(!html.includes("data-sort-value=\"Sleep\""));
});

void test("getPeLazySectionDescriptors keeps import counters in the section shell", () => {
  const pe = createPeWithImportLinking();

  const imports = getPeLazySectionDescriptors(pe).find(
    section => section.key === PE_LAZY_SECTION_KEYS.imports
  );

  assert.deepEqual(imports, {
    id: "peImportsPanel",
    key: PE_LAZY_SECTION_KEYS.imports,
    summary: "imports: 2 DLL / 2 functions",
    title: "Import table"
  });
});

void test("getPeLazySectionDescriptors creates one section per packaging analyzer", () => {
  const pe = createPeWithImportLinking();
  pe.packers = {
    reports: [
      { id: "upx", findings: [], warnings: ["UPX warning"] },
      { id: "nsis-installer", findings: [], warnings: ["NSIS warning"] },
      { id: "bun-standalone", findings: [], warnings: ["Bun warning"] }
    ]
  };

  const packaging = getPeLazySectionDescriptors(pe).filter(section =>
    ([
      PE_LAZY_SECTION_KEYS.upx,
      PE_LAZY_SECTION_KEYS.nsisInstaller,
      PE_LAZY_SECTION_KEYS.bunStandalone
    ] as PeLazySectionKey[]).includes(section.key)
  );

  assert.deepEqual(packaging, [
    { key: PE_LAZY_SECTION_KEYS.upx, summary: "1 warning", title: "UPX executable packer" },
    { key: PE_LAZY_SECTION_KEYS.nsisInstaller, summary: "1 warning", title: "NSIS installer" },
    {
      key: PE_LAZY_SECTION_KEYS.bunStandalone,
      summary: "1 warning",
      title: "Bun standalone executable"
    }
  ]);
});

void test("getPeLazySectionDescriptors shows residual overlay supplied by the analyzer", () => {
  const pe = createBasePe();
  pe.overlay = {
    ranges: [{ start: 0x400, end: 0x500, size: 0x100, findings: [] }]
  };
  pe.packers = {
    reports: [{
      id: "nsis-installer",
      findings: [{
        id: "nsis-installer",
        name: "NSIS installer",
        kind: "installer",
        confidence: "high",
        evidence: ["NSIS verified"],
        headerSize: 16,
        firstHeaderOffset: 0x400,
        flags: 0,
        followingDataSize: 0x100
      }],
      warnings: []
    }]
  };

  const descriptors = getPeLazySectionDescriptors(pe);

  assert.equal(descriptors.some(section => section.key === PE_LAZY_SECTION_KEYS.overlay), true);
  assert.equal(descriptors.some(section => section.key === PE_LAZY_SECTION_KEYS.nsisInstaller), true);
});

void test("getPeLazySectionDescriptors exposes only standalone payload archives", () => {
  const pe = createBasePe();
  pe.payloads = {
    entries: [
      { start: 0x400, end: 0x500, format: "sevenzip", source: "nsis" },
      { start: 0x600, end: 0x700, format: "rar", source: "overlay" }
    ]
  };

  const descriptor = getPeLazySectionDescriptors(pe).find(
    section => section.key === PE_LAZY_SECTION_KEYS.payloads
  );

  assert.deepEqual(descriptor, {
    key: PE_LAZY_SECTION_KEYS.payloads,
    summary: "1 validated payload(s)",
    title: "Embedded payloads"
  });
});

void test("getPeLazySectionDescriptors groups file-header COFF symbols into legacy tail", () => {
  const pe = createBasePe();
  pe.coff.PointerToSymbolTable = 0x300;
  pe.coff.NumberOfSymbols = 2;
  pe.coffDebug = {
    lineNumberBlocks: [],
    source: "coff-header",
    stringTableOffset: null,
    symbolTableOffset: 0x300,
    symbols: []
  };

  const descriptors = getPeLazySectionDescriptors(pe);
  const legacyCoffTail = descriptors.find(
    section => section.key === PE_LAZY_SECTION_KEYS.legacyCoffTail
  );

  assert.deepEqual(legacyCoffTail, {
    key: PE_LAZY_SECTION_KEYS.legacyCoffTail,
    summary: "2 symbol-table records",
    title: "Legacy COFF tail"
  });
  assert.equal(descriptors.some(section => section.title === "COFF symbols"), false);
});

void test("getPeLazySectionDescriptors renders singular COFF tail record summary", () => {
  const pe = createBasePe();
  pe.coff.PointerToSymbolTable = 0x300;
  pe.coff.NumberOfSymbols = 1;

  const legacyCoffTail = getPeLazySectionDescriptors(pe).find(
    section => section.key === PE_LAZY_SECTION_KEYS.legacyCoffTail
  );

  assert.deepEqual(legacyCoffTail, {
    key: PE_LAZY_SECTION_KEYS.legacyCoffTail,
    summary: "1 symbol-table record",
    title: "Legacy COFF tail"
  });
});

void test("renderPe emits a sanity shell for entrypoint section issues", () => {
  const pe = createBasePe();
  pe.opt.AddressOfEntryPoint = 0x1000;
  pe.sections = [createPeSection(".rdata", { characteristics: 0x40000040 })];
  pe.coff.NumberOfSections = pe.sections.length;

  const html = renderPe(pe);

  assert.ok(html.includes('data-pe-lazy-section="sanity"'));
  assert.ok(html.includes("structural findings"));
  assert.match(
    html,
    /data-pe-lazy-section="sanity"[\s\S]*data-pe-lazy-section-body><\/div>/
  );
  assert.ok(!html.includes("Entry point is in a non-executable section"));
});

void test("getPeLazySectionDescriptors exposes DWARF as a lazy section", () => {
  const pe = createBasePe();
  pe.dwarf = {
    sections: [],
    units: [],
    linePrograms: [],
    issues: ["fixture notice"]
  };

  const descriptor = getPeLazySectionDescriptors(pe).find(
    section => section.key === PE_LAZY_SECTION_KEYS.dwarf
  );
  const html = renderPe(pe);

  assert.deepEqual(descriptor, {
    key: PE_LAZY_SECTION_KEYS.dwarf,
    summary: "0 units",
    title: "DWARF debug information"
  });
  assert.ok(html.includes('data-pe-lazy-section="dwarf"'));
  assert.ok(!html.includes("fixture notice"));
});

void test("getPeLazySectionDescriptors exposes Microsoft C++ RTTI without eager rows", () => {
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
    types: [{ decoratedName: ".?AVLazyType@@", rva: 0x2100 }],
    vftables: [{
      completeObjectLocatorRva: 0x2300,
      functionTargetRvas: [0x1000],
      locatorSlotRva: 0x2400,
      rva: 0x2408
    }]
  };

  const descriptor = getPeLazySectionDescriptors(pe).find(
    section => section.key === PE_LAZY_SECTION_KEYS.msvcRtti
  );
  const html = renderPe(pe);

  assert.deepEqual(descriptor, {
    key: PE_LAZY_SECTION_KEYS.msvcRtti,
    summary: "1 type / 1 COL / 1 vftable",
    title: "Microsoft C++ RTTI"
  });
  assert.ok(html.includes('data-pe-lazy-section="msvc-rtti"'));
  assert.ok(!html.includes(".?AVLazyType@@"));
});
