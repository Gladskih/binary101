"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPe } from "../../../../renderers/pe/index.js";
import {
  getPeLazySectionDescriptors,
  PE_LAZY_SECTION_KEYS
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
