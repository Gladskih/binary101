"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { COFF_SYMBOL_RECORD_BYTE_LENGTH } from "../../../../analyzers/coff/layout.js";
import { renderCoffTailSummary } from "../../../../renderers/pe/coff-tail-summary.js";
import { createPeSection, createPeWithSections } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createSyntheticLegacyCoffStringTableFixture } from "../../../fixtures/pe-coff-tail-fixture.js";
import { TEST_COFF_STORAGE_CLASS } from "../../../fixtures/pe-coff-debug-fixtures.js";

const countMatches = (html: string, pattern: RegExp): number => [...html.matchAll(pattern)].length;

const createPeWithLegacyCoffTail = () => {
  const stringTable = createSyntheticLegacyCoffStringTableFixture(2);
  const firstLongSection = stringTable.entries[0];
  const secondLongSection = stringTable.entries[1];
  if (!firstLongSection || !secondLongSection) assert.fail("expected synthetic COFF string-table entries");
  const pe = createPeWithSections(
    createPeSection(firstLongSection.name, { coffStringTableOffset: firstLongSection.offset }),
    createPeSection(secondLongSection.name, { coffStringTableOffset: secondLongSection.offset })
  );
  const lastSection = pe.sections[pe.sections.length - 1];
  if (!lastSection) assert.fail("expected legacy COFF tail test section");
  pe.coff.PointerToSymbolTable = lastSection.pointerToRawData + lastSection.sizeOfRawData;
  pe.coff.NumberOfSymbols = stringTable.entries.length;
  const stringTableOffset = pe.coff.PointerToSymbolTable +
    pe.coff.NumberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  pe.coffStringTableSize = stringTable.size;
  pe.trailingAlignmentPaddingSize = firstLongSection.offset;
  pe.coffDebug = {
    source: "coff-header",
    symbolTableOffset: pe.coff.PointerToSymbolTable,
    stringTableOffset,
    stringTableSize: stringTable.size,
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
  return { pe, firstLongSection, secondLongSection };
};

void test("renderCoffTailSummary renders a structured legacy COFF tail section", () => {
  const { pe, firstLongSection, secondLongSection } = createPeWithLegacyCoffTail();
  const symbolTableOffset = pe.coff.PointerToSymbolTable;
  const symbolTableSize = pe.coff.NumberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  const stringTableOffset = pe.coff.PointerToSymbolTable +
    pe.coff.NumberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  const trailingAlignmentPaddingSize = pe.trailingAlignmentPaddingSize;
  if (trailingAlignmentPaddingSize == null) assert.fail("expected trailing padding size");

  const html = renderCoffTailSummary(pe);

  assert.ok(html, "expected COFF tail section");
  assert.match(html, /<details class="peSectionDetails">/);
  assert.match(html, /<summary[^>]*><b>Legacy COFF tail<\/b> - 2 symbol-table records<\/summary>/);
  assert.match(html, /SymbolTableOffset/);
  assert.match(html, new RegExp(`0x${symbolTableOffset.toString(16).padStart(8, "0")}`));
  assert.match(html, /SymbolTableRecords/);
  assert.match(html, new RegExp(String(pe.coff.NumberOfSymbols)));
  assert.match(html, /SymbolTableSize/);
  assert.match(html, new RegExp(`${symbolTableSize} B \\(${symbolTableSize} bytes\\)`));
  assert.match(html, /StringTableOffset/);
  assert.match(html, new RegExp(`0x${stringTableOffset.toString(16).padStart(8, "0")}`));
  assert.match(html, /StringTableSize/);
  assert.match(html, new RegExp(`${pe.coffStringTableSize} B \\(${pe.coffStringTableSize} bytes\\)`));
  assert.match(html, /RecoveredLongSectionNames/);
  assert.match(html, new RegExp(String(pe.coff.NumberOfSymbols)));
  assert.match(html, /<dt[^>]*>PrimarySymbolsParsed<\/dt><dd>1<\/dd>/);
  assert.match(html, /<dt[^>]*>AuxiliaryRecordsParsed<\/dt><dd>1<\/dd>/);
  assert.match(html, /<dt[^>]*>SymbolRecordsParsed<\/dt><dd>2<\/dd>/);
  assert.match(html, /Parsed COFF symbol table/);
  assert.match(html, /NumberOfSymbols counts symbol-table records, including auxiliary records/);
  assert.match(html, /data-sort-state-key="pe-coff-symbols-symbols"/);
  assert.equal(countMatches(html, /PrimarySymbolsParsed/g), 1);
  assert.equal(countMatches(html, /AuxiliaryRecordsParsed/g), 1);
  assert.equal(countMatches(html, /SymbolRecordsParsed/g), 1);
  assert.doesNotMatch(html, /<dt[^>]*>Source<\/dt>/);
  assert.doesNotMatch(html, /<dt[^>]*>Symbol table<\/dt>/);
  assert.doesNotMatch(html, /Primary symbols parsed/);
  assert.match(html, /main\.c/);
  assert.match(html, /TrailingAlignmentPadding/);
  assert.match(
    html,
    new RegExp(`${trailingAlignmentPaddingSize} B \\(${trailingAlignmentPaddingSize} bytes\\)`)
  );
  assert.match(html, new RegExp(`Recovered long section names \\(${pe.coff.NumberOfSymbols}\\)`));
  assert.match(html, new RegExp(`/${firstLongSection.offset}`));
  assert.match(html, new RegExp(firstLongSection.name));
  assert.match(html, new RegExp(`/${secondLongSection.offset}`));
  assert.match(html, new RegExp(secondLongSection.name));
});

void test("renderCoffTailSummary does not duplicate debug-directory COFF as a file-header tail", () => {
  const { pe } = createPeWithLegacyCoffTail();
  if (!pe.coffDebug) assert.fail("expected file-header COFF debug fixture");
  pe.coffDebug = { ...pe.coffDebug, source: "debug-directory" };

  const html = renderCoffTailSummary(pe);

  assert.ok(html, "expected COFF tail section");
  assert.doesNotMatch(html, /Parsed COFF symbol table/);
  assert.doesNotMatch(html, /PrimarySymbolsParsed/);
});

void test("renderCoffTailSummary renders singular symbol-table record wording", () => {
  const pe = createPeWithSections(createPeSection(".text"));
  pe.coff.PointerToSymbolTable = 0x300;
  pe.coff.NumberOfSymbols = 1;

  const html = renderCoffTailSummary(pe);

  assert.match(html ?? "", /<summary[^>]*><b>Legacy COFF tail<\/b> - 1 symbol-table record<\/summary>/);
});

void test("renderCoffTailSummary returns null when no legacy COFF tail is present", () => {
  const pe = createPeWithSections(createPeSection(""));

  assert.equal(renderCoffTailSummary(pe), null);
});
