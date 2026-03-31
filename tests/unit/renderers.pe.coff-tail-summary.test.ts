"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderCoffTailSummary } from "../../renderers/pe/coff-tail-summary.js";
import { createPeSection, createPeWithSections } from "../fixtures/pe-renderer-headers-fixture.js";
import {
  COFF_SYMBOL_RECORD_SIZE,
  createSyntheticLegacyCoffStringTableFixture
} from "../fixtures/pe-coff-tail-fixture.js";

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
  pe.coffStringTableSize = stringTable.size;
  pe.trailingAlignmentPaddingSize = firstLongSection.offset;
  return { pe, firstLongSection, secondLongSection };
};

void test("renderCoffTailSummary renders a structured legacy COFF tail section", () => {
  const { pe, firstLongSection, secondLongSection } = createPeWithLegacyCoffTail();
  const symbolTableOffset = pe.coff.PointerToSymbolTable;
  const symbolTableSize = pe.coff.NumberOfSymbols * COFF_SYMBOL_RECORD_SIZE;
  const stringTableOffset = pe.coff.PointerToSymbolTable + pe.coff.NumberOfSymbols * COFF_SYMBOL_RECORD_SIZE;
  const trailingAlignmentPaddingSize = pe.trailingAlignmentPaddingSize;
  if (trailingAlignmentPaddingSize == null) assert.fail("expected trailing padding size");

  const html = renderCoffTailSummary(pe);

  assert.ok(html, "expected COFF tail section");
  assert.match(html, /Legacy COFF tail/);
  assert.match(html, /SymbolTableOffset/);
  assert.match(html, new RegExp(`0x${symbolTableOffset.toString(16).padStart(8, "0")}`));
  assert.match(html, /SymbolRecords/);
  assert.match(html, new RegExp(String(pe.coff.NumberOfSymbols)));
  assert.match(html, /SymbolTableSize/);
  assert.match(html, new RegExp(`${symbolTableSize} B \\(${symbolTableSize} bytes\\)`));
  assert.match(html, /StringTableOffset/);
  assert.match(html, new RegExp(`0x${stringTableOffset.toString(16).padStart(8, "0")}`));
  assert.match(html, /StringTableSize/);
  assert.match(html, new RegExp(`${pe.coffStringTableSize} B \\(${pe.coffStringTableSize} bytes\\)`));
  assert.match(html, /RecoveredLongSectionNames/);
  assert.match(html, new RegExp(String(pe.coff.NumberOfSymbols)));
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

void test("renderCoffTailSummary returns null when no legacy COFF tail is present", () => {
  const pe = createPeWithSections(createPeSection(""));

  assert.equal(renderCoffTailSummary(pe), null);
});
