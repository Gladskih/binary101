"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSanity } from "../../../../../renderers/pe/layout.js";
import type { PeParseResult } from "../../../../../analyzers/pe/index.js";
import { createPeSection, createPeWithSections } from "../../../../fixtures/pe-renderer-headers-fixture.js";
import { createSyntheticLegacyCoffStringTableFixture } from "../../../../fixtures/pe-coff-tail-fixture.js";

const assertSanityAbsent = (html: string): void => assert.equal(html, "");

const createPeWithCoffTailFixture = (): {
  pe: PeParseResult;
  firstLongSectionOffset: number;
  rawImageEnd: number;
} => {
  const pe = createPeWithSections(createPeSection(""));
  const stringTable = createSyntheticLegacyCoffStringTableFixture(2);
  const firstLongSection = stringTable.entries[0];
  const firstSection = pe.sections[0];
  if (!firstLongSection) assert.fail("expected synthetic COFF string-table entry");
  if (!firstSection) assert.fail("expected PE section fixture");
  pe.imageSizeMismatch = false;
  pe.debug = null;
  pe.coff.PointerToSymbolTable = firstSection.pointerToRawData + firstSection.sizeOfRawData;
  // Smallest non-empty COFF symbol table: one 18-byte IMAGE_SYMBOL record per Microsoft PE/COFF.
  pe.coff.NumberOfSymbols = 1;
  pe.coffStringTableSize = stringTable.size;
  pe.opt.AddressOfEntryPoint = firstSection.virtualAddress;
  return {
    pe,
    firstLongSectionOffset: firstLongSection.offset,
    rawImageEnd: firstSection.pointerToRawData + firstSection.sizeOfRawData
  };
};

void test("renderSanity omits a clean result for a COFF tail after the last section", () => {
  const out: string[] = [];
  const fixture = createPeWithCoffTailFixture();

  renderSanity(fixture.pe, out);
  assertSanityAbsent(out.join(""));
});

void test("renderSanity omits a clean result for an overlay range after a COFF tail", () => {
  const out: string[] = [];
  const fixture = createPeWithCoffTailFixture();

  renderSanity(
    {
      ...fixture.pe,
      overlay: {
        ranges: [{
          start: fixture.rawImageEnd,
          end: fixture.rawImageEnd + fixture.firstLongSectionOffset,
          size: fixture.firstLongSectionOffset,
          findings: []
        }]
      }
    } as PeParseResult,
    out
  );

  assertSanityAbsent(out.join(""));
});

void test("renderSanity omits a clean result for trailing alignment padding", () => {
  const out: string[] = [];
  const fixture = createPeWithCoffTailFixture();
  const trailingAlignmentPaddingSize = fixture.pe.coffStringTableSize;
  if (trailingAlignmentPaddingSize == null) assert.fail("expected synthetic COFF string-table size");

  renderSanity(
    {
      ...fixture.pe,
      trailingAlignmentPaddingSize
    } as PeParseResult,
    out
  );

  assertSanityAbsent(out.join(""));
});
