"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSanity } from "../../renderers/pe/layout.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import { createPeSection, createPeWithSections } from "../fixtures/pe-renderer-headers-fixture.js";
import {
  COFF_SYMBOL_RECORD_SIZE,
  createSyntheticLegacyCoffStringTableFixture
} from "../fixtures/pe-coff-tail-fixture.js";

const createPeWithCoffTailFixture = (): { pe: PeParseResult; knownCoffTailSize: number } => {
  const pe = createPeWithSections(createPeSection(""));
  const stringTable = createSyntheticLegacyCoffStringTableFixture(2);
  const firstSection = pe.sections[0];
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
    knownCoffTailSize: pe.coff.NumberOfSymbols * COFF_SYMBOL_RECORD_SIZE + pe.coffStringTableSize
  };
};

void test("renderSanity does not flag COFF symbol and string tables after the last section", () => {
  const out: string[] = [];
  const fixture = createPeWithCoffTailFixture();

  renderSanity({ ...fixture.pe, overlaySize: fixture.knownCoffTailSize } as PeParseResult, out);

  const html = out.join("");
  assert.ok(!html.includes("Overlay after last section"));
  assert.ok(html.includes("No obvious structural issues"));
});

void test("renderSanity still reports bytes that remain after the known COFF tail", () => {
  const out: string[] = [];
  const fixture = createPeWithCoffTailFixture();

  renderSanity(
    { ...fixture.pe, overlaySize: fixture.knownCoffTailSize + 16 } as PeParseResult,
    out
  );

  assert.ok(out.join("").includes("Overlay after last section: 16 B (16 bytes)."));
});

void test("renderSanity does not flag explicit trailing alignment padding after the known COFF tail", () => {
  const out: string[] = [];
  const fixture = createPeWithCoffTailFixture();
  const trailingAlignmentPaddingSize = 0x20;

  renderSanity(
    {
      ...fixture.pe,
      // Keep overlay 4 bytes shorter than known COFF tail + zero padding to prove clipping works.
      overlaySize: fixture.knownCoffTailSize + trailingAlignmentPaddingSize - 4,
      trailingAlignmentPaddingSize
    } as PeParseResult,
    out
  );

  assert.ok(!out.join("").includes("Overlay after last section"));
});
