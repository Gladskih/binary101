"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderCoffTailSummary } from "../../renderers/pe/coff-tail-summary.js";
import { createPeSection, createPeWithSections } from "../fixtures/pe-renderer-headers-fixture.js";

void test("renderCoffTailSummary renders a structured legacy COFF tail section", () => {
  const pe = createPeWithSections(
    createPeSection(".debug_line", { coffStringTableOffset: 4, characteristics: 0x42000040 }),
    createPeSection(".debug_info", { coffStringTableOffset: 58, characteristics: 0x42000040 })
  );
  pe.coff.PointerToSymbolTable = 0x142c00;
  pe.coff.NumberOfSymbols = 1405;
  pe.coffStringTableSize = 72555;
  pe.trailingAlignmentPaddingSize = 459;

  const html = renderCoffTailSummary(pe);

  assert.ok(html, "expected COFF tail section");
  assert.match(html, /Legacy COFF tail/);
  assert.match(html, /SymbolTableOffset/);
  assert.match(html, /0x00142c00/);
  assert.match(html, /SymbolRecords/);
  assert.match(html, /1405/);
  assert.match(html, /SymbolTableSize/);
  assert.match(html, /24\.7 KB \(25290 bytes\)/);
  assert.match(html, /StringTableOffset/);
  assert.match(html, /0x00148eca/);
  assert.match(html, /StringTableSize/);
  assert.match(html, /70\.9 KB \(72555 bytes\)/);
  assert.match(html, /RecoveredLongSectionNames/);
  assert.match(html, /2/);
  assert.match(html, /TrailingAlignmentPadding/);
  assert.match(html, /459 B \(459 bytes\)/);
  assert.match(html, /Recovered long section names \(2\)/);
  assert.match(html, /\/4/);
  assert.match(html, /\.debug_line/);
  assert.match(html, /\/58/);
  assert.match(html, /\.debug_info/);
});

void test("renderCoffTailSummary returns null when no legacy COFF tail is present", () => {
  const pe = createPeWithSections(createPeSection(".text"));

  assert.equal(renderCoffTailSummary(pe), null);
});
