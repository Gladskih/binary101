"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderHeaders } from "../../renderers/pe/headers.js";
import { createPeSection, createPeWithSections } from "../fixtures/pe-renderer-headers-fixture.js";
import { createSyntheticLegacyCoffStringTableFixture } from "../fixtures/pe-coff-tail-fixture.js";

const createPeWithLongSectionName = (): { longSectionName: string; nameStringTableOffset: number; html: string } => {
  const stringTable = createSyntheticLegacyCoffStringTableFixture(1);
  const firstLongSection = stringTable.entries[0];
  if (!firstLongSection) assert.fail("expected synthetic COFF string-table entry");
  const pe = createPeWithSections(
    createPeSection(firstLongSection.name, { coffStringTableOffset: firstLongSection.offset })
  );
  const out: string[] = [];
  renderHeaders(pe, out);
  return {
    longSectionName: firstLongSection.name,
    nameStringTableOffset: firstLongSection.offset,
    html: out.join("")
  };
};

void test("renderHeaders shows both the resolved long section name and its COFF string-table offset", () => {
  const { longSectionName, nameStringTableOffset, html } = createPeWithLongSectionName();

  assert.match(html, new RegExp(longSectionName));
  assert.match(html, new RegExp(`COFF name /${nameStringTableOffset}`));
});
