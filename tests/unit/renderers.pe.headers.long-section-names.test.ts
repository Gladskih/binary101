"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderHeaders } from "../../renderers/pe/headers.js";
import { createPeSection, createPeWithSections } from "../fixtures/pe-renderer-headers-fixture.js";

const createPeWithLongSectionName = (): { nameStringTableOffset: number; html: string } => {
  // COFF string-table entries start after the 4-byte size field, so /4 is the first valid offset.
  const nameStringTableOffset = 4;
  const pe = createPeWithSections(
    createPeSection(".debug_line", { coffStringTableOffset: nameStringTableOffset, characteristics: 0x42000040 })
  );
  const out: string[] = [];
  renderHeaders(pe, out);
  return { nameStringTableOffset, html: out.join("") };
};

void test("renderHeaders shows both the resolved long section name and its COFF string-table offset", () => {
  const { nameStringTableOffset, html } = createPeWithLongSectionName();

  assert.match(html, /\.debug_line/);
  assert.match(html, new RegExp(`COFF name /${nameStringTableOffset}`));
});
