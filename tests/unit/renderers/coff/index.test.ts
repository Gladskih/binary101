"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCoffObject } from "../../../../analyzers/coff/index.js";
import { renderCoff } from "../../../../renderers/coff/index.js";
import { createCoffObjectFile } from "../../../fixtures/coff-object-fixture.js";

void test("renderCoff renders COFF object headers and symbol tables outside the PE renderer", async () => {
  const coff = await parseCoffObject(createCoffObjectFile());
  if (!coff) assert.fail("expected parsed COFF object");

  const html = renderCoff(coff);

  assert.match(html, /COFF file header/);
  assert.match(html, /Section headers/);
  assert.match(html, /data-section-entropy-action/);
  assert.match(html, /Calculate entropy/);
  assert.match(html, /Not calculated/);
  assert.match(html, /COFF relocations/);
  assert.match(html, /IMAGE_REL_I386_REL32/);
  assert.match(html, /COFF symbol table/);
  assert.match(html, /target/);
  assert.match(html, /main\.c/);
  assert.doesNotMatch(html, /PE signature/);
  assert.doesNotMatch(html, /DOS header/);
});
