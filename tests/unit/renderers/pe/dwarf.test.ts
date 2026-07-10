"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { renderPeDwarf } from "../../../../renderers/pe/dwarf.js";
import { createDwarf4SectionsFixture } from "../../../fixtures/dwarf-sections-fixture.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";

void test("renderPeDwarf wraps common DWARF analysis in a PE section", async () => {
  const fixture = createDwarf4SectionsFixture();
  const pe = createBasePe();
  pe.dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const out: string[] = [];

  renderPeDwarf(pe, out);

  const html = out.join("");
  assert.ok(html.includes("DWARF debug information"));
  assert.ok(html.includes("1 unit"));
  assert.ok(html.includes("main.c"));
});

void test("renderPeDwarf omits the section when DWARF is absent", () => {
  const out: string[] = [];
  renderPeDwarf(createBasePe(), out);
  assert.deepEqual(out, []);
});
