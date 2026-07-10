"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../analyzers/dwarf/index.js";
import { renderDwarfAnalysis } from "../../../renderers/dwarf.js";
import { createDwarf4SectionsFixture } from "../../fixtures/dwarf-sections-fixture.js";

void test("renderDwarfAnalysis renders sections, units, producers, and tag counts", async () => {
  const fixture = createDwarf4SectionsFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);

  const html = renderDwarfAnalysis(dwarf);

  assert.ok(html.includes(".debug_info"));
  assert.ok(html.includes("main.c"));
  assert.ok(html.includes("fixture compiler"));
  assert.ok(html.includes("DW_LANG_C99"));
  assert.ok(html.includes("DW_TAG_subprogram"));
  assert.ok(html.includes("Line programs, ranges, locations"));
});

void test("renderDwarfAnalysis renders inventory-only, compressed, and issue states", () => {
  const html = renderDwarfAnalysis({
    sections: [
      { name: ".debug_line", offset: 0, size: 0, compressed: false, status: "inventory-only" },
      { name: ".zdebug_info", offset: 0, size: 0, compressed: true, status: "compressed-unsupported" },
      { name: ".zdebug_str", offset: 0, size: 0, compressed: true, status: "referenced" },
      {
        name: ".rela.debug_info",
        offset: 0,
        size: 0,
        compressed: false,
        requiresRelocations: true,
        status: "relocations-unsupported"
      }
    ],
    units: [],
    issues: ["bad <value>"]
  });

  assert.ok(html.includes("inventory only"));
  assert.ok(html.includes("compressed; not decoded"));
  assert.ok(html.includes("decompressed; used for references"));
  assert.ok(html.includes("relocations required; not decoded"));
  assert.ok(html.includes("bad &lt;value>"));
  assert.ok(!html.includes("<h5>Units</h5>"));
});
