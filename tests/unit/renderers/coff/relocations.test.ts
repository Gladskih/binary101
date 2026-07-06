"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCoffObject } from "../../../../analyzers/coff/index.js";
import {
  createCoffRelocationTableModel,
  renderCoffRelocations
} from "../../../../renderers/coff/relocations.js";
import { createCoffObjectFile } from "../../../fixtures/coff-object-fixture.js";

void test("renderCoffRelocations renders COFF relocation records with symbol and type labels", async () => {
  const coff = await parseCoffObject(createCoffObjectFile());
  if (!coff?.relocations?.[0]) assert.fail("expected parsed COFF relocations");
  const out: string[] = [];

  renderCoffRelocations(coff, out);
  const html = out.join("");

  assert.match(html, /COFF relocations/);
  assert.match(html, /#2 target/);
  assert.match(html, /IMAGE_REL_I386_REL32/);
});

void test("createCoffRelocationTableModel exposes relocation rows for paging", async () => {
  const coff = await parseCoffObject(createCoffObjectFile());
  if (!coff?.relocations?.[0]) assert.fail("expected parsed COFF relocations");

  const model = createCoffRelocationTableModel(coff, coff.relocations[0], "relocations-test");

  assert.equal(model.rowCount, 1);
  assert.match(model.rowAt(0)?.cells[3]?.html ?? "", /target/);
  assert.equal(model.sortValueAt(0, 4), "IMAGE_REL_I386_REL32");
});
