"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCoffObject } from "../../../../analyzers/coff/index.js";
import { getCoffPagedTableModel } from "../../../../renderers/coff/paged-tables.js";
import { coffRelocationTableId } from "../../../../renderers/coff/relocations.js";
import { createCoffObjectFile } from "../../../fixtures/coff-object-fixture.js";

void test("getCoffPagedTableModel dispatches COFF relocation tables by section", async () => {
  const coff = await parseCoffObject(createCoffObjectFile());
  if (!coff?.relocations?.[0]) assert.fail("expected parsed COFF relocations");

  const model = getCoffPagedTableModel(coff, coffRelocationTableId(1));

  assert.equal(model?.rowCount, 1);
  assert.match(model?.rowAt(0)?.cells[3]?.html ?? "", /target/);
});
