"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderInnoSetupFindingDetails } from "../../../../renderers/pe/inno-setup.js";
import { createInnoFinding } from "../../../fixtures/inno-setup-fixture.js";

void test("renderInnoSetupFindingDetails shows validated bounds and engine action", () => {
  const html = renderInnoSetupFindingDetails(createInnoFinding());

  assert.ok(html.includes("Loader table"));
  assert.ok(html.includes("Embedded data start"));
  assert.ok(html.includes("Setup headers start"));
  assert.ok(html.includes("Packed engine size"));
  assert.ok(html.includes("Unpacked engine size"));
  assert.ok(html.includes("Decoded LZMA and reversed Inno x86 call filter"));
  assert.ok(html.includes(`data-pe-inno-engine-download`));
  assert.ok(html.includes(`data-inno-table-offset="16"`));
});
