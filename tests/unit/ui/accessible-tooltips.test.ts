"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { accessibleTooltipSelector } from "../../../ui/accessible-tooltips.js";

void test("accessible tooltips require an explicit semantic marker", () => {
  assert.equal(accessibleTooltipSelector, "[data-accessible-tooltip][title]");
});
