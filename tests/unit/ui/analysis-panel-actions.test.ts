"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { createAnalysisPanelActions } from "../../../ui/analysis-panel-actions.js";

void test("createAnalysisPanelActions creates controllers for independent analysis panels", () => {
  const actions = createAnalysisPanelActions(
    () => null,
    () => ({ analyzer: null, parsed: null }),
    () => {}
  );

  assert.equal(typeof actions.peDisassembly.start, "function");
  assert.equal(typeof actions.peEntrypointDisassembly.start, "function");
  assert.equal(typeof actions.peOverlayScan.handleClick, "function");
  assert.equal(typeof actions.elfDisassembly.start, "function");
});
