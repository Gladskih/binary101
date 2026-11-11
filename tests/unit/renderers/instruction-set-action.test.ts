import assert from "node:assert/strict";
import { test } from "node:test";
import { renderInstructionSetAction } from "../../../renderers/instruction-set-action.js";

void test("instruction analysis starts as a single available action", () => {
  const html = renderInstructionSetAction("analysis");

  assert.match(html, />Analyze instruction sets<\/button>/);
  assert.match(html, /^<button type="button" class="actionButton" id="analysis">/);
  assert.doesNotMatch(html, /disabled/);
});

void test("completed instruction analysis is visibly finished and cannot be repeated", () => {
  const html = renderInstructionSetAction("analysis", { bytesSampled: 12 });

  assert.match(html, /disabled/);
  assert.match(html, />Instruction sets analyzed<\/button>/);
  assert.doesNotMatch(html, /Re-analyze/);
});

void test("an empty code report explains why there is no further action", () => {
  assert.match(renderInstructionSetAction("analysis", { bytesSampled: 0 }), /disabled>No code to analyze/);
});
