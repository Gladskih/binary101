"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { renderIssues } from "../../renderers/capture/issues.js";

void test("renderIssues renders escaped issue items and skips empty input", () => {
  assert.equal(renderIssues([]), "");
  assert.equal(renderIssues(null), "");

  const html = renderIssues(["bad <tag>", "truncated block"]);
  assert.match(html, /Issues/);
  assert.match(html, /bad &lt;tag>/);
  assert.match(html, /truncated block/);
});
