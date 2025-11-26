"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ARCHIVE_FLAG_DEFS,
  FILE_FLAG_DEFS,
  renderFlagsOrNone
} from "../../dist/renderers/sevenz/flags-view.js";

test("renderFlagsOrNone renders a None chip for zero mask", () => {
  const html = renderFlagsOrNone(0, ARCHIVE_FLAG_DEFS);
  assert.match(html, /No flags set/);
  assert.match(html, /None/);
});

test("renderFlagsOrNone renders set and unset archive flags", () => {
  const html = renderFlagsOrNone(1 | 4, ARCHIVE_FLAG_DEFS);
  // All known flags should appear at least once.
  assert.match(html, /Solid/);
  assert.match(html, /Header enc/);
  assert.match(html, /Encrypted data/);
  // For non-zero mask, there should be no standalone "None" chip.
  assert.doesNotMatch(html, />None</);
});

test("renderFlagsOrNone handles unknown bits without crashing", () => {
  // 0x80 is not present in FILE_FLAG_DEFS.
  const html = renderFlagsOrNone(0x80, FILE_FLAG_DEFS);
  // Still renders all defined flags in a consistent structure.
  assert.match(html, /dir/);
  assert.match(html, /enc/);
  assert.match(html, /empty/);
  assert.match(html, /no-stream/);
});

