"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  renderEntrypointBlockLabel,
  renderEntrypointSourcesPreview
} from "../../../../renderers/pe/entrypoint-disassembly-block-labels.js";
import type { PeEntrypointRenderBlock } from "../../../../renderers/pe/entrypoint-disassembly-model.js";

const createBlock = (sources: readonly number[]): PeEntrypointRenderBlock => ({
  duplicateCount: sources.length,
  sources: [...sources],
  block: {
    kind: "followed-call",
    startRva: 0x2000,
    fileOffsetStart: 0x200,
    instructions: [{ rva: 0x2000, fileOffset: 0x200, text: "ret" }]
  }
});

void test("renderEntrypointSourcesPreview clips large source lists", () => {
  const html = renderEntrypointSourcesPreview(createBlock([0x1000, 0x1001, 0x1002, 0x1003]));

  assert.ok(html.includes(`data-pe-entrypoint-jump="4096"`));
  assert.ok(html.includes(`data-pe-entrypoint-jump="4098"`));
  assert.equal(html.includes(`data-pe-entrypoint-jump="4099"`), false);
  assert.ok(html.includes("+1 more"));
});

void test("renderEntrypointBlockLabel summarizes large source lists", () => {
  const label = renderEntrypointBlockLabel(createBlock([0x1000, 0x1001, 0x1002, 0x1003]));

  assert.equal(label, "Followed call target from 4 source(s); 3 duplicate context(s) merged");
});
