import assert from "node:assert/strict";
import { test } from "node:test";
import { renderException } from "../../../../renderers/pe/exception.js";
import { createEmptyExceptionDirectory } from "../../../../analyzers/pe/exception/types.js";
import { createV12Statistics } from "../../../../analyzers/pe/exception/amd64/unwind-v12-statistics.js";
import { renderExceptionV12 } from "../../../../renderers/pe/exception-v12.js";

void test("exception view summarizes v1/v2 operations and distinguishes blocks from function frames", () => {
  const statistics = { ...createV12Statistics(), blockCount: 2, incompleteBlockCount: 1,
    operationCounts: { PUSH_NONVOL: 2, ALLOC_LARGE: 1, "<unknown>&amp;": 1 },
    registerCounts: { RBP: 2 }, allocationCounts: { 32: 1, 65536: 1 },
    saveOffsetCounts: { 0: 1, 32: 1 }, frameRegisterCounts: { RBP: 1 },
    frameOffsetCounts: { 16: 1 }, machineFrameCounts: { 40: 1, 48: 1 }, prologSizeCounts: { 24: 2 } };
  const out: string[] = [];
  renderException({ ...createEmptyExceptionDirectory([], "amd64"), unwindInfoV12: statistics }, out);
  const html = out.join("");

  assert.match(html, /AMD64 v1\/v2 unwind operations/);
  assert.match(html, /PUSH NONVOL/);
  assert.match(html, /Saved registers/);
  assert.match(html, /Frame registers/);
  assert.match(html, /Largest explicit stack allocation/);
  assert.match(html, /Blocks with incomplete operation decoding<\/dt><dd>1/);
  assert.match(html, /&lt;unknown&gt;&amp;amp;/);
  assert.match(html, /not reconstructed function-frame sizes/);
  assert.doesNotMatch(html, /0x[\da-f]{8}/i);
});

void test("v1/v2 view omits empty inventories and unavailable extrema", () => {
  assert.equal(renderExceptionV12(createV12Statistics()), "");
  const html = renderExceptionV12({ ...createV12Statistics(), blockCount: 1 });
  assert.doesNotMatch(html, /<table|Largest|Blocks with incomplete/);
  assert.match(html, /<dl class="peExceptionStats"><dt>UNWIND_INFO v1\/v2/);
  assert.match(html, /v1\/v2 blocks summarized<\/dt><dd>1/);
});
