import assert from "node:assert/strict";
import { test } from "node:test";
import { renderArm64PackedStatistics, renderArm64UnwindStatistics } from "../../../../renderers/pe/exception-arm64.js";
import { createArm64PackedStatistics } from "../../../../analyzers/pe/exception/arm64-packed-statistics.js";
import { createArm64UnwindStatistics } from "../../../../analyzers/pe/exception/arm64-unwind-statistics.js";
import { renderException } from "../../../../renderers/pe/exception.js";
import { createEmptyExceptionDirectory } from "../../../../analyzers/pe/exception/types.js";

void test("ARM64 renderer distinguishes packed frame sizes from xdata operands and scalable sizes", () => {
  const packed = { ...createArm64PackedStatistics(), frameSizeCounts: { 0: 1, 128: 1 },
    returnKinds: { 0: 1, 1: 1, 2: 1, 3: 1 }, registerCounts: { X19: 1, "<name>&amp;": 1 },
    fragmentCount: 1, homesParametersCount: 1 };
  const unwind = { ...createArm64UnwindStatistics(), blockCount: 1, incompleteBlockCount: 1,
    operationCounts: { save_regp: 1 }, registerCounts: { X19: 1 }, allocationCounts: { 32: 1 },
    preIndexAdjustmentCounts: { 16: 1 }, saveOffsetCounts: { 0: 1 }, frameOffsetCounts: { 0: 1 },
    scalableAllocationCounts: { 3: 1 }, scalableSaveCounts: { "vectorLengths:4": 1, "predicateLengths:2": 1 } };
  const out: string[] = [];
  renderException({ ...createEmptyExceptionDirectory([], "arm64"), arm64Packed: packed, arm64Unwind: unwind }, out);
  const html = out.join("");

  assert.match(html, /Largest encoded packed frame/);
  assert.match(html, /Packed fragments<\/dt><dd>1/);
  assert.match(html, /Packed entries with parameter homes<\/dt><dd>1/);
  assert.match(html, /Frame chain with signed LR/);
  assert.match(html, /Unchained, LR saved/);
  assert.match(html, /Unchained, LR not saved/);
  assert.match(html, /&lt;name&gt;&amp;amp;/);
  assert.match(html, /not reconstructed frame sizes/);
  assert.match(html, /ARM64 blocks with decode gaps<\/dt><dd>1/);
  assert.match(html, /4 × VL/);
  assert.match(html, /2 × \(VL \/ 8\)/);
  assert.doesNotMatch(html, /0x[\da-f]{8}/i);
});

void test("ARM64 renderer omits unavailable inventories but retains a real zero frame size", () => {
  assert.equal(renderArm64PackedStatistics(createArm64PackedStatistics()), "");
  assert.equal(renderArm64UnwindStatistics(createArm64UnwindStatistics()), "");
  const html = renderArm64PackedStatistics({ ...createArm64PackedStatistics(), frameSizeCounts: { 0: 1 } });
  assert.match(html, /Largest encoded packed frame/);
  assert.match(html, /0 bytes/);
  const empty = renderArm64UnwindStatistics({ ...createArm64UnwindStatistics(), blockCount: 1 });
  assert.doesNotMatch(empty, /decode gaps|<table/);
});
