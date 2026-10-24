import assert from "node:assert/strict";
import { test } from "node:test";
import { createArm64UnwindStatistics, recordArm64UnwindStatistics }
  from "../../../../../analyzers/pe/exception/arm64-unwind-statistics.js";
import { decodeArm64UnwindPool } from "../../../../../analyzers/pe/exception/arm64-unwind-code-pool.js";

void test("ARM64 inventories distinguish fixed allocations, save writeback, frame and scalable units", () => {
  const statistics = createArm64UnwindStatistics();
  const issues: string[] = [];
  const bytes = Uint8Array.from([2, 2, 0x83, 0xc8, 2, 0xe1, 0xe2, 4, 0xdf, 3,
    0xe7, 0, 0xc1, 0xe7, 0x14, 0xc2, 0xe4]);
  const decoded = decodeArm64UnwindPool(new DataView(bytes.buffer), new Set([0]), issues);
  recordArm64UnwindStatistics(statistics, decoded);
  recordArm64UnwindStatistics(statistics, { operations: [], hasDecodeGaps: true });

  assert.equal(statistics.blockCount, 2);
  assert.equal(statistics.incompleteBlockCount, 1);
  assert.deepEqual(statistics.allocationCounts, { 32: 2 });
  assert.deepEqual(statistics.preIndexAdjustmentCounts, { 32: 1 });
  assert.deepEqual(statistics.saveOffsetCounts, { 16: 1 });
  assert.deepEqual(statistics.frameOffsetCounts, { 0: 1, 32: 1 });
  assert.deepEqual(statistics.scalableAllocationCounts, { 3: 1 });
  assert.deepEqual(statistics.scalableSaveCounts, { "vectorLengths:1": 1, "predicateLengths:2": 1 });
  assert.deepEqual(statistics.registerCounts, { X29: 1, LR: 1, X19: 1, X20: 1, Z8: 1, P4: 1 });
  assert.equal(statistics.operationCounts["end"], 1);
  assert.equal(statistics.operationCounts["alloc_s"], 2);
  assert.deepEqual(issues, []);
});

void test("ARM64 empty inventory fields are freshly allocated for each parse", () => {
  const first = createArm64UnwindStatistics();
  const second = createArm64UnwindStatistics();
  first.operationCounts["nop"] = 1;
  assert.deepEqual(second.operationCounts, {});
  assert.equal(second.blockCount, 0);
});
