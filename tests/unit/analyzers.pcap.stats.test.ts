"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createMutableTrafficStats,
  finalizePacketStats,
  finalizeTrafficStats,
  observePacket
} from "../../analyzers/capture/stats.js";

void test("traffic stats accumulate packet lengths and timestamps", () => {
  const stats = createMutableTrafficStats();

  observePacket(stats, 60, 80, 10.5);
  observePacket(stats, 40, 40, 9.5);
  observePacket(stats, 100, 100, null);

  const finalized = finalizeTrafficStats(stats);

  assert.strictEqual(finalized.totalPackets, 3);
  assert.strictEqual(finalized.totalCapturedBytes, 200);
  assert.strictEqual(finalized.totalOriginalBytes, 220);
  assert.strictEqual(finalized.capturedLengthMin, 40);
  assert.strictEqual(finalized.capturedLengthMax, 100);
  assert.strictEqual(finalized.capturedLengthAverage, 200 / 3);
  assert.strictEqual(finalized.originalLengthMin, 40);
  assert.strictEqual(finalized.originalLengthMax, 100);
  assert.strictEqual(finalized.originalLengthAverage, 220 / 3);
  assert.strictEqual(finalized.truncatedPackets, 1);
  assert.strictEqual(finalized.timestampMinSeconds, 9.5);
  assert.strictEqual(finalized.timestampMaxSeconds, 10.5);
  assert.strictEqual(finalized.outOfOrderTimestamps, 1);
});

void test("packet stats propagate truncated-file state", () => {
  const stats = createMutableTrafficStats();

  observePacket(stats, 0, 0, null);

  const finalized = finalizePacketStats(stats, true);

  assert.strictEqual(finalized.totalPackets, 1);
  assert.strictEqual(finalized.truncatedFile, true);
});
