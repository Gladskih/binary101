"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import type { PcapPacketStats } from "../../analyzers/capture/types.js";
import { renderPacketSummary } from "../../renderers/capture/packet-summary.js";

void test("renderPacketSummary renders packet counters and time range", () => {
  const packets: PcapPacketStats = {
    totalPackets: 3,
    totalCapturedBytes: 120,
    totalOriginalBytes: 144,
    capturedLengthMin: 32,
    capturedLengthMax: 48,
    capturedLengthAverage: 40,
    originalLengthMin: 40,
    originalLengthMax: 56,
    originalLengthAverage: 48,
    truncatedPackets: 1,
    timestampMinSeconds: 1,
    timestampMaxSeconds: 3.5,
    outOfOrderTimestamps: 0,
    truncatedFile: false
  };

  const out: string[] = [];
  renderPacketSummary(packets, out);
  const html = out.join("");

  assert.match(html, /Packets/);
  assert.match(html, /Total packets/);
  assert.match(html, />3</);
  assert.match(html, /Capture-truncated packets/);
  assert.match(html, /Time start/);
  assert.match(html, /Time span/);
});
