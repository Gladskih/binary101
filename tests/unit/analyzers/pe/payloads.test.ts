"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeOverlayAnalysis } from "../../../../analyzers/pe/overlay.js";
import type { PePackerAnalysis } from "../../../../analyzers/pe/packers/types.js";
import {
  analyzePePayloads,
  subtractExplainedPeOverlay
} from "../../../../analyzers/pe/payloads.js";
import {
  createRar4File,
  createSevenZipFile
} from "../../../fixtures/rar-sevenzip-fixtures.js";
import { MockFile } from "../../../helpers/mock-file.js";

const IMAGE_BYTES = 16;
const PAYLOAD_PREFIX_BYTES = 128;

const createOverlayFixture = (payload: Uint8Array) => {
  const start = IMAGE_BYTES;
  const payloadStart = start + PAYLOAD_PREFIX_BYTES;
  const end = payloadStart + payload.byteLength;
  const bytes = new Uint8Array(end);
  bytes.set(payload, payloadStart);
  const file = new MockFile(bytes, "installer.exe");
  const overlay: PeOverlayAnalysis = {
    ranges: [{ start, end, size: end - start, findings: [] }]
  };
  return { end, file, overlay, payloadStart, start };
};

const createNsisAnalysis = (start: number, end: number): PePackerAnalysis => ({
  reports: [{
    id: "nsis-installer",
    findings: [{
      id: "nsis-installer",
      name: "NSIS installer",
      kind: "installer",
      confidence: "high",
      evidence: ["NSIS verified"],
      headerSize: 64,
      firstHeaderOffset: start,
      flags: 0,
      followingDataSize: end - start
    }],
    warnings: []
  }]
});

void test("analyzePePayloads finds bounded 7z data inside NSIS", async () => {
  const sevenZip = createSevenZipFile().data;
  const fixture = createOverlayFixture(sevenZip);

  const result = await analyzePePayloads(
    fixture.file,
    fixture.file,
    fixture.overlay,
    createNsisAnalysis(fixture.start, fixture.end)
  );

  assert.deepEqual(result, {
    entries: [{
      end: fixture.payloadStart + sevenZip.byteLength,
      format: "sevenzip",
      source: "nsis",
      start: fixture.payloadStart
    }]
  });
});

void test("analyzePePayloads finds validated RAR overlay data", async () => {
  const rar = createRar4File().data;
  const fixture = createOverlayFixture(rar);

  const result = await analyzePePayloads(
    fixture.file,
    fixture.file,
    fixture.overlay,
    null
  );

  assert.deepEqual(result, {
    entries: [{
      end: fixture.end,
      format: "rar",
      source: "overlay",
      start: fixture.payloadStart
    }]
  });
});

void test("analyzePePayloads returns null without validated archive payloads", async () => {
  const file = new MockFile(new Uint8Array(32), "plain.exe");

  const result = await analyzePePayloads(file, file, null, null);

  assert.equal(result, null);
});

void test("subtractExplainedPeOverlay leaves only bytes beyond verified NSIS data", () => {
  const overlay: PeOverlayAnalysis = {
    ranges: [{ start: 100, end: 200, size: 100, findings: [] }]
  };

  const result = subtractExplainedPeOverlay(overlay, createNsisAnalysis(100, 198), null);

  assert.deepEqual(result, {
    ranges: [{ start: 198, end: 200, size: 2, findings: [] }]
  });
});

void test("subtractExplainedPeOverlay removes a fully validated archive", () => {
  const overlay: PeOverlayAnalysis = {
    ranges: [{ start: 100, end: 200, size: 100, findings: [] }]
  };

  const result = subtractExplainedPeOverlay(overlay, null, {
    entries: [{ start: 100, end: 200, format: "rar", source: "overlay" }]
  });

  assert.equal(result, null);
});

void test("subtractExplainedPeOverlay preserves residual sides and warnings", () => {
  const overlay: PeOverlayAnalysis = {
    ranges: [{ start: 100, end: 200, size: 100, findings: [] }],
    warnings: ["Synthetic warning"]
  };

  const result = subtractExplainedPeOverlay(overlay, null, {
    entries: [{ start: 120, end: 180, format: "sevenzip", source: "overlay" }]
  });

  assert.deepEqual(result, {
    ranges: [
      { start: 100, end: 120, size: 20, findings: [] },
      { start: 180, end: 200, size: 20, findings: [] }
    ],
    warnings: ["Synthetic warning"]
  });
});

void test("subtractExplainedPeOverlay keeps warnings without residual ranges", () => {
  const result = subtractExplainedPeOverlay({ ranges: [], warnings: ["warning"] }, null, null);

  assert.deepEqual(result, { ranges: [], warnings: ["warning"] });
});

void test("subtractExplainedPeOverlay accepts a missing physical overlay", () => {
  assert.equal(subtractExplainedPeOverlay(null, null, null), null);
});
