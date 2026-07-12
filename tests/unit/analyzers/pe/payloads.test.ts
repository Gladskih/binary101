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
import { createInnoFinding } from "../../../fixtures/inno-setup-fixture.js";

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

void test("analyzePePayloads finds a bounded PE executable in a resource leaf", async () => {
  const bytes = new Uint8Array(256);
  const resourceStart = 32;
  const peHeaderOffset = 0x40;
  const view = new DataView(bytes.buffer);
  view.setUint16(resourceStart, 0x5a4d, true);
  view.setUint32(resourceStart + 0x3c, peHeaderOffset, true);
  view.setUint32(resourceStart + peHeaderOffset, 0x50450000, false);
  const file = new MockFile(bytes, "resource-installer.exe");

  const result = await analyzePePayloads(file, file, null, null, {
    top: [],
    detail: [],
    paths: [{
      nodes: [{ id: 10, name: null }, { id: 101, name: null }, { id: 1033, name: null }],
      size: 128,
      codePage: 0,
      dataRVA: 0x2000,
      dataFileOffset: resourceStart,
      reserved: 0
    }]
  });

  assert.deepEqual(result, {
    entries: [{ start: resourceStart, end: resourceStart + 128, format: "pe", source: "resource" }]
  });
});

void test("analyzePePayloads rejects malformed and out-of-bounds resource executables", async () => {
  const file = new MockFile(new Uint8Array(128), "resource-installer.exe");
  const createPath = (dataFileOffset: number | null, size: number) => ({
    nodes: [{ id: 10, name: null }, { id: 101, name: null }, { id: 1033, name: null }],
    size,
    codePage: 0,
    dataRVA: 0x2000,
    dataFileOffset,
    reserved: 0
  });

  const result = await analyzePePayloads(file, file, null, null, {
    top: [],
    detail: [],
    paths: [createPath(null, 64), createPath(96, 64), createPath(0, 32), createPath(0, 64)]
  });

  assert.equal(result, null);
});

void test("subtractExplainedPeOverlay leaves only bytes beyond verified NSIS data", async () => {
  const overlay: PeOverlayAnalysis = {
    ranges: [{ start: 100, end: 200, size: 100, findings: [] }]
  };

  const result = await subtractExplainedPeOverlay(
    new MockFile(new Uint8Array(200), "installer.exe"),
    null,
    overlay,
    createNsisAnalysis(100, 198),
    null
  );

  assert.deepEqual(result, {
    ranges: [{ start: 198, end: 200, size: 2, findings: [] }]
  });
});

void test("subtractExplainedPeOverlay removes data explained by Inno Setup", async () => {
  const result = await subtractExplainedPeOverlay(
    new MockFile(new Uint8Array(242), "installer.exe"),
    null,
    { ranges: [{ start: 80, end: 242, size: 162, findings: [] }] },
    { reports: [{ id: "inno-setup", findings: [createInnoFinding()], warnings: [] }] },
    null
  );

  assert.deepEqual(result, {
    ranges: [{ start: 240, end: 242, size: 2, findings: [] }]
  });
});

void test("subtractExplainedPeOverlay removes a fully validated archive", async () => {
  const overlay: PeOverlayAnalysis = {
    ranges: [{ start: 100, end: 200, size: 100, findings: [] }]
  };

  const result = await subtractExplainedPeOverlay(
    new MockFile(new Uint8Array(200), "installer.exe"),
    null,
    overlay,
    null,
    { entries: [{ start: 100, end: 200, format: "rar", source: "overlay" }] }
  );

  assert.equal(result, null);
});

void test("subtractExplainedPeOverlay preserves residual sides and warnings", async () => {
  const overlay: PeOverlayAnalysis = {
    ranges: [{ start: 100, end: 200, size: 100, findings: [] }],
    warnings: ["Synthetic warning"]
  };

  const result = await subtractExplainedPeOverlay(
    new MockFile(new Uint8Array(200), "installer.exe"),
    null,
    overlay,
    null,
    { entries: [{ start: 120, end: 180, format: "sevenzip", source: "overlay" }] }
  );

  assert.deepEqual(result, {
    ranges: [
      { start: 100, end: 120, size: 20, findings: [] },
      { start: 180, end: 200, size: 20, findings: [] }
    ],
    warnings: ["Synthetic warning"]
  });
});

void test("subtractExplainedPeOverlay keeps warnings without residual ranges", async () => {
  const result = await subtractExplainedPeOverlay(
    new MockFile(new Uint8Array(), "installer.exe"),
    null,
    { ranges: [], warnings: ["warning"] },
    null,
    null
  );

  assert.deepEqual(result, { ranges: [], warnings: ["warning"] });
});

void test("subtractExplainedPeOverlay accepts a missing physical overlay", async () => {
  const result = await subtractExplainedPeOverlay(
    new MockFile(new Uint8Array(), "installer.exe"),
    null,
    null,
    null,
    null
  );

  assert.equal(result, null);
});

void test("subtractExplainedPeOverlay excludes certificate padding after a validated archive", async () => {
  const bytes = new Uint8Array(120);
  const result = await subtractExplainedPeOverlay(
    new MockFile(bytes, "signed-installer.exe"),
    120,
    { ranges: [{ start: 100, end: 120, size: 20, findings: [] }] },
    null,
    { entries: [{ start: 100, end: 118, format: "rar", source: "overlay" }] }
  );

  assert.equal(result, null);
});

void test("subtractExplainedPeOverlay keeps non-zero bytes before a certificate table", async () => {
  const bytes = new Uint8Array(120);
  bytes[119] = 1;
  const result = await subtractExplainedPeOverlay(
    new MockFile(bytes, "signed-installer.exe"),
    120,
    { ranges: [{ start: 100, end: 120, size: 20, findings: [] }] },
    null,
    { entries: [{ start: 100, end: 118, format: "rar", source: "overlay" }] }
  );

  assert.deepEqual(result, {
    ranges: [{ start: 118, end: 120, size: 2, findings: [] }]
  });
});
