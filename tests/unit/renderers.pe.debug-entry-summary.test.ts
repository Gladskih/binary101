"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  getDebugStorageInfo,
  getEntrySummary
} from "../../renderers/pe/debug-entry-summary.js";
import { createDebugViewEntry } from "../fixtures/pe-debug-view-subject.js";
import {
  createBasePe,
  createPeSection,
  createPeWithSections
} from "../fixtures/pe-renderer-headers-fixture.js";

void test("getDebugStorageInfo reports unresolved payloads", () => {
  const pe = createBasePe();

  const result = getDebugStorageInfo(pe, createDebugViewEntry(0xff, 0, 0, 0));

  assert.equal(result.label, "UNRESOLVED");
  assert.match(result.description, /does not resolve/i);
});

void test("getDebugStorageInfo reports mapped section-backed payloads", () => {
  const section = createPeSection("S0");
  const pe = createPeWithSections(section);

  const result = getDebugStorageInfo(pe, createDebugViewEntry(2, section.virtualAddress, section.pointerToRawData, 4));

  assert.equal(result.label, "MAPPED");
  assert.match(result.description, /section-backed/i);
});

void test("getDebugStorageInfo reports unmapped file-only payloads", () => {
  const pe = createBasePe();

  const result = getDebugStorageInfo(pe, createDebugViewEntry(16, 0, 0x200, 4));

  assert.equal(result.label, "UNMAPPED");
  assert.match(result.description, /file pointer/i);
});

void test("getDebugStorageInfo reports inconsistent RVA and section coverage", () => {
  const section = createPeSection("S0");
  const pe = createPeWithSections(section);

  const result = getDebugStorageInfo(pe, createDebugViewEntry(17, 0, section.pointerToRawData, 4));

  assert.equal(result.label, "INCONSISTENT");
  assert.match(result.description, /disagree/i);
});

void test("getEntrySummary describes decoded payload families", () => {
  const summaries = [
    getEntrySummary({
      ...createDebugViewEntry(2, 0, 1),
      codeView: { signature: "NB10", offset: 0, timestamp: 1, age: 1, path: "legacy.pdb" }
    }),
    getEntrySummary({
      ...createDebugViewEntry(19, 0, 1),
      pdbChecksum: { algorithmName: "SHA256", checksumBytes: [0xaa] }
    }),
    getEntrySummary({
      ...createDebugViewEntry(10, 0, 1),
      rawPayload: { previewBytes: [0xbb] }
    })
  ];

  assert.deepEqual(summaries, [
    "CodeView NB10 record with PDB identity and path.",
    "SHA256 checksum.",
    "Raw debug payload preview for a reserved or unrecognized format."
  ]);
});

void test("getEntrySummary falls back to debug type descriptions", () => {
  const result = getEntrySummary(createDebugViewEntry(5, 0, 1));

  assert.equal(result, "Copy of the .pdata exception data.");
});
