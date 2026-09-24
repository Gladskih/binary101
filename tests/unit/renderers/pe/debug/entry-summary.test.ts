"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  getDebugStorageInfo,
  getEntrySummary
} from "../../../../../renderers/pe/debug-entry-summary.js";
import { createDebugViewEntry } from "../../../../fixtures/pe-debug-view-subject.js";
import {
  createBasePe,
  createPeSection,
  createPeWithSections
} from "../../../../fixtures/pe-renderer-headers-fixture.js";

void test("getDebugStorageInfo distinguishes empty entries from unresolved payloads", () => {
  const pe = createBasePe();

  const empty = getDebugStorageInfo(pe, createDebugViewEntry(14, 0, 0, 0));
  const unresolved = getDebugStorageInfo(pe, createDebugViewEntry(0xff, 0, 0, 4));

  assert.equal(empty.label, "NO PAYLOAD");
  assert.match(empty.description, /zero/i);
  assert.equal(unresolved.label, "UNRESOLVED");
  assert.match(unresolved.description, /does not resolve/i);
});

void test("getEntrySummary explains empty and nonempty ILTCG entries", () => {
  const empty = getEntrySummary(createDebugViewEntry(14, 0, 0, 0));
  const nonempty = getEntrySummary(createDebugViewEntry(14, 0, 0x80, 4));

  assert.match(empty, /Incremental Link-Time Code Generation/);
  assert.match(empty, /\/LTCG:INCREMENTAL/);
  assert.match(empty, /reoptimizes files affected by edits during linking/);
  assert.match(empty, /no payload/i);
  assert.match(nonempty, /Incremental Link-Time Code Generation/);
  assert.match(nonempty, /Payload format is not documented here/);
  assert.doesNotMatch(nonempty, /no payload/i);
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
    }),
    getEntrySummary({
      ...createDebugViewEntry(13, 0, 1),
      pogo: { signature: 0x4c544347, signatureName: "LTCG", entries: [] }
    })
  ];

  assert.deepEqual(summaries, [
    "CodeView NB10 record with PDB identity and path.",
    "SHA256 checksum.",
    "Raw debug payload preview for a reserved or unrecognized format.",
    "Linker layout map with 0 records."
  ]);
});

void test("getEntrySummary falls back to debug type descriptions", () => {
  const result = getEntrySummary(createDebugViewEntry(5, 0, 1));

  assert.equal(result, "Copy of the .pdata exception data.");
});
