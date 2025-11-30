"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWebm } from "../../analyzers/webm/index.js";
import { MockFile } from "../helpers/mock-file.js";

const ebmlId = [0x1a, 0x45, 0xdf, 0xa3];
const segmentId = [0x18, 0x53, 0x80, 0x67];
const ebmlSizeZero = [0x80];

void test("parseWebm returns null for non-EBML prefix", async () => {
  const file = new MockFile(new Uint8Array([0x00, 0x01, 0x02, 0x03]), "no.webm", "application/octet-stream");
  const parsed = await parseWebm(file);
  assert.strictEqual(parsed, null);
});

void test("parseWebm reports missing segment after EBML header", async () => {
  // EBML header with zero-length payload, no segment
  const header = new Uint8Array([...ebmlId, ...ebmlSizeZero]);
  const file = new MockFile(header, "header-only.webm", "video/webm");
  const parsed = await parseWebm(file);
  assert.ok(parsed);
  assert.strictEqual(parsed?.segment, null);
  assert.ok(parsed?.issues.some(msg => msg.toLowerCase().includes("segment element not found")));
});

void test("parseWebm warns when segment has unknown size and no metadata", async () => {
  // EBML header (empty) + segment with unknown size but no children
  const ebmlHeader = new Uint8Array([...ebmlId, ...ebmlSizeZero]);
  const unknownSize = [0xff]; // unknown length marker (1 byte)
  const segment = new Uint8Array([...segmentId, ...unknownSize]);
  const padding = new Uint8Array(2 * 1024 * 1024).fill(0); // force scan limit hit
  const file = new MockFile(
    new Uint8Array([...ebmlHeader, ...segment, ...padding]),
    "segment-unknown.webm",
    "video/webm"
  );
  const parsed = await parseWebm(file);
  assert.ok(parsed);
  assert.ok(parsed?.segment);
  assert.ok(parsed?.issues.length >= 1);
});
