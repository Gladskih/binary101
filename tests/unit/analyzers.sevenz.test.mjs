"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { hasSevenZipSignature, parseSevenZip } from "../../analyzers/sevenz/index.js";
import { MockFile } from "../helpers/mock-file.mjs";

test("hasSevenZipSignature detects 7z magic bytes", () => {
  const sig = new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 0]);
  assert.equal(hasSevenZipSignature(new DataView(sig.buffer)), true);
  assert.equal(hasSevenZipSignature(new DataView(new Uint8Array([0x00, 0x01]).buffer)), false);
});

test("parseSevenZip reports out-of-bounds next header", async () => {
  const header = new Uint8Array(48).fill(0);
  header.set([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], 0);
  header[6] = 0; // version major
  header[7] = 4; // version minor
  // startHeaderCrc (ignored here)
  header[8] = 0x12;
  header[9] = 0x34;
  header[10] = 0x56;
  header[11] = 0x78;
  // nextHeaderOffset = 8
  header[12] = 8;
  // nextHeaderSize = 16
  header[20] = 16;
  // nextHeaderCrc
  header[28] = 0xaa;
  header[29] = 0xbb;
  header[30] = 0xcc;
  header[31] = 0xdd;

  const file = new MockFile(header, "bad-next-header.7z");
  const parsed = await parseSevenZip(file);
  assert.equal(parsed.is7z, true);
  assert.ok(parsed.issues.some(msg => msg.includes("outside the file bounds")));
});

test("parseSevenZip returns non-7z for missing signature", async () => {
  const file = new MockFile(new Uint8Array(16).fill(0), "not7z.bin");
  const parsed = await parseSevenZip(file);
  assert.equal(parsed.is7z, false);
});
