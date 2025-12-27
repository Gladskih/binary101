"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseTgaExtensionArea } from "../../analyzers/tga/extension-area.js";
import { MockFile } from "../helpers/mock-file.js";

void test("parseTgaExtensionArea returns null for invalid offsets", async () => {
  const file = new MockFile(new Uint8Array(10), "x.tga", "application/octet-stream");
  const issues: string[] = [];
  const parsed = await parseTgaExtensionArea(file, 0, 3, 1, message => issues.push(message));
  assert.strictEqual(parsed, null);
});

void test("parseTgaExtensionArea parses optional structures and reports anomalies", async () => {
  const bytes = new Uint8Array(700);
  const dv = new DataView(bytes.buffer);
  const extOffset = 100;

  dv.setUint16(extOffset + 0, 123, true);
  bytes.set(Buffer.from("Author\u0000", "ascii"), extOffset + 2);
  bytes.set(Buffer.from("Comment\u0000", "ascii"), extOffset + 43);
  dv.setUint16(extOffset + 367, 13, true);
  dv.setUint16(extOffset + 369, 32, true);
  dv.setUint16(extOffset + 371, 2025, true);
  dv.setUint16(extOffset + 373, 24, true);
  dv.setUint16(extOffset + 375, 60, true);
  dv.setUint16(extOffset + 377, 60, true);

  bytes.set(Buffer.from("Job\u0000", "ascii"), extOffset + 379);
  dv.setUint16(extOffset + 420, 1, true);
  dv.setUint16(extOffset + 422, 2, true);
  dv.setUint16(extOffset + 424, 3, true);

  bytes.set(Buffer.from("Soft\u0000", "ascii"), extOffset + 426);
  dv.setUint16(extOffset + 467, 101, true);
  bytes[extOffset + 469] = 0;

  dv.setUint32(extOffset + 470, 0x11223344, true);
  dv.setUint16(extOffset + 474, 0, true);
  dv.setUint16(extOffset + 476, 1, true);
  dv.setUint16(extOffset + 478, 22, true);
  dv.setUint16(extOffset + 480, 10, true);

  dv.setUint32(extOffset + 482, 650, true);
  dv.setUint32(extOffset + 486, 690, true);
  dv.setUint32(extOffset + 490, 600, true);
  bytes[extOffset + 494] = 1;

  bytes[690] = 2;
  bytes[691] = 2;

  const file = new MockFile(bytes, "x.tga", "application/octet-stream");
  const issues: string[] = [];
  const ext = await parseTgaExtensionArea(file, extOffset, 3, 2, message => issues.push(message));
  assert.ok(ext);
  assert.strictEqual(ext.size, 123);
  assert.strictEqual(ext.authorName, "Author");
  assert.strictEqual(ext.authorComment, "Comment");
  assert.ok(ext.timestamp);
  assert.strictEqual(ext.pixelAspectRatio, null);
  assert.ok(ext.gamma);
  assert.ok(ext.colorCorrectionTable);
  assert.strictEqual(ext.colorCorrectionTable.truncated, true);
  assert.ok(ext.postageStamp);
  assert.strictEqual(ext.postageStamp.width, 2);
  assert.strictEqual(ext.postageStamp.height, 2);
  assert.strictEqual(ext.postageStamp.truncated, true);
  assert.ok(ext.scanLineTable);
  assert.strictEqual(ext.scanLineTable.expectedBytes, 8);
  assert.strictEqual(ext.scanLineTable.truncated, false);
  assert.ok(issues.some(message => message.toLowerCase().includes("extension area size")));
  assert.ok(issues.some(message => message.toLowerCase().includes("timestamp")));
});

