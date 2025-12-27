"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseTgaDeveloperDirectory } from "../../analyzers/tga/developer-directory.js";
import { MockFile } from "../helpers/mock-file.js";

void test("parseTgaDeveloperDirectory returns null when offset is outside file", async () => {
  const file = new MockFile(new Uint8Array(10), "x.tga", "application/octet-stream");
  const result = await parseTgaDeveloperDirectory(file, 10, () => {});
  assert.strictEqual(result, null);
});

void test("parseTgaDeveloperDirectory reports truncated header reads", async () => {
  const file = new MockFile(new Uint8Array(10), "x.tga", "application/octet-stream");
  const result = await parseTgaDeveloperDirectory(file, 9, () => {});
  assert.ok(result);
  assert.strictEqual(result.tagCount, null);
  assert.strictEqual(result.truncated, true);
});

void test("parseTgaDeveloperDirectory caps parsed tags and flags truncated tag data", async () => {
  const bytes = new Uint8Array(6000);
  const dv = new DataView(bytes.buffer);
  const offset = 4;

  dv.setUint16(offset + 0, 513, true);
  dv.setUint16(offset + 2, 1, true);
  dv.setUint32(offset + 4, 5990, true);
  dv.setUint32(offset + 8, 50, true);

  const file = new MockFile(bytes, "x.tga", "application/octet-stream");
  const issues: string[] = [];
  const dir = await parseTgaDeveloperDirectory(file, offset, message => issues.push(message));
  assert.ok(dir);
  assert.strictEqual(dir.tagCount, 513);
  assert.strictEqual(dir.tags.length, 512);
  assert.strictEqual(dir.tags[0]?.tagNumber, 1);
  assert.strictEqual(dir.tags[0]?.truncated, true);
  assert.ok(issues.some(message => message.toLowerCase().includes("showing first")));
});

void test("parseTgaDeveloperDirectory reports truncated directories", async () => {
  const bytes = new Uint8Array(10);
  const dv = new DataView(bytes.buffer);
  const offset = 4;
  dv.setUint16(offset + 0, 2, true);
  const file = new MockFile(bytes, "x.tga", "application/octet-stream");
  const issues: string[] = [];
  const dir = await parseTgaDeveloperDirectory(file, offset, message => issues.push(message));
  assert.ok(dir);
  assert.strictEqual(dir.truncated, true);
  assert.ok(issues.some(message => message.toLowerCase().includes("truncated")));
});
