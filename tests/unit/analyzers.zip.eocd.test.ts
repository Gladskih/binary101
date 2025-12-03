"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { MockFile } from "../helpers/mock-file.js";
import { findZip64Locator, parseEocd, parseZip64Eocd, readTailForEocd } from "../../analyzers/zip/eocd.js";

const makeTail = async (bytes: Uint8Array) => {
  const file = new MockFile(bytes);
  return readTailForEocd(file);
};

void test("parseEocd locates EOCD and reads fields", async () => {
  const bytes = new Uint8Array(64).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(40, 0x06054b50, true);
  dv.setUint16(44, 1, true);
  dv.setUint16(46, 1, true);
  dv.setUint16(48, 2, true);
  dv.setUint16(50, 2, true);
  dv.setUint32(52, 10, true);
  dv.setUint32(56, 20, true);
  const { dv: tail, baseOffset } = await makeTail(bytes);
  const eocd = parseEocd(tail, baseOffset);
  assert.ok(eocd);
  assert.strictEqual(eocd?.totalEntries, 2);
  assert.strictEqual(eocd?.centralDirOffset, 20);
});

void test("findZip64Locator returns last locator when present", async () => {
  const bytes = new Uint8Array(32).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 0x07064b50, true);
  dv.setUint32(4, 5, true);
  dv.setBigUint64(8, 0x40n, true);
  dv.setUint32(16, 1, true);
  const locator = findZip64Locator(new DataView(bytes.buffer), 0);
  assert.ok(locator);
  assert.strictEqual(locator?.zip64EocdOffset, 0x40n);
});

void test("parseZip64Eocd validates signature and size", async () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0x20, 0x06064b50, true);
  dv.setBigUint64(0x24, 44n, true);
  dv.setUint16(0x2c, 45, true);
  dv.setUint16(0x2e, 46, true);
  const file = new MockFile(bytes);
  const issues: string[] = [];
  const locator = { offset: 0, diskWithEocd: 0, zip64EocdOffset: 0x20n, totalDisks: 1 };
  const parsed = await parseZip64Eocd(file, locator, issues);
  assert.ok(parsed);
  assert.strictEqual(parsed?.versionMadeBy, 45);
  assert.deepEqual(issues, []);
});
