"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  readVint,
  readElementHeader,
  clampReadLength,
  readUtf8,
  readDate
} from "../../analyzers/webm/ebml.js";
import type { Issues } from "../../analyzers/webm/types.js";

const dvFrom = (bytes: number[]): DataView => new DataView(Uint8Array.from(bytes).buffer);

void test("readVint decodes standard and unknown sizes", () => {
  const vint = readVint(dvFrom([0x83]), 0);
  assert.ok(vint);
  assert.strictEqual(vint?.length, 1);
  assert.strictEqual(vint?.data, 0x03n);

  const unknown = readVint(dvFrom([0xff]), 0);
  assert.ok(unknown);
  assert.strictEqual(unknown?.unknown, true);
});

void test("readElementHeader parses id/size and reports truncation", () => {
  const issues: Issues = [];
  const dv = dvFrom([
    0x1a, 0x45, 0xdf, 0xa3, // EBML
    0x84, // size marker (4 bytes)
    0x00, 0x00, 0x00, 0x10 // declared size
  ]);
  const header = readElementHeader(dv, 0, 0, issues);
  assert.ok(header);
  assert.strictEqual(header?.id, 0x1a45dfa3);
  assert.strictEqual(header?.size, 0x04);
  const truncated = readElementHeader(dvFrom([0x1a]), 0, 0, []);
  assert.strictEqual(truncated, null);
  assert.ok(issues.length === 0);
});

void test("clampReadLength respects caps and declared sizes", () => {
  const { length, truncated } = clampReadLength(1000, 0, 2000, 512);
  assert.strictEqual(length, 512);
  assert.strictEqual(truncated, true);
});

void test("readUtf8 and readDate return decoded values", () => {
  const utf8 = readUtf8(dvFrom([0x68, 0x69]), 0, 2);
  assert.strictEqual(utf8, "hi");
  const now = Date.UTC(2001, 0, 1, 0, 0, 1);
  const nanos = BigInt(now - Date.UTC(2001, 0, 1, 0, 0, 0)) * 1000000n;
  const buffer = new ArrayBuffer(8);
  new DataView(buffer).setBigInt64(0, nanos, false);
  const iso = readDate(new DataView(buffer), 0, 8, []);
  assert.ok(iso?.startsWith("2001-01-01T00:00:01"));
});
