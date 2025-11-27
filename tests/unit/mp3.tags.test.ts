"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseApeTag, parseLyrics3 } from "../../analyzers/mp3/tags.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);

void test("parseApeTag locates footer data and reports fields", () => {
  const bytes = new Uint8Array(80).fill(0);
  const footerOffset = bytes.length - 32;
  bytes.set(Buffer.from("APETAGEX", "ascii"), footerOffset);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(footerOffset + 8, 2000, true);
  dv.setUint32(footerOffset + 12, 32, true);
  dv.setUint32(footerOffset + 16, 2, true);

  const issues: string[] = [];
  const ape = parseApeTag(dv, issues);
  assert.ok(ape);
  assert.strictEqual(ape.offset, footerOffset);
  assert.strictEqual(ape.size, 32);
  assert.strictEqual(ape.itemCount, 2);
  assert.deepStrictEqual(issues, []);
});

void test("parseApeTag warns when declared size exceeds buffer", () => {
  const bytes = new Uint8Array(64).fill(0);
  const footerOffset = bytes.length - 32;
  bytes.set(Buffer.from("APETAGEX", "ascii"), footerOffset);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(footerOffset + 8, 2000, true);
  dv.setUint32(footerOffset + 12, 400, true);
  dv.setUint32(footerOffset + 16, 1, true);

  const issues: string[] = [];
  const ape = parseApeTag(dv, issues);
  assert.ok(ape);
  assert.ok(issues.some(msg => msg.includes("truncated")));
});

void test("parseLyrics3 extracts v2 info and flags truncated legacy tags", () => {
  const bytes = new Uint8Array(256).fill(0x41); // 'A'
  const endOffset = 200;
  bytes.set(Buffer.from("000012", "ascii"), endOffset - 6);
  bytes.set(Buffer.from("LYRICS200", "ascii"), endOffset);

  const issues: string[] = [];
  const info = parseLyrics3(dvFrom(bytes), issues);
  assert.ok(info);
  assert.strictEqual(info.version, "2.00");
  assert.strictEqual(info.sizeEstimate, 12);
  assert.strictEqual(info.offset, endOffset - 6 - 12);
  assert.deepStrictEqual(issues, []);

  const truncated = new Uint8Array(64).fill(0);
  truncated.set(Buffer.from("LYRICSEND", "ascii"), 20);
  const truncatedIssues: string[] = [];
  const legacy = parseLyrics3(dvFrom(truncated), truncatedIssues);
  assert.strictEqual(legacy, null);
  assert.ok(truncatedIssues.some(msg => msg.toLowerCase().includes("truncated lyrics3")));
});
