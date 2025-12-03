"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildOffsetMap, parseXref } from "../../analyzers/pdf/xref.js";

const tableText = [
  "xref",
  "0 2",
  "0000000000 65535 f ",
  "0000000017 00000 n ",
  "trailer",
  "<< /Size 2 >>",
  "startxref",
  "0"
].join("\n");

void test("parseXref reads table sections and trailer", () => {
  const issues: string[] = [];
  const xref = parseXref(tableText, 0, issues);
  assert.strictEqual(xref?.kind, "table");
  if (!xref || xref.kind !== "table" || !xref.trailer) assert.fail("xref table not parsed");
  assert.strictEqual(xref.entries.length, 2);
  assert.strictEqual(xref.trailer.size, 2);
  const offsets = buildOffsetMap(xref);
  assert.strictEqual(offsets?.get(1), 17);
  assert.deepEqual(issues, []);
});

void test("parseXref reports errors for out-of-bounds offsets", () => {
  const issues: string[] = [];
  const res = parseXref("short", 100, issues);
  assert.strictEqual(res, null);
  assert.ok(issues.some(msg => msg.includes("outside the file")));
});
