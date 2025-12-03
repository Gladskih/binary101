"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseHeader, parseStartxref } from "../../analyzers/pdf/header.js";

void test("parseHeader reads version and binary marker", () => {
  const issues: string[] = [];
  const header = parseHeader("%PDF-1.7\n%1234", issues);
  assert.strictEqual(header.version, "1.7");
  assert.strictEqual(header.binaryMarker, "%PDF-1.7");
  assert.deepEqual(issues, []);
});

void test("parseHeader reports malformed header", () => {
  const issues: string[] = [];
  const header = parseHeader("garbage", issues);
  assert.strictEqual(header.version, null);
  assert.ok(issues.some(msg => msg.includes("Missing or malformed")));
});

void test("parseStartxref returns offset or reports missing", () => {
  const issues: string[] = [];
  assert.strictEqual(parseStartxref("startxref\n42", issues), 42);
  const errs: string[] = [];
  assert.strictEqual(parseStartxref("no marker", errs), null);
  assert.ok(errs.length > 0);
});
