"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseHeader, parseStartxref } from "../../../../analyzers/pdf/header.js";

void test("parseHeader reads version and binary marker", () => {
  const issues: string[] = [];
  // ISO 32000-2, 7.5.2: the binary marker is a comment with at least four high bytes.
  const header = parseHeader("%PDF-1.7\r%\xE2\xE3\xCF\xD3", issues);
  assert.strictEqual(header.version, "1.7");
  assert.strictEqual(header.binaryMarker, "%\xE2\xE3\xCF\xD3");
  assert.deepEqual(issues, []);
});

void test("parseHeader reports malformed header", () => {
  const issues: string[] = [];
  const header = parseHeader("garbage", issues);
  assert.deepEqual(header, { headerLine: "garbage", version: null, binaryMarker: null });
  assert.deepEqual(issues, ["Missing or malformed %PDF- header."]);
});

void test("parseStartxref returns offset or reports missing", () => {
  const issues: string[] = [];
  assert.strictEqual(parseStartxref("startxref\n42\n%%EOF\n", issues), 42);
  const errs: string[] = [];
  assert.strictEqual(parseStartxref("no marker", errs), null);
  assert.deepEqual(errs, ["Final %%EOF marker and startxref offset could not be located."]);
});

void test("header preserves both version components, CRLF separation and trailing padding", () => {
  const issues: string[] = [];
  assert.deepEqual(parseHeader("%PDF-12.34 \r\n% ordinary comment", issues),
    { headerLine: "%PDF-12.34", version: "12.34", binaryMarker: null });
  assert.deepEqual(issues, []);
});

for (const value of ["padding %PDF-1.7", "%PDF-1.7extra", " %PDF-1.7"]) {
  void test("rejects the entire malformed header " + JSON.stringify(value), () => {
    assert.equal(parseHeader(value, []).version, null);
  });
}

for (const value of ["%\xE2\xE3\xCFa", "%\xE2", "foo%\xE2\xE3\xCF\xD3"]) {
  void test("recognizes a binary marker only at the start of the second line", () => {
    assert.equal(parseHeader("%PDF-2.0\n" + value, []).binaryMarker, null);
  });
}

void test("uses the final standalone EOF and accepts CRLF and horizontal padding", () => {
  const issues: string[] = [];
  assert.equal(parseStartxref(
    "startxref\r\n18\r\n%%EOF\r\nstartxref \t\r\n\t92 \r\n%%EOF \t\r\n%%EOFsuffix", issues), 92);
  assert.deepEqual(issues, []);
});

void test("reports when a tail consisting only of EOF has no offset", () => {
  const issues: string[] = [];
  assert.equal(parseStartxref("%%EOF", issues), null);
  assert.deepEqual(issues, ["Missing or invalid startxref offset before %%EOF."]);
});

void test("parseStartxref anchors the offset to the final EOF line", () => {
  const issues: string[] = [];
  assert.equal(parseStartxref("startxref\r42\r%%EOF\r% startxref 11", issues), 42);
  assert.deepEqual(issues, []);
});

for (const tail of ["42junk", "9007199254740992", "-1", "42\n% unrelated"]) {
  void test("parseStartxref rejects " + JSON.stringify(tail), () => {
    const issues: string[] = [];
    assert.equal(parseStartxref("startxref\n" + tail + "\n%%EOF\n", issues), null);
    assert.match(issues.join("\n"), /startxref/);
  });

void test("rejects extra text on the startxref keyword line", () => {
  const issues: string[] = [];
  assert.equal(parseStartxref("startxref junk\n42\n%%EOF", issues), null);
  assert.deepEqual(issues, ["Missing or invalid startxref offset before %%EOF."]);
});
}
