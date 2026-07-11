"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PePackerAnalysis } from "../../../../analyzers/pe/packers/index.js";
import { renderPackers } from "../../../../renderers/pe/packers.js";

const createPackers = (): PePackerAnalysis => ({
  findings: [{
    id: "sample",
    name: "<Runtime>",
    kind: "runtime-packager",
    confidence: "high",
    evidence: ["<evidence>"],
    // Fixed endpoints are the oracle for PE-style 8-digit hexadecimal ranges.
    details: [{ label: "<range>", kind: "range", start: 0x10, end: 0x20 }]
  }],
  warnings: ["<warning>"]
});

void test("renderPackers renders nothing when analysis is absent", () => {
  const out: string[] = [];

  renderPackers(null, out);

  assert.deepEqual(out, []);
});

void test("renderPackers renders escaped findings and warnings", () => {
  const out: string[] = [];

  renderPackers(createPackers(), out);

  const html = out.join("");
  assert.ok(html.includes("Packaging signatures"));
  assert.ok(html.includes("&lt;Runtime>"));
  assert.ok(html.includes("&lt;evidence>"));
  assert.ok(html.includes("0x00000010-0x00000020"));
  assert.ok(html.includes("&lt;warning>"));
});

void test("renderPackers shows warning-only malformed packaging analysis", () => {
  const out: string[] = [];

  renderPackers({ findings: [], warnings: ["bad"] }, out);

  const html = out.join("");
  assert.ok(html.includes("No high-confidence packaging signature was detected."));
});

void test("renderPackers labels executable packer findings", () => {
  const packers = createPackers();
  packers.findings[0]!.kind = "executable-packer";
  const out: string[] = [];

  renderPackers(packers, out);

  assert.ok(out.join("").includes("executable packer"));
});
