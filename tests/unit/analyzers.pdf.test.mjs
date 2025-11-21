"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePdf } from "../../analyzers/pdf/index.js";
import { createPdfFile } from "../fixtures/sample-files.mjs";
import { createPdfMissingStartxref, createPdfWithBadXref } from "../fixtures/pdf-fixtures.mjs";
import { createPdfWithXrefStream } from "../fixtures/pdf-corrupt-stream.mjs";

test("parsePdf warns when startxref is missing", async () => {
  const pdf = await parsePdf(createPdfMissingStartxref());
  assert.ok(pdf);
  assert.ok(pdf.issues.some(issue => issue.toLowerCase().includes("startxref")));
});

test("parsePdf warns when startxref points outside file", async () => {
  const pdf = await parsePdf(createPdfWithBadXref());
  assert.ok(pdf);
  assert.ok(pdf.issues.some(issue => issue.toLowerCase().includes("offset")));
});

test("parsePdf parses minimal valid PDF", async () => {
  const pdf = await parsePdf(createPdfFile());
  assert.ok(pdf.header);
  assert.ok(pdf.xref);
});

test("parsePdf notes xref stream detection", async () => {
  const pdf = await parsePdf(createPdfWithXrefStream());
  assert.ok(pdf.issues.some(issue => issue.toLowerCase().includes("cross-reference stream")));
});
