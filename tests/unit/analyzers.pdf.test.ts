"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePdf } from "../../analyzers/pdf/index.js";
import { createPdfFile } from "../fixtures/sample-files.js";
import { createPdfMissingStartxref, createPdfWithBadXref } from "../fixtures/pdf-fixtures.js";
import { createPdfWithXrefStream } from "../fixtures/pdf-corrupt-stream.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("parsePdf warns when startxref is missing", async () => {
  const pdf = expectDefined(await parsePdf(createPdfMissingStartxref()));
  assert.ok(pdf.issues.some(issue => issue.toLowerCase().includes("startxref")));
});

void test("parsePdf warns when startxref points outside file", async () => {
  const pdf = expectDefined(await parsePdf(createPdfWithBadXref()));
  assert.ok(pdf.issues.some(issue => issue.toLowerCase().includes("offset")));
});

void test("parsePdf parses minimal valid PDF", async () => {
  const pdf = expectDefined(await parsePdf(createPdfFile()));
  assert.ok(pdf.header);
  assert.ok(pdf.xref);
});

void test("parsePdf notes xref stream detection", async () => {
  const pdf = expectDefined(await parsePdf(createPdfWithXrefStream()));
  assert.ok(pdf.issues.some(issue => issue.toLowerCase().includes("cross-reference stream")));
});
