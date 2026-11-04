import assert from "node:assert/strict";
import { test } from "node:test";
import { inspectEmbeddedDocument } from "../../../../../../analyzers/pe/resources/preview/embedded-document.js";
import { createPdfFile } from "../../../../../fixtures/document-sample-files.js";
import { createZipFile } from "../../../../../fixtures/zip-fixtures.js";
import { createAviFile } from "../../../../../fixtures/riff-sample-files.js";

void test("inspects embedded documents with the existing local analyzers", async () => {
  const pdf = await inspectEmbeddedDocument(createPdfFile().data, "PDF");
  const zip = await inspectEmbeddedDocument(createZipFile().data, "ZIP");
  const avi = await inspectEmbeddedDocument(createAviFile().data, "AVI");

  assert.ok(pdf.preview?.embeddedDocument?.analysis);
  assert.ok(zip.preview?.embeddedDocument?.analysis);
  assert.ok(avi.preview?.embeddedDocument?.analysis);
});

void test("retains unsupported or truncated document diagnostics", async () => {
  assert.ok((await inspectEmbeddedDocument(new Uint8Array(), "PDF")).issues?.length);
  assert.ok((await inspectEmbeddedDocument(new Uint8Array(), "ZIP")).issues?.length);
  assert.ok((await inspectEmbeddedDocument(new Uint8Array(), "AVI")).issues?.length);
});
