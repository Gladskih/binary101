import assert from "node:assert/strict";
import { test } from "node:test";
import { renderEmbeddedDocument } from "../../../../renderers/pe/resource-preview-document.js";
import { inspectEmbeddedDocument } from "../../../../analyzers/pe/resources/preview/embedded-document.js";
import { createPdfFile } from "../../../fixtures/document-sample-files.js";
import { createZipFile } from "../../../fixtures/zip-fixtures.js";
import { createAviFile } from "../../../fixtures/riff-sample-files.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
void test("formats locally inspected PDF, ZIP and AVI metadata", async () => {
  const pdf = expectDefined((await inspectEmbeddedDocument(createPdfFile().data,"PDF")).preview?.embeddedDocument);
  const zip = expectDefined((await inspectEmbeddedDocument(createZipFile().data,"ZIP")).preview?.embeddedDocument);
  const avi = expectDefined((await inspectEmbeddedDocument(createAviFile().data,"AVI")).preview?.embeddedDocument);
  assert.match(renderEmbeddedDocument(pdf), /Version/);
  assert.match(renderEmbeddedDocument(zip), /Uncompressed/);
  assert.match(renderEmbeddedDocument(avi), /Codec/);
  assert.match(renderEmbeddedDocument({format:"PDF"}), /Embedded PDF/);
});
