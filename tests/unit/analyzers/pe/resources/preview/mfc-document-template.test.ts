import assert from "node:assert/strict";
import { test } from "node:test";
import { readMfcDocumentTemplate } from "../../../../../../analyzers/pe/resources/preview/mfc-document-template.js";

void test("recognizes the seven CDocTemplate fields and optional registry strings", () => {
  assert.deepEqual(readMfcDocumentTemplate("Window\nDocument\nNew\nText (*.txt)\n.txt\nText.Document\nText document"), {
    windowTitle: "Window", documentName: "Document", newName: "New", filter: "Text (*.txt)",
    extension: ".txt", registryId: "Text.Document", registryName: "Text document"
  });
  assert.equal(readMfcDocumentTemplate("\nDoc\nNew\nFiles\n.dat")?.registryName, "");
});

void test("rejects unrelated multiline strings, paths and extra fields", () => {
  assert.equal(readMfcDocumentTemplate("one\ntwo\nthree\nfour"), null);
  assert.equal(readMfcDocumentTemplate("a\nb\nc\nd\n.exe\ne\nf\ng"), null);
  assert.equal(readMfcDocumentTemplate("a\nb\nc\nd\n.c:/x"), null);
  assert.equal(readMfcDocumentTemplate("a\nb\nc\nd\nnoextension"), null);
});
