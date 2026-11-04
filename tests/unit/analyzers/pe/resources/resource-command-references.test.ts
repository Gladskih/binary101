import assert from "node:assert/strict";
import { test } from "node:test";
import { collectResourceCommandReferences, resourceNumericId } from
  "../../../../../analyzers/pe/resources/resource-command-references.js";
import { createPreviewLangEntry } from "../../../../helpers/pe-resource-preview-fixture.js";
import { addXmlResourcePreviewWithParser } from "../../../../../analyzers/pe/resources/preview/xml.js";
import { parseManifestTestXmlDocument } from "../../../../helpers/manifest-test-parser.js";
import { interactiveRibbonXml } from "../../../../fixtures/pe-resource-interactive-payloads.js";

void test("only accepts exact unsigned DWORD resource IDs", () => {
  assert.equal(resourceNumericId("4294967295"), 4294967295);
  assert.equal(resourceNumericId("4294967296"), null);
  assert.equal(resourceNumericId("9007199254740993"), null);
  assert.equal(resourceNumericId("-1"), null);
  assert.equal(resourceNumericId("0x10"), null);
  assert.equal(resourceNumericId("0"), 0);
  assert.equal(resourceNumericId(undefined), null);
});

void test("collects command string conventions and possible document-template associations", () => {
  const leaf = { ...createPreviewLangEntry(), toolbar: { version: 1, width: 16, height: 16, items: [0, 100, 100] },
    stringTable: [{ id: 200, text: "Window\nDoc\nNew\nFilter\n.bin" }, { id: null, text: "ordinary" }] };
  const references = collectResourceCommandReferences(leaf);

  assert.deepEqual(references.map(item => [item.key, item.types]), [
    [100, ["STRING"]], [200, ["MENU"]], [200, ["GROUP_ICON"]], [200, ["ACCELERATOR"]]
  ]);
});

void test("recognizes command IDs within the real MFC Ribbon XML wrapper", () => {
  const xml = addXmlResourcePreviewWithParser(new TextEncoder().encode(interactiveRibbonXml), "RIBBON_XML", 65001,
    parseManifestTestXmlDocument);
  const references = collectResourceCommandReferences({ ...createPreviewLangEntry(), ...xml?.preview });

  assert.deepEqual(references.map(item => item.key).sort((left, right) => left - right), [100, 101]);
});
