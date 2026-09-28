"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addXmlResourcePreviewWithParser } from "../../../../../../analyzers/pe/resources/preview/xml.js";
import { parseManifestTestXmlDocument } from "../../../../../helpers/manifest-test-parser.js";

const encoder = new TextEncoder();
// Windows code page identifier for UTF-8. Source:
// https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
const WINDOWS_UTF8_CODE_PAGE = 65001;

void test(
  "addXmlResourcePreviewWithParser builds a generic XML tree for XMLFILE resources",
  () => {
  const result = addXmlResourcePreviewWithParser(
    encoder.encode("<root lang=\"en\"><child>value</child></root>"),
    "XMLFILE",
    WINDOWS_UTF8_CODE_PAGE,
    parseManifestTestXmlDocument
  );

  assert.equal(result?.preview?.previewKind, "xml");
  assert.equal(result?.preview?.xmlTree?.name, "root");
  assert.deepEqual(result?.preview?.xmlTree?.attributes, [{ name: "lang", value: "en" }]);
  assert.equal(result?.preview?.xmlTree?.children[0]?.name, "child");
  assert.equal(result?.preview?.xmlTree?.children[0]?.text, "value");
  assert.equal(result?.issues, undefined);
  }
);

void test("addXmlResourcePreviewWithParser reports malformed XML without throwing", () => {
  const result = addXmlResourcePreviewWithParser(
    encoder.encode("<root><child></root>"),
    "UIFILE",
    WINDOWS_UTF8_CODE_PAGE,
    parseManifestTestXmlDocument
  );

  assert.equal(result?.preview?.previewKind, "xml");
  assert.equal(result?.preview?.xmlTree, undefined);
  assert.ok(result?.issues?.some(issue => /UIFILE markup/i.test(issue)));
});

void test("addXmlResourcePreviewWithParser summarizes non-XML named resources", () => {
  const result = addXmlResourcePreviewWithParser(
    encoder.encode("compiled payload"),
    "UIFILE",
    WINDOWS_UTF8_CODE_PAGE,
    parseManifestTestXmlDocument
  );

  assert.equal(result?.preview?.previewKind, "summary");
  assert.ok(
    result?.preview?.previewFields?.some(field => field.value.includes("not plain XML text"))
  );
});

void test("addXmlResourcePreviewWithParser ignores unrelated resource types", () => {
  assert.equal(
    addXmlResourcePreviewWithParser(
      encoder.encode("<root/>"),
      "RCDATA",
      WINDOWS_UTF8_CODE_PAGE,
      parseManifestTestXmlDocument
    ),
    null
  );
});

void test("recognizes MFC ribbon XML by numeric resource type", () => {
  const result = addXmlResourcePreviewWithParser(
    encoder.encode("<RIBBON_BAR><CATEGORY/></RIBBON_BAR>"),
    "RIBBON_XML",
    WINDOWS_UTF8_CODE_PAGE,
    parseManifestTestXmlDocument
  );
  assert.equal(result?.preview?.previewKind, "ribbonXml");
  assert.equal(result?.preview?.xmlTree?.name, "RIBBON_BAR");
});

void test("recognizes compiled UIFILE without decoding it as XML", () => {
  // UIRibbon-Reversing/new.ksy: nine-byte preamble, SCBin, then total length.
  const bytes = new Uint8Array([0, 18, 0, 0, 0, 0, 0, 1, 0,
    83, 67, 66, 105, 110, 30, 0, 0, 0, 2, 7, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0]);
  const result = addXmlResourcePreviewWithParser(
    bytes, "UIFILE", WINDOWS_UTF8_CODE_PAGE, parseManifestTestXmlDocument
  );
  assert.equal(result?.preview?.previewKind, "summary");
  assert.ok(result?.preview?.previewFields?.some(field => field.value.includes("compiled BML")));
  assert.deepEqual(result?.preview?.ribbonBml, { strings: [], commands: [] });
  assert.equal(result?.issues, undefined);
  assert.match(addXmlResourcePreviewWithParser(bytes.subarray(0, 14), "UIFILE",
    WINDOWS_UTF8_CODE_PAGE, parseManifestTestXmlDocument)?.issues?.[0] ?? "", /truncated/);
  bytes[14] = 31;
  assert.match(addXmlResourcePreviewWithParser(bytes, "UIFILE", WINDOWS_UTF8_CODE_PAGE,
    parseManifestTestXmlDocument)?.issues?.[0] ?? "", /length differs/);
});
