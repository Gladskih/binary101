"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { metadataValueText, renderMetadataValue } from "../../../../renderers/pe/clr-metadata-values.js";

void test("renders constants, native types and parameters", () => {
  assert.equal(metadataValueText({ kind: "constant", value: null }), "null");
  assert.equal(metadataValueText({ kind: "constant", value: -1 }), "-1");
  assert.equal(renderMetadataValue({ kind: "constant", value: "<script>" }), "&lt;script>");
  assert.equal(metadataValueText({ kind: "marshal", nativeType: "ARRAY", parameters: { size: 4 } }), "ARRAY; size=4");
});

void test("renders security XML, arguments and nested warnings with HTML escaping", () => {
  assert.equal(renderMetadataValue({ kind: "security", encoding: "xml", xml: "<PermissionSet/>" }), "&lt;PermissionSet/>");
  assert.equal(metadataValueText({ kind: "security", encoding: "binary", attributes: [
    { typeName: "A", namedArguments: [{ kind: "property", type: "i4", name: "B", value: 1 }], issues: ["bad"] },
    { typeName: "C", namedArguments: [] }, { typeName: "D", namedArguments: [], issues: [] }
  ] }), "A: property i4 B=1 (bad)\nC: \nD: ");
});
