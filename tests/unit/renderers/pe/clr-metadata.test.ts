"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createClrMetadataTablesWithParameterNames } from "../../../fixtures/pe-clr-metadata-tables.js";
import { renderClrMetadataTables } from "../../../../renderers/pe/clr-metadata.js";

void test("renderClrMetadataTables renders CLR parameter names without shifting return parameters", () => {
  const out: string[] = [];
  renderClrMetadataTables(createClrMetadataTablesWithParameterNames(), out);
  const html = out.join("");
  assert.match(html, /Demo\.Buffer::Copy/);
  assert.match(html, /bool returnValue \(string source, i4 length\)/);
  assert.match(html, /\? \(\? value\)/);
  assert.match(html, /NoSignature<\/td><td>0x00001236<\/td><td>0x0006<\/td><td>-<\/td>/);
  assert.match(html, /Parameter rows/);
  assert.match(html, /<th>RID<\/th><th>Sequence<\/th><th>Name<\/th><th>Flags<\/th>/);
  assert.match(html, /<td>1<\/td><td>0<\/td><td>returnValue<\/td><td>0x0002<\/td>/);
  assert.match(html, /<td>2<\/td><td>1<\/td><td>source<\/td><td>0x0001<\/td>/);
  assert.match(html, /<td>3<\/td><td>2<\/td><td>length<\/td><td>0x0000<\/td>/);
  assert.doesNotMatch(html, /string returnValue, i4 source/);
});

void test("shows additional table columns, signature issues and escaped heap values", () => {
  const metadata = createClrMetadataTablesWithParameterNames();
  metadata.rowCounts.push({ tableId: 0x17, name: "Property", rows: 1, known: true, sorted: false });
  metadata.additionalTables = [{ tableId: 0x17, rows: [{ Flags: 0, Name: "<Item>", Type: {
    callingConvention: 0x28, parameterCount: 0, returnType: "i4", parameterTypes: [],
    issues: ["<truncated>"]
  } }] }];
  metadata.methodDefs[0]!.signature!.issues = ["Method signature is truncated."];
  const out: string[] = [];
  renderClrMetadataTables(metadata, out);
  const html = out.join("");
  assert.match(html, /Property/);
  assert.match(html, /<th>RID<\/th><th>Flags<\/th><th>Name<\/th><th>Type<\/th>/);
  assert.match(html, /&lt;Item>/);
  assert.match(html, /&lt;truncated>/);
  assert.match(html, /Method signature is truncated\./);
});
