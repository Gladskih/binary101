"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createClrMetadataTablesWithParameterNames } from "../../../fixtures/pe-clr-metadata-tables.js";
import { createClrMetadataTableModels, renderClrMetadataTables } from "../../../../renderers/pe/clr-metadata.js";

void test("renderClrMetadataTables renders CLR parameter names without shifting return parameters", () => {
  const out: string[] = [];
  renderClrMetadataTables(createClrMetadataTablesWithParameterNames(), out);
  const html = out.join("");
  assert.match(html, /Demo\.Buffer::Copy/);
  assert.match(html, /bool returnValue \(string source, i4 length\)/);
  assert.match(html, /\? \(\? value\)/);
  assert.match(html, /NoSignature<\/td><td class="peNumeric">0x00001236<\/td><td class="peNumeric">0x0006/);
  assert.match(html, /Parameter rows/);
  assert.match(html, /<th class="peNumeric">RID<\/th><th class="peNumeric">Sequence<\/th><th>Name/);
  assert.match(html, /<td class="peNumeric">1<\/td><td class="peNumeric">0<\/td><td>returnValue/);
  assert.match(html, /<td class="peNumeric">2<\/td><td class="peNumeric">1<\/td><td>source/);
  assert.match(html, /<td class="peNumeric">3<\/td><td class="peNumeric">2<\/td><td>length/);
  assert.doesNotMatch(html, /string returnValue, i4 source/);
});

void test("makes rows beyond the first page available and reuses table models", () => {
  const metadata = createClrMetadataTablesWithParameterNames();
  metadata.typeDefs = Array.from({ length: 81 }, (_, index) => ({ ...metadata.typeDefs[0]!,
    row: index + 1, name: `T${index}`, fullName: `Demo.T${index}` }));
  const models = createClrMetadataTableModels(metadata);
  const model = models.find(entry => entry.id === "pe-clr-Type%20definitions")!;
  assert.equal(model.rowCount, 81);
  assert.equal(model.rowAt(80)?.cells[0]?.html, "Demo.T80");
  assert.equal(model.rowAt(81), null);
  assert.equal(createClrMetadataTableModels(metadata), models);
  const out: string[] = [];
  renderClrMetadataTables(metadata, out);
  assert.match(out.join(""), /data-paged-sortable-table-root/);
  assert.doesNotMatch(out.join(""), /Showing first/);
});

void test("does not render absent metadata or empty tables", () => {
  const out: string[] = [];
  renderClrMetadataTables(undefined, out);
  assert.deepEqual(out, []);
  const metadata = createClrMetadataTablesWithParameterNames();
  metadata.parameters = [];
  assert.equal(createClrMetadataTableModels(metadata).find(model => model.id === "pe-clr-Parameter%20rows")?.rowAt(0), null);
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
  assert.match(html, /<th class="peNumeric">RID<\/th><th class="peNumeric">Flags<\/th><th>Name<\/th><th>Type/);
  assert.match(html, /&lt;Item>/);
  assert.match(html, /&lt;truncated>/);
  assert.match(html, /Method signature is truncated\./);
});
