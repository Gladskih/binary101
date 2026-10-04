"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  methodSignatureText, renderAdditionalMetadataTables, renderFieldsAndMembers, renderMetadataCell, renderSignatureIssues
} from "../../../../renderers/pe/clr-metadata-cells.js";
import { createClrMetadataTablesWithParameterNames } from "../../../fixtures/pe-clr-metadata-tables.js";

void test("renders scalar cells, blobs and token validity", () => {
  assert.equal(renderMetadataCell(null), "-");
  assert.equal(renderMetadataCell(42), "42");
  assert.equal(renderMetadataCell("<img>"), "&lt;img>");
  assert.equal(renderMetadataCell([0, 255]), "00 ff");
  assert.match(renderMetadataCell(new Array<number>(65).fill(0)), /65 bytes/);
  assert.equal(renderMetadataCell({ table: "Field", tableId: 4, row: 1, raw: 1, valid: true }), "Field #1");
  assert.match(renderMetadataCell({ table: "Field", tableId: 4, row: 2, raw: 2, valid: false }), /invalid/);
});

void test("renders all signature kinds and their warnings", () => {
  assert.equal(renderMetadataCell({ type: "i4[]" }), "i4[]");
  assert.equal(renderMetadataCell({ type: null }), "?");
  assert.equal(renderMetadataCell({ types: ["string", "i4"] }), "string, i4");
  assert.equal(methodSignatureText({ callingConvention: 5, parameterCount: 2,
    returnType: null, parameterTypes: ["i4", null], sentinelIndex: 1 }), "? (i4, ..., ?)");
  assert.equal(renderSignatureIssues([]), "");
  assert.equal(renderSignatureIssues(undefined), "");
  assert.match(renderMetadataCell({ types: [], issues: ["<bad>"] }), /&lt;bad>/);
});

void test("bounds additional tables before formatting and labels missing names", () => {
  const metadata = createClrMetadataTablesWithParameterNames();
  metadata.additionalTables = [{ tableId: 99, rows: new Array<Record<string, number>>(81).fill({ Size: 42 }) },
    { tableId: 98, rows: [] }];
  const html = renderAdditionalMetadataTables(metadata);
  assert.match(html, /Table 99 \(81\)/);
  assert.match(html, /Showing first 80 of 81/);
  assert.equal((html.match(/<tr>/g) ?? []).length, 81);
  assert.doesNotMatch(html, /Table 98/);
});

void test("absence of additional tables produces no disclosure", () => {
  assert.equal(renderAdditionalMetadataTables(createClrMetadataTablesWithParameterNames()), "");
});

void test("renders missing cells in an incomplete row", () => {
  const metadata = createClrMetadataTablesWithParameterNames();
  metadata.additionalTables = [{ tableId: 99, rows: [{ Size: 42 }, {}] }];
  assert.match(renderAdditionalMetadataTables(metadata), /<td class="peNumeric">2<\/td><td>-<\/td>/);
});

void test("shows fields and MemberRefs with signatures and escaped names", () => {
  const metadata = createClrMetadataTablesWithParameterNames();
  metadata.fields = [{ row: 1, name: "<Field>", flags: 0, signatureBlobIndex: 1,
    signature: { callingConvention: 6, parameterCount: 0, returnType: "i4", parameterTypes: [] } }];
  metadata.memberRefs = [{ row: 1, parentName: "<Owner>", name: "Call", signatureBlobIndex: 0,
    parent: { table: "TypeRef", tableId: 1, row: 1, raw: 1, valid: true } }];
  const html = renderFieldsAndMembers(metadata);
  assert.match(html, /Field definitions/);
  assert.match(html, /Member references/);
  assert.match(html, /&lt;Field>/);
  assert.match(html, /&lt;Owner>/);
  assert.match(html, /<td>i4<\/td>/);
  assert.doesNotMatch(html, /i4 \(\)/);
});

void test("handles absent field signatures and unresolved MemberRef parents", () => {
  const metadata = createClrMetadataTablesWithParameterNames();
  metadata.fields = [{ row: 1, name: "Field", flags: 0, signatureBlobIndex: 0 }];
  metadata.memberRefs = [{ row: 1, parentName: null, name: "Call", signatureBlobIndex: 1,
    parent: { table: "TypeRef", tableId: 1, row: 99, raw: 99, valid: false },
    signature: { callingConvention: 6, parameterCount: 0, returnType: null, parameterTypes: [] } }];
  assert.match(renderFieldsAndMembers(metadata), /TypeRef #99 \(invalid\)/);
  assert.match(renderFieldsAndMembers(metadata), /<td>\?<\/td>/);
});
