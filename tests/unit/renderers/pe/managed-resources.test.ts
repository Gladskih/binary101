"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createManagedResourceTableModel, createManagedResourceValueTableModel,
  getManagedResourceTableModel, renderManagedResources
} from "../../../../renderers/pe/managed-resources.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import type {
  PeClrManagedResourceEntry, PeClrManagedResourceValue
} from "../../../../analyzers/pe/clr/managed-resource-types.js";
import { createClrHeaderFixture } from "../../../fixtures/pe-manifest-preview-fixture.js";
import { createClrMetadataTablesWithParameterNames } from "../../../fixtures/pe-clr-metadata-tables.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";

const resource = (row = 1): PeClrManagedResourceEntry => ({
  row, name: "Demo.resources", flags: 1, offset: row * 16, size: row * 32,
  implementation: { raw: 0, row: 0, table: "null", tableId: -1, valid: true },
  storage: "embedded"
});

const value = (index = 0): PeClrManagedResourceValue => ({
  name: `entry-${index}`, type: "String", value: `text-${index}`, opaque: false
});

const clr = (entries: PeClrManagedResourceEntry[] = [resource()]) => ({
  ...createClrHeaderFixture(1), managedResources: { entries, issues: [] as string[] }
});

void test("managed resources use a dense table with numeric size and offset cells", () => {
  const model = createManagedResourceTableModel(clr());

  assert.strictEqual(model.rowCount, 1);
  assert.strictEqual(model.rowAt(0)?.cells[0]?.html, "Demo.resources");
  assert.strictEqual(model.rowAt(0)?.cells[3]?.className, "peNumeric");
  assert.strictEqual(model.rowAt(0)?.cells[4]?.className, "peNumeric");
  assert.strictEqual(model.sortValueAt(0, 3), "16");
  assert.strictEqual(model.sortValueAt(0, 4), "32");
  assert.strictEqual(model.sortValueAt(0, 0), "Demo.resources");
  assert.strictEqual(model.sortValueAt(0, 99), "");
  assert.strictEqual(model.rowAt(1), null);
  assert.strictEqual(model.sortValueAt(1, 0), "");
  assert.strictEqual(model.rowAt(0)?.additionalRowsHtml, "");
});

void test("external implementations resolve their metadata names and escape HTML", () => {
  const header = clr([{ ...resource(), name: "<unsafe>", storage: "external", size: null,
    flags: 2, implementation: { raw: 4, row: 1, table: "File", tableId: 38, valid: true } }]);
  header.meta = { streams: [], tables: createClrMetadataTablesWithParameterNames() };
  header.meta.tables!.files = [{ row: 1, name: "linked.resources", flags: 0, hashValueSize: 0 }];
  const model = createManagedResourceTableModel(header);

  assert.strictEqual(model.rowAt(0)?.cells[0]?.html, "&lt;unsafe>");
  assert.match(model.rowAt(0)?.cells[2]?.html ?? "", /Private/);
  assert.match(model.rowAt(0)?.cells[5]?.html ?? "", /File #1: linked.resources/);
  assert.strictEqual(model.sortValueAt(0, 4), "");
});

void test("missing implementation targets and unknown flags remain visible", () => {
  const model = createManagedResourceTableModel(clr([{ ...resource(), name: null, flags: 0,
    implementation: { raw: 5, row: 1, table: "AssemblyRef", tableId: 35, valid: false } }]));

  assert.match(model.rowAt(0)?.cells[0]?.html ?? "", /unnamed/);
  assert.match(model.rowAt(0)?.cells[2]?.html ?? "", /Unknown/);
  assert.match(model.rowAt(0)?.cells[5]?.html ?? "", /AssemblyRef #1 \(invalid\)/);
});

void test("the resource table displays previews, nested entries and warnings", () => {
  const entry = { ...resource(), entries: [value()], previewKind: "text", textPreview: "<unsafe>",
    issues: ["<warning>"] };
  const model = createManagedResourceTableModel(clr([entry]));

  assert.match(model.rowAt(0)?.cells[6]?.html ?? "", /\.resources \(1 entries\)/);
  assert.match(model.rowAt(0)?.additionalRowsHtml ?? "", /Entry/);
  assert.match(model.rowAt(0)?.additionalRowsHtml ?? "", /&lt;unsafe>/);
  assert.match(model.rowAt(0)?.additionalRowsHtml ?? "", /&lt;warning>/);
});

void test("value tables distinguish null, malformed values and serialized objects", () => {
  const model = createManagedResourceValueTableModel([
    { ...value(), value: null }, { ...value(), value: null, issues: ["<broken>"] },
    { ...value(), opaque: true }, { ...value(), previewKind: "text", textPreview: "preview" }
  ], 1);

  assert.strictEqual(model.rowAt(0)?.cells[2]?.html, "null");
  assert.strictEqual(model.rowAt(1)?.cells[2]?.html, "Unavailable");
  assert.match(model.rowAt(1)?.additionalRowsHtml ?? "", /&lt;broken>/);
  assert.strictEqual(model.rowAt(2)?.cells[2]?.html, "Opaque serialized data");
  assert.strictEqual(model.rowAt(3)?.cells[2]?.html, "See preview");
  assert.match(model.rowAt(3)?.additionalRowsHtml ?? "", /preview/);
  assert.strictEqual(model.sortValueAt(3, 2), "text-0");
  assert.strictEqual(model.sortValueAt(0, 99), "");
  assert.strictEqual(model.rowAt(4), null);
  assert.strictEqual(model.sortValueAt(4, 0), "");
});

void test("all managed resources and values can be paged through the PE model resolver", () => {
  const header = clr(Array.from({ length: 51 }, (_, index) => ({ ...resource(index + 1),
    entries: Array.from({ length: 51 }, (_, index) => value(index)) })));
  const pe = createBasePe();
  pe.clr = header;
  const model = getPePagedTableModel(pe, "pe-clr-managed-resource-values-51");

  assert.strictEqual(model?.rowCount, 51);
  assert.strictEqual(model?.rowAt(50)?.cells[0]?.html, "entry-50");
  assert.strictEqual(getManagedResourceTableModel(header, "pe-clr-managed-resources")?.rowCount, 51);
  assert.strictEqual(getManagedResourceTableModel(header, "pe-clr-managed-resource-values-99"), null);
  assert.strictEqual(getManagedResourceTableModel(header, "unknown"), null);
  assert.strictEqual(getManagedResourceTableModel(clr(), "pe-clr-managed-resource-values-1"), null);
  assert.strictEqual(getManagedResourceTableModel(null, "pe-clr-managed-resources"), null);
});

void test("resource sections show warnings and only paginate when necessary", () => {
  const header = clr(Array.from({ length: 51 }, (_, index) => resource(index + 1)));
  header.managedResources.issues = ["global warning"];
  const out: string[] = [];

  renderManagedResources(header, out);
  renderManagedResources(createClrHeaderFixture(1), out);

  assert.match(out.join(""), /Managed resources \(51\)/);
  assert.match(out.join(""), /pagedSortableTableToolbar/);
  assert.match(out.join(""), /global warning/);
  assert.strictEqual(createManagedResourceTableModel(createClrHeaderFixture(1)).rowCount, 0);
});

void test("long string cells are bounded without changing their parsed value", () => {
  const parsed = { ...value(), value: "x".repeat(2048) };
  const model = createManagedResourceValueTableModel([parsed], 1);

  assert.match(model.rowAt(0)?.cells[2]?.html ?? "", /display capped/);
  assert.strictEqual(parsed.value.length, 2048);
});

void test("string source previews are rendered from the value without a duplicate parsed field", () => {
  const model = createManagedResourceValueTableModel([{ ...value(), previewKind: "text",
    value: "<escaped>" }], 1);

  assert.match(model.rowAt(0)?.additionalRowsHtml ?? "", /&lt;escaped>/);
});
