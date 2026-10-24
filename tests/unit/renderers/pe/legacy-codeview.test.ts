import assert from "node:assert/strict";
import { test } from "node:test";
import { renderLegacyCodeView, getLegacyCodeViewTableModel,
  renderCodeViewSources } from "../../../../renderers/pe/legacy-codeview.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";
import { codeViewInfoWithTypes } from "../../../fixtures/pe-codeview-callables.js";

const subject = () => {
  const pe = createBasePe();
  const entry = { ...createDebugViewEntry(2, 0, 128), legacyCodeView: createLegacyCodeViewInfo() };
  pe.debug = { entry: null, entries: [entry] };
  return { pe, entry };
};

void test("CodeView stored type strings preserve literal entity spellings", () => {
  const { pe, entry } = subject();
  entry.legacyCodeView = codeViewInfoWithTypes([
    { type: 0x1605, index: 0x1000, strings: ["<path>&amp;.cpp"], shape: { kind: "stringId", substrings: 0 } }
  ]);
  const model = getLegacyCodeViewTableModel(pe, "pe-debug-entry-0-legacy-typeStrings")!;
  assert.equal(model.rowAt(0)?.cells[3]?.html, "&lt;path&gt;&amp;amp;.cpp");
});

void test("CodeView function signatures retain literal entities and remain pageable", () => {
  const pe = createBasePe();
  const entry = { ...createDebugViewEntry(2, 0, 128), legacyCodeView: codeViewInfoWithTypes([
    { type: 0x1201, index: 0x1000, shape: { kind: "arguments", types: [] } },
    { type: 0x1008, index: 0x1001, shape: { kind: "procedure", returnType: 3,
      parameterCount: 0, argumentList: 0x1000, callingConvention: 0, attributes: 0 } },
    ...Array.from({ length: 101 }, (_, index) => ({ type: 0x1601, index: 0x1002 + index,
      strings: [`<function_${index}>&amp;`], shape: { kind: "functionId" as const, scopeId: 0, functionType: 0x1001 } }))
  ]) };
  pe.debug = { entry: null, entries: [entry] };
  const model = getLegacyCodeViewTableModel(pe, "pe-debug-entry-0-legacy-functions")!;
  const out: string[] = [];
  renderLegacyCodeView(entry, 0, out);
  assert.equal(model.rowCount, 101);
  assert.equal(model.pageSize, 100);
  assert.equal(model.rowAt(100)?.cells[2]?.html, "&lt;function_100&gt;&amp;amp;");
  assert.equal(model.rowAt(0)?.cells[5]?.className, "peNumeric");
  assert.equal(model.sortValueAt(100, 2), "<function_100>&amp;");
  assert.match(out.join(""), /Function type signatures/);
});

for (const kind of ["overlay", "section", "directory"] as const) {
  void test(`Standalone CodeView ${kind} sources retain escaped, pageable tables`, () => {
    const { pe, entry } = subject();
    pe.debug = { entry: null, codeViewSources: [
      { kind, offset: 512, size: 128, legacyCodeView: entry.legacyCodeView }] };
    const out: string[] = [];
    renderCodeViewSources(pe, out);
    const model = getLegacyCodeViewTableModel(pe, "pe-debug-codeviewSource-0-legacy-module")!;
    assert.match(out.join(""), /CodeView source #1:/);
    assert.match(out.join(""), /&lt;module&gt;.obj/);
    assert.equal(model.rowAt(0)?.cells[2]?.html, "&lt;module&gt;.obj");
    assert.equal(getLegacyCodeViewTableModel(pe, "pe-debug-codeviewSource-1-legacy-module"), null);
  });
}

void test("legacy CodeView renders escaped readable tables and statistical summaries", () => {
  const { pe, entry } = subject();
  const out: string[] = [];
  renderLegacyCodeView(entry, 0, out);
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-legacy-module")!;

  assert.match(out.join(""), /Embedded CodeView format/);
  assert.match(out.join(""), /&lt;module&gt;.obj/);
  assert.match(out.join(""), /&lt;public&gt;/);
  assert.match(out.join(""), /&lt;field&gt;/);
  assert.match(out.join(""), /\.\?AU&lt;Structure&gt;@@/);
  assert.equal(getLegacyCodeViewTableModel(pe, "pe-debug-entry-0-legacy-types")?.tableClassName,
    "peCodeViewTypeTable");
  assert.match(out.join(""), /Member and enumerator names/);
  assert.equal(getLegacyCodeViewTableModel(pe, "pe-debug-entry-0-legacy-members")?.tableClassName,
    "peCodeViewMemberTable");
  assert.match(out.join(""), /Line\/address pairs/);
  assert.doesNotMatch(out.join(""), /<public>|RVA<\/th>|0x00000010/);
  assert.equal(model.rowAt(0)?.cells[2]?.html, "&lt;module&gt;.obj");
  assert.equal(model.sortValueAt(0, 2), "<module>.obj");
  assert.equal(model.rowAt(1), null);
  assert.equal(model.sortValueAt(1, 2), "");
  assert.equal(model.sortValueAt(0, 9), "");
});

void test("CodeView symbol strings remain escaped and available beyond the first page", () => {
  const { pe, entry } = subject();
  entry.legacyCodeView.directories[0]!.subsections.push({ type: 0x125, module: 2, offset: 0, size: 0,
    data: { kind: "symbols", records: [{ type: 0x1019, strings:
      Array.from({ length: 101 }, (_, index) => `<annotation_${index}>`) }] } });
  const out: string[] = [];
  renderLegacyCodeView(entry, 0, out);
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-legacy-symbolStrings")!;

  assert.match(out.join(""), /Stored symbol strings/);
  assert.match(out.join(""), /&lt;annotation_0&gt;/);
  assert.doesNotMatch(out.join(""), /<annotation_0>/);
  assert.equal(model.rowCount, 101);
  assert.equal(model.pageSize, 100);
  assert.equal(model.rowAt(100)?.cells[3]?.html, "String 101");
  assert.equal(model.rowAt(100)?.cells[4]?.html, "&lt;annotation_100&gt;");
  assert.equal(model.sortValueAt(100, 4), "<annotation_100>");
});

void test("CodeView index statistics retain escaped section names and right-align numeric counts", () => {
  const { pe, entry } = subject();
  entry.legacyCodeView.directories[0]!.subsections.push({ type: 0x12e, module: 0, offset: 0, size: 0,
    data: { kind: "segmentNames", names: [{ offset: 0, name: "<section>" }] } });
  entry.legacyCodeView.directories[0]!.subsections.push({ type: 0x12a, module: 0, offset: 0, size: 0,
    data: { kind: "symbols", records: [], addressIndex: { algorithm: 12, counts: [7] },
      nameIndex: { algorithm: 10, counts: [7] } } });
  const out: string[] = [];
  renderLegacyCodeView(entry, 0, out);
  const sections = getPePagedTableModel(pe, "pe-debug-entry-0-legacy-indexedSections")!;
  const summary = getPePagedTableModel(pe, "pe-debug-entry-0-legacy-indexes")!;
  const buckets = getPePagedTableModel(pe, "pe-debug-entry-0-legacy-buckets")!;

  assert.match(out.join(""), /Symbol index statistics \(declared counts\)/);
  assert.doesNotMatch(out.join(""), /<section>|RVA<\/th>|Chain offset/);
  assert.equal(sections.rowAt(0)?.cells[3]?.html, "&lt;section&gt;");
  assert.equal(sections.columns[4]?.className, "peNumeric");
  assert.equal(sections.rowAt(0)?.cells[4]?.className, "peNumeric");
  assert.equal(summary.columns[3]?.className, "");
  assert.equal(summary.tableClassName, "peCodeViewIndexTable");
  assert.equal(buckets.tableClassName, undefined);
  assert.deepEqual(summary.columns.slice(5).map(column => column.className),
    ["peNumeric", "peNumeric", "peNumeric", "peNumeric"]);
  assert.deepEqual(buckets.columns.slice(3).map(column => column.className), ["peNumeric", "peNumeric"]);
});

void test("CodeView embedded names are paginated, escaped and accompanied by numeric discard statistics", () => {
  const { pe, entry } = subject();
  entry.legacyCodeView.directories[0]!.subsections.push({ type: 0x125, module: 2, offset: 0, size: 0,
    data: { kind: "symbols", records: [{ type: 0x113b, discarded: { reason: 2, fileId: 0, line: 42 },
      children: Array.from({ length: 101 }, (_, index) => ({ type: 0x110d, name: `<removed_${index}>` })) }] } });
  entry.legacyCodeView.directories[0]!.subsections.push({ type: 0x121, module: 3, offset: 0, size: 0,
    data: { kind: "types", records: [{ type: 2, strings: ["Base"] }, { type: 0x1002, strings: ["WideBase"] }] } });
  const out: string[] = [];
  renderLegacyCodeView(entry, 0, out);
  const names = getPePagedTableModel(pe, "pe-debug-entry-0-legacy-embeddedSymbols")!;
  const statistics = getPePagedTableModel(pe, "pe-debug-entry-0-legacy-discardedSymbols")!;
  const strings = getPePagedTableModel(pe, "pe-debug-entry-0-legacy-typeStrings")!;

  assert.match(out.join(""), /Embedded symbol names|Embedded symbol statistics/);
  assert.match(out.join(""), /Pointer base type/);
  assert.match(out.join(""), /&lt;removed_0&gt;/);
  assert.doesNotMatch(out.join(""), /<removed_0>/);
  assert.equal(names.rowCount, 101);
  assert.equal(names.id, "pe-debug-entry-0-legacy-embeddedSymbols");
  assert.equal(statistics.id, "pe-debug-entry-0-legacy-discardedSymbols");
  assert.equal(names.rowAt(100)?.cells[4]?.html, "&lt;removed_100&gt;");
  assert.equal(names.sortValueAt(100, 4), "<removed_100>");
  assert.equal(statistics.tableClassName, "peCodeViewDiscardedTable");
  assert.deepEqual(statistics.columns.slice(3).map(column => column.className),
    ["peNumeric", "peNumeric", "peNumeric", "peNumeric"]);
  assert.deepEqual(statistics.rowAt(0)?.cells.slice(3).map(cell => cell.html), ["1", "1", "42", "42"]);
  assert.equal(strings.sortValueAt(0, 2), "Pointer base type");
  assert.equal(strings.sortValueAt(1, 2), "Pointer base type");
});

void test("CodeView stored strings are escaped, paginated and available through the table dispatcher", () => {
  const { pe, entry } = subject();
  entry.legacyCodeView.directories[0]!.subsections.push({ type: 0x121, module: 2, offset: 0, size: 0,
    data: { kind: "types", records: Array.from({ length: 101 }, (_, index) =>
      ({ type: 0x1605, strings: [`<string_${index}>`] })) } });
  const out: string[] = [];
  renderLegacyCodeView(entry, 0, out);
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-legacy-typeStrings")!;

  assert.match(out.join(""), /Stored type and ID strings/);
  assert.match(out.join(""), /&lt;string_0&gt;/);
  assert.doesNotMatch(out.join(""), /<string_0>/);
  assert.equal(model.rowCount, 101);
  assert.equal(model.pageSize, 100);
  assert.equal(model.rowAt(100)?.cells[3]?.html, "&lt;string_100&gt;");
  assert.equal(model.sortValueAt(100, 3), "<string_100>");
});

void test("legacy CodeView names remain accessible beyond a page and across directory generations", () => {
  const { pe, entry } = subject();
  entry.legacyCodeView.directories[0]!.subsections.push({ type: 0x12a, module: 0xffff, offset: 0, size: 0,
    data: { kind: "symbols", records: Array.from({ length: 101 }, (_, index) => ({ type: 0x203, name: `name${index}` })) } });
  entry.legacyCodeView.directories.push({ flags: 0, subsections: [] });
  const out: string[] = [];
  renderLegacyCodeView(entry, 0, out);
  const model = getLegacyCodeViewTableModel(pe, "pe-debug-entry-0-legacy-symbols")!;

  assert.equal(model.pageSize, 100);
  assert.equal(model.rowCount, 103);
  assert.equal(model.rowAt(102)?.cells[3]?.html, "name100");
  assert.match(out.join(""), /incremental-link records/);
});

void test("legacy CodeView omits absent and empty details and rejects unrelated table requests", () => {
  const { pe, entry } = subject();
  const out: string[] = [];
  renderLegacyCodeView(createDebugViewEntry(2, 0, 128), 0, out);

  assert.deepEqual(out, []);
  assert.equal(getLegacyCodeViewTableModel(pe, "other"), null);
  assert.equal(getLegacyCodeViewTableModel(pe, "pe-debug-entry-1-legacy-symbols"), null);
  assert.equal(getLegacyCodeViewTableModel(pe, "pe-debug-entry-0-legacy-other"), null);
  assert.equal(getLegacyCodeViewTableModel(createBasePe(), "pe-debug-entry-0-legacy-symbols"), null);
  entry.legacyCodeView.directories = [];
  renderLegacyCodeView(entry, 0, out);
  assert.doesNotMatch(out.join(""), /<table/);
});
