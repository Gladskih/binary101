import assert from "node:assert/strict";
import test from "node:test";
import { createReadyToRunTableModels, getReadyToRunTableModel, renderReadyToRunData } from
  "../../../../renderers/pe/ready-to-run-tables.js";
import { createReadyToRunRendererFixture } from "../../../helpers/ready-to-run-renderer-fixture.js";

void test("ReadyToRun exposes explained counts and section sizes instead of address and cell dumps", () => {
  const data = createReadyToRunRendererFixture();
  const models = createReadyToRunTableModels(data);
  const html = renderReadyToRunData(data);

  assert.deepEqual(models.map(model => model.id), ["pe-r2r-statistics", "pe-r2r-sections"]);
  assert.equal(models[1]!.rowCount, 7);
  assert.equal(models[1]!.tableClassName, "readyToRunTable");
  assert.deepEqual(models[1]!.rowAt(1)!.cells.map(cell => cell.html), ["ImportSections", "1", "20"]);
  assert.equal(models[1]!.rowAt(5)!.cells[0]!.html, "&lt;unknown>");
  assert.deepEqual(models[1]!.columns.map(column => column.label), ["Section", "Blocks", "Encoded bytes"]);
  assert.equal(models[1]!.columns[1]!.className, "peNumeric");
  assert.equal(models[1]!.columns[2]!.className, "peNumeric");
  assert.equal(models[1]!.rowAt(1)!.cells[0]!.className, "");
  assert.equal(models[1]!.rowAt(1)!.cells[2]!.className, "peNumeric");
  assert.equal(models[1]!.rowAt(-1), null);
  assert.equal(models[1]!.sortValueAt(-1, 0), "");
  assert.equal(models[1]!.sortValueAt(1, 0), "ImportSections");
  assert.equal(models[1]!.sortValueAt(1, 3), "");
  assert.match(html, /&lt;compiler>/);
  assert.match(html, /Hot\/cold code pairs/);
  assert.match(html, /Dependency cells contain data/);
  assert.doesNotMatch(html, /RVA|12 34 56 78|0x0000|Runtime function index|Stryker/);
  assert.match(html, /Compiler information retained in the ReadyToRun image/);
  assert.equal(getReadyToRunTableModel({ readyToRun: data }, "pe-r2r-statistics")?.rowCount, 8);
  assert.equal(getReadyToRunTableModel({ readyToRun: data }, "pe-r2r-1-cells"), null);
  assert.equal(getReadyToRunTableModel(null, "pe-r2r-statistics"), null);
  assert.equal(getReadyToRunTableModel({}, "pe-r2r-statistics"), null);
  assert.equal(getReadyToRunTableModel({ readyToRun: data }, "unrelated"), null);
});

void test("multiple text sections remain escaped without contaminating the summary", () => {
  const data = createReadyToRunRendererFixture();
  data.sections.push({ type: 100, rva: 0x900, size: 8, name: "Other compiler",
    decoded: { kind: "text", text: "<second>" } });

  const html = renderReadyToRunData(data);

  assert.match(html, /&lt;compiler>/);
  assert.match(html, /&lt;second>/);
  assert.doesNotMatch(html, /Stryker/);
});

void test("component summaries combine distinct payloads and count aliased sections once", () => {
  const data = createReadyToRunRendererFixture();
  const components = data.sections[3]!.decoded!;
  assert.equal(components.kind, "components");
  const entry = components.entries[0]!;
  entry.coreHeader = { flags: 0, sectionCount: 1, sections: [data.sections[2]!, {
    ...data.sections[2]!, rva: 0x800
  }] };
  components.entries.push({ ...entry });

  const models = createReadyToRunTableModels(data);

  const methodRow = models[0]!.rowAt(3)!;
  assert.equal(methodRow.cells[0]!.html, "Method-definition entry points");
  assert.equal(methodRow.cells[1]!.html, "4");
  assert.equal(models[1]!.rowAt(2)!.cells[1]!.html, "2");
  assert.match(renderReadyToRunData(data), /shared sections are counted once/);
});

void test("absent sections and compiler text do not produce empty raw-detail tables", () => {
  const data = { ...createReadyToRunRendererFixture(), sections: [] };

  assert.doesNotMatch(renderReadyToRunData(data), /<table|<dl>/);
  assert.match(renderReadyToRunData(data), /^<p class="smallNote">/);
  assert.match(renderReadyToRunData(data), /precompiled managed code/);
});
