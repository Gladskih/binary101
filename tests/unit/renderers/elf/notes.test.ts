"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { createElfNotesTableModel, renderElfNotes } from "../../../../renderers/elf/notes.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { renderPagedSortableTable } from "../../../../renderers/paged-sortable-table.js";
import type { ElfNotesInfo } from "../../../../analyzers/elf/types.js";

function summaryNotes(values: Array<[string | null, string | null]>): ElfNotesInfo {
  return { issues: [], entries: values.map(([typeName, value]) => ({ source: "fixture",
    name: "GNU", type: 0, typeName, value, description: null, descSize: 0 })) };
}

void test("renderElfNotes renders GNU build-id", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const out: string[] = [];
  renderElfNotes(elf, out);
  const html = out.join("");
  assert.ok(html.includes("Notes"));
  assert.ok(html.includes("Build ID"));
  assert.ok(html.includes(expected.buildIdHex));
});

void test("notes remain accessible beyond the former display limit and escape control bytes", async () => {
  const elf = expectDefined(await parseElf(createElfMetadataFile().file));
  // The previous renderer discarded every note after entry 2000.
  elf.notes = { issues: [], entries: Array.from({ length: 2001 }, (_, index) => ({
    ...expectDefined(elf.notes?.entries[0]), name: `owner${index}\u0001`, value: "<payload>"
  })) };

  const out: string[] = [];
  renderElfNotes(elf, out);
  const model = expectDefined(getElfPagedTableModel(elf, "elf-notes"));
  const last = renderPagedSortableTable(model, {
    pageIndex: 20, sortColumnIndex: null, sortDirection: null
  });

  assert.match(out.join(""), /Showing 1-100 of 2001/);
  assert.match(last, /owner2000\\x01/);
  assert.match(last, /&lt;payload>/);
  assert.equal(model.rowAt(2001), null);
  assert.equal(model.sortValueAt(2001, 0), "");
});

void test("note model preserves unknown fields, escapes control ranges and rejects missing rows", () => {
  const model = createElfNotesTableModel({ issues: [], entries: [{ source: "source",
    name: "\u001f ~\u007f\u009f\u00a0", type: 255, typeName: null,
    description: null, value: null, descSize: 0 }] });
  assert.equal(model.rowCount, 1);
  assert.equal(model.id, "elf-notes");
  assert.equal(model.pageSize, 100);
  assert.deepEqual(model.columns.map(column => column.label),
    ["Source", "Owner / attribute", "Type", "Description", "Value", "Descriptor bytes"]);
  assert.equal(model.rowAt(0)?.cells[1]?.html, "\\x1f ~\\x7f\\x9f\u00a0");
  assert.equal(model.rowAt(0)?.cells[2]?.html, "0xff");
  assert.equal(model.rowAt(0)?.cells[3]?.html, "—");
  assert.equal(model.rowAt(0)?.cells[4]?.html, "—");
  assert.equal(model.rowAt(0)?.cells[5]?.html, "0");
  assert.equal(model.rowAt(0)?.cells[5]?.className, "peNumeric");
  assert.equal(model.rowAt(0)?.cells[0]?.className, "elfNote__value");
  assert.equal(model.columns[1]?.className, "elfNote__value");
  assert.equal(model.columns[5]?.className, "peNumeric elfNote__value");
  assert.equal(model.sortValueAt(0, 2), "0xff");
  assert.equal(model.sortValueAt(0, 99), "");
  assert.equal(model.rowAt(-1), null);
  assert.equal(model.rowAt(1), null);
  assert.equal(model.sortValueAt(-1, 0), "");
});

void test("renders ABI summaries, known note names and intentionally empty values", async () => {
  const elf = expectDefined(await parseElf(createElfMetadataFile().file));
  elf.notes = { issues: [], entries: [{ source: "source", name: "GNU", type: 1,
    typeName: "NT_GNU_ABI_TAG", description: "", value: "Linux <version>", descSize: 16 }] };
  const out: string[] = [];
  renderElfNotes(elf, out);
  assert.match(out.join(""), /<dt>ABI tag<\/dt><dd>Linux &lt;version><\/dd>/);
  assert.equal(createElfNotesTableModel(elf.notes).rowAt(0)?.cells[3]?.html, "");
  elf.notes.entries[0]!.value = "";
  assert.equal(createElfNotesTableModel(elf.notes).rowAt(0)?.cells[4]?.html, "");
});

void test("note summaries select the first decoded value of each matching type", async () => {
  const elf = expectDefined(await parseElf(createElfMetadataFile().file));
  elf.notes = summaryNotes([[null, "decoy"], ["NT_GNU_BUILD_ID", null],
    ["NT_GNU_ABI_TAG", null], ["NT_GNU_BUILD_ID", "<build>"], ["NT_GNU_ABI_TAG", "<abi>"]]);
  const out: string[] = [];
  renderElfNotes(elf, out);
  const summary = out.join("").match(/<dl>.*?<\/dl>/s)?.[0] ?? "";
  assert.match(summary, /<dt>Total notes<\/dt><dd>5<\/dd>/);
  assert.match(summary, /<dt>Build ID<\/dt><dd><span class="mono">&lt;build><\/span><\/dd>/);
  assert.match(summary, /<dt>ABI tag<\/dt><dd>&lt;abi><\/dd>/);
  assert.doesNotMatch(summary, /decoy/);
});

void test("note summaries distinguish absent values from empty decoded strings", async () => {
  const elf = expectDefined(await parseElf(createElfMetadataFile().file));
  const out: string[] = [];
  elf.notes = summaryNotes([["NT_GNU_BUILD_ID", null], ["NT_GNU_ABI_TAG", null]]);
  renderElfNotes(elf, out);
  assert.doesNotMatch(out.join("").match(/<dl>.*?<\/dl>/s)?.[0] ?? "", /Build ID|ABI tag/);
  out.length = 0;
  elf.notes = summaryNotes([["NT_GNU_BUILD_ID", ""], ["NT_GNU_ABI_TAG", ""]]);
  renderElfNotes(elf, out);
  assert.match(out.join(""), /<dt>Build ID<\/dt><dd><span class="mono"><\/span><\/dd>/);
  assert.match(out.join(""), /<dt>ABI tag<\/dt><dd><\/dd>/);
});

void test("empty note tables retain escaped warnings without fabricating rows", async () => {
  const elf = expectDefined(await parseElf(createElfMetadataFile().file));
  elf.notes = { entries: [], issues: ["<warning>"] };
  const out: string[] = [];
  renderElfNotes(elf, out);
  assert.match(out.join(""), /&lt;warning>/);
  assert.doesNotMatch(out.join(""), /<tbody><tr>/);
  out.length = 0;
  delete elf.notes;
  renderElfNotes(elf, out);
  assert.deepEqual(out, []);
});
