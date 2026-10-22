import assert from "node:assert/strict";
import { test } from "node:test";
import { buildLegacyCodeViewTables } from "../../../../renderers/pe/legacy-codeview-tables.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";

void test("CodeView stored strings remain separate from type names and distinguish virtual methods", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x121, module: 7, offset: 0, size: 0,
    data: { kind: "types", records: [{ type: 0x1515, strings: ["file.pdb"] },
      { type: 0x1601, strings: ["function"] }, { type: 0x1602, strings: ["method"] },
      { type: 0x1605, strings: ["", "<identifier>"] },
      { type: 0x151d, strings: ["table", "virtual1", "virtual2"] }] } });
  const tables = buildLegacyCodeViewTables(info);

  assert.deepEqual(tables.find(table => table.key === "typeStrings"), {
    key: "typeStrings", title: "Stored type and ID strings",
    columns: ["Directory", "Module", "Record kind", "Text"], rows: [
      ["1", "7", "Type server PDB path", "file.pdb"], ["1", "7", "Function ID", "function"],
      ["1", "7", "Member function ID", "method"], ["1", "7", "String ID", "(empty)"],
      ["1", "7", "String ID", "<identifier>"], ["1", "7", "Virtual table name", "table"],
      ["1", "7", "Virtual method name", "virtual1"], ["1", "7", "Virtual method name", "virtual2"]
    ]
  });
  assert.equal(tables.find(table => table.key === "types")?.rows.length, 2);
});

void test("CodeView stored strings accumulate across subsections and directory generations", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x121, module: 7, offset: 0, size: 0,
    data: { kind: "types", records: [{ type: 0x1605, strings: ["first"] }] } });
  info.directories.push({ flags: 0, subsections: [{ type: 0x12b, module: 0xffff, offset: 0, size: 0,
    data: { kind: "types", records: [{ type: 0x1605, strings: ["second"] }] } }] });
  const tables = buildLegacyCodeViewTables(info).filter(table => table.key === "typeStrings");

  assert.equal(tables.length, 1);
  assert.deepEqual(tables[0]!.rows,
    [["1", "7", "String ID", "first"], ["2", "65535", "String ID", "second"]]);
});

void test("CodeView tables retain readable names and summarize symbol, line and frame arrays", () => {
  const tables = buildLegacyCodeViewTables(createLegacyCodeViewInfo());

  assert.deepEqual(tables.find(table => table.key === "module")?.rows,
    [["1", "1", "<module>.obj", "library.lib", "CV", "1", "24"]]);
  assert.deepEqual(tables.find(table => table.key === "symbols")?.rows,
    [["1", "1", "Public symbol", "<public>"], ["1", "1", "Public symbol", "second"]]);
  assert.deepEqual(tables.find(table => table.key === "types")?.rows, [["1", "1", "Structure", "Structure"],
    ["1", "1", "Structure (decorated)", ".?AU<Structure>@@"]]);
  assert.deepEqual(tables.find(table => table.key === "members")?.rows,
    [["1", "1", "Data member", "<field>"], ["1", "1", "Enumerator", "first"], ["1", "1", "Enumerator", "(unnamed)"]]);
  assert.ok(tables.find(table => table.key === "records")?.rows.some(row => row[2] === "Type members" && row[4] === "2"));
  assert.deepEqual(tables.find(table => table.key === "source")?.rows, [["1", "1", "source.c", "1", "3", "2"]]);
  assert.deepEqual(tables.find(table => table.key === "frameMap")?.rows, [["1", "1", "3", "2"]]);
  assert.deepEqual(tables.find(table => table.key === "files")?.rows,
    [["1", "1", "source.c", "1"], ["1", "1", "unreferenced.c", "0"]]);
  assert.deepEqual(tables.find(table => table.key === "segmentMap")?.rows,
    [["1", "1", "1", ".text", "CODE", "24", "read, write, execute, 32-bit, selector"]]);
  assert.ok(tables.find(table => table.key === "records")?.rows.some(row => row.includes("Scope end")));
});

void test("CodeView table inventory includes unknown and malformed subsections without empty details", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections = [{ type: 0x999, module: 1, offset: 0, size: 8 },
    { type: 0x999, module: 2, offset: 8, size: 4 }];
  const tables = buildLegacyCodeViewTables(info);

  assert.equal(tables.length, 1);
  assert.deepEqual(tables[0]?.rows, [["1", "Unknown subsection 0x999", "2", "12", "0 / 2"]]);
  assert.deepEqual(buildLegacyCodeViewTables({ signature: "NB09", directories: [] }), []);
});

void test("CodeView missing name references stay explicit and unused segment access bits remain meaningful", () => {
  const info = createLegacyCodeViewInfo();
  const sections = info.directories[0]!.subsections;
  const module = sections[0]!.data;
  const segments = sections[6]!.data;
  assert.ok(module?.kind === "module");
  assert.ok(segments?.kind === "segmentMap");
  module.library = 0;
  segments.segments[0]!.flags = 0x1200;
  segments.segments[0]!.className = 0xffff;
  sections.splice(5, 1);
  const tables = buildLegacyCodeViewTables(info);

  assert.equal(tables.find(table => table.key === "module")?.rows[0]?.[3], "(none)");
  assert.deepEqual(tables.find(table => table.key === "segmentMap")?.rows,
    [["1", "1", "1", "(unnamed)", "(unnamed)", "24", "absolute, group"]]);
});

void test("CodeView module inventory distinguishes missing libraries and zero access flags", () => {
  const info = createLegacyCodeViewInfo();
  const sections = info.directories[0]!.subsections;
  const segments = sections[6]!.data;
  assert.ok(segments?.kind === "segmentMap");
  segments.segments[0]!.flags = 0;
  sections.splice(1, 1);
  const tables = buildLegacyCodeViewTables(info);

  assert.equal(tables.find(table => table.key === "module")?.rows[0]?.[3], "#1");
  assert.equal(tables.find(table => table.key === "segmentMap")?.rows[0]?.[6], "No access flags");
});
