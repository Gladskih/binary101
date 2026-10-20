import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElfRelocations } from "../../../../renderers/elf/relocations.js";
import { relocationFixture, relocationTable } from "../../../fixtures/elf-relocations.js";

void test("renders human-readable aggregates without address or addend rows", () => {
  const { elf } = relocationFixture();
  elf.relocations = { tables: [relocationTable()], entries: [{
    tableIndex: 0, recordOffset: 64, offset: 8n, type: 8, symbolIndex: 0,
    symbol: null, addend: 16n,
    target: { sectionIndex: 1, sectionOffset: 8n, fileOffset: 520n }
  }], issues: [] };
  const out: string[] = [];
  renderElfRelocations(elf, out);
  assert.match(out.join(""), /Relocation type/);
  assert.match(out.join(""), /100\.0%/);
  assert.match(out.join(""), /Target section/);
  assert.doesNotMatch(out.join(""), /Virtual address|File offset|Section offset|Addend<|0x208/);
});

import { summarizeElfRelocations } from "../../../../renderers/elf/relocation-summary.js";
import type { ElfRelocation } from "../../../../analyzers/elf/relocation-types.js";

const summaryEntry = (fields: Partial<ElfRelocation> = {}): ElfRelocation => ({
  tableIndex: 0, recordOffset: 64, offset: 8n, type: 1, symbolIndex: 1,
  symbol: { name: "target", value: 4n, sectionIndex: 1 }, addend: -4n,
  target: { sectionIndex: 1, sectionOffset: 8n, fileOffset: 520n }, ...fields
});

void test("summary keeps formats, missing mappings, NONE and authenticated RELR distinct", () => {
  const { elf } = relocationFixture();
  elf.relocations = { tables: [relocationTable(), relocationTable({ encoding: "RELR" }),
    relocationTable({ encoding: "AUTH_RELR" })], entries: [
    summaryEntry(), summaryEntry(), summaryEntry({ type: 0, symbolIndex: 0, target: null }),
    summaryEntry({ tableIndex: 1, type: null, symbolIndex: null, addend: null, target: null }),
    summaryEntry({ tableIndex: 2, type: null, symbolIndex: null,
      target: { sectionIndex: null, sectionOffset: null, fileOffset: null } }),
    summaryEntry({ symbolIndex: 2, symbol: null,
      target: { sectionIndex: 99, sectionOffset: 0n, fileOffset: null } })
  ], issues: [] };
  const summary = summarizeElfRelocations(elf);
  assert.equal(summary.types[0]?.label, "R_X86_64_64");
  assert.equal(summary.types[0]?.count, 3);
  assert.ok(summary.types.some(row => row.label === "Authenticated relative (RELR)"));
  assert.ok(summary.targets.some(row => row.label === "Unmapped"));
  assert.ok(summary.targets.some(row => row.label === "No target (NONE)"));
  assert.ok(summary.targets.some(row => row.label === "PT_LOAD (section unavailable)"));
  assert.ok(summary.targets.some(row => row.label === "Section #99" && row.detail === "No file bytes"));
  assert.ok(summary.symbols.some(row => row.detail === "Unresolved symbol reference"));
});

void test("summary groups symbol identity instead of spelling and describes undefined/absolute/common symbols", () => {
  const { elf } = relocationFixture();
  elf.sections[2]!.type = 11; // SHT_DYNSYM; section and dynamic aliases identify the same symbols.
  elf.relocations = { tables: [relocationTable(), relocationTable({ symbolTableIndex: null })], entries: [
    summaryEntry({ symbol: { name: "", value: 0n, sectionIndex: 1 } }),
    summaryEntry({ tableIndex: 1, symbol: { name: "", value: 0n, sectionIndex: 1 } }),
    summaryEntry({ symbolIndex: 2, symbol: { name: "", value: 0n, sectionIndex: 0 } }),
    summaryEntry({ symbolIndex: 3, symbol: { name: "same", value: 0n, sectionIndex: 0xfff1 } }),
    summaryEntry({ symbolIndex: 4, symbol: { name: "same", value: 0n, sectionIndex: 0xfff2 } }),
    summaryEntry({ symbolIndex: 5, symbol: null }),
    summaryEntry({ type: 1, symbolIndex: 0, symbol: null })
  ], issues: [] };
  const summary = summarizeElfRelocations(elf);
  assert.equal(summary.symbols.length, 5);
  assert.equal(summary.symbols[0]?.label, ".debug_info");
  assert.equal(summary.symbols[0]?.count, 2);
  assert.ok(summary.symbols.some(row => row.detail === "Undefined; requires symbol lookup"));
  assert.ok(summary.symbols.some(row => row.detail === "Absolute definition"));
  assert.ok(summary.symbols.some(row => row.detail === "Common definition"));
  assert.ok(summary.symbols.some(row => row.label === "Unnamed symbol"));
  assert.equal(summary.types.length, 2); // Same type, with and without a symbol reference.
});

void test("absent summaries have no groups", () => {
  assert.deepEqual(summarizeElfRelocations(relocationFixture().elf),
    { types: [], formats: [], targets: [], symbols: [] });
});

void test("all distributions report exact counts, labels, storage and binding semantics", () => {
  const { elf } = relocationFixture();
  elf.relocations = { tables: [relocationTable(), relocationTable({ encoding: "RELR" }),
    relocationTable({ encoding: "AUTH_RELR" })], entries: [
    summaryEntry({ tableIndex: 2, type: null, symbolIndex: null, symbol: null, addend: null, target: null }),
    summaryEntry({ tableIndex: 1, type: null, symbolIndex: null, symbol: null, addend: null, target: null }),
    summaryEntry({ type: 0, symbolIndex: 0, symbol: null, target: null }),
    summaryEntry(), summaryEntry(), summaryEntry({ symbolIndex: 0, symbol: null })
  ], issues: [] };
  const summary = summarizeElfRelocations(elf);
  assert.deepEqual(summary.types, [
    { label: "R_X86_64_64", detail: "Symbol reference", count: 2 },
    { label: "Authenticated relative (RELR)", detail: "No symbol reference", count: 1 },
    { label: "R_X86_64_64", detail: "No symbol reference", count: 1 },
    { label: "R_X86_64_NONE", detail: "No symbol reference", count: 1 },
    { label: "Relative (RELR)", detail: "No symbol reference", count: 1 }
  ]);
  assert.deepEqual(summary.formats, [
    { label: "RELA", detail: "Explicit addend", count: 4 },
    { label: "AUTH_RELR", detail: "Addend in target bytes", count: 1 },
    { label: "RELR", detail: "Addend in target bytes", count: 1 }
  ]);
  assert.deepEqual(summary.targets, [
    { label: ".debug_info", detail: "File-backed", count: 3 },
    { label: "Unmapped", detail: "", count: 2 },
    { label: "No target (NONE)", detail: "", count: 1 }
  ]);
  assert.equal(summary.symbols[0]?.detail, "Defined in this file");
  assert.equal(summary.symbols[0]?.count, 2);
  assert.equal(summary.symbols[0]?.symbol, elf.relocations.entries[3]?.symbol);
});

void test("same-index symbols from distinct static tables never collapse", () => {
  const { elf } = relocationFixture();
  elf.relocations = { tables: [relocationTable({ symbolTableIndex: null }), relocationTable()], entries: [
    summaryEntry({ symbol: null }),
    summaryEntry({ tableIndex: 1, symbol: { name: "", value: 0n, sectionIndex: 0xfff2 } })
  ], issues: [] };
  const summary = summarizeElfRelocations(elf);
  assert.equal(summary.symbols.length, 2);
  assert.deepEqual(summary.symbols.map(row => [row.label, row.detail]),
    [["Unnamed symbol", "Common definition"], ["Unresolved symbol", "Unresolved symbol reference"]]);
});

void test("authenticated and plain relative relocations have independent totals", () => {
  const { elf } = relocationFixture();
  elf.relocations = { tables: [relocationTable({ encoding: "RELR" }), relocationTable({ encoding: "AUTH_RELR" })],
    entries: [summaryEntry({ type: null, symbolIndex: null }),
      summaryEntry({ tableIndex: 1, type: null, symbolIndex: null }),
      summaryEntry({ tableIndex: 1, type: null, symbolIndex: null })], issues: [] };
  assert.deepEqual(summarizeElfRelocations(elf).types, [
    { label: "Authenticated relative (RELR)", detail: "No symbol reference", count: 2 },
    { label: "Relative (RELR)", detail: "No symbol reference", count: 1 }
  ]);
});
