import assert from "node:assert/strict";
import { test } from "node:test";
import { buildTd32SymbolTables } from "../../../../renderers/pe/td32-symbol-tables.js";
import type { PeTd32Info } from "../../../../analyzers/pe/debug/td32.js";

const info = (): PeTd32Info => ({ signature: "FB0A", directories: [{ flags: 0, subsections: [
  { type: 0x130, module: 0, offset: 0, size: 64, data: { kind: "names", names: ["worker", "value", "unit.pas"] } },
  { type: 0x125, module: 1, offset: 64, size: 128, data: { kind: "symbols", recordOffsets: [4, 48, 64, 80, 96], records: [
    { type: 0x205, nameIndex: 1, metadata: { codeLength: 64, location: { segment: 1, offset: 32 },
      debugRange: { start: 4, end: 60 }, scopeOffsets: { parent: 0, end: 96, next: 0 } } },
    { type: 0x200, nameIndex: 2, metadata: { frameOffset: -8, typeIndex: 0x1004 } },
    { type: 0x211, metadata: { rangeStart: 4, codeLength: 12, register: 17 } },
    { type: 0x24, metadata: { nameIndices: [3] } }, { type: 6 }] } }
] }] });

void test("TD32 procedure and variable tables lead with names and preserve stored placement semantics", () => {
  const tables = buildTd32SymbolTables(info());
  const procedures = tables.find(table => table.key === "procedures")!;
  const variables = tables.find(table => table.key === "symbolmetadata")!;

  assert.deepEqual(procedures.rows[0]?.slice(0, 4), ["worker", "64", "56", "segment 1, stored offset 32"]);
  assert.equal(variables.rows[0]?.[0], "value");
  assert.match(variables.rows[0]![3]!, /stored BP-relative offset -8/);
  assert.doesNotMatch(variables.rows[0]!.join(" "), /parameter|local stack/);
  assert.ok(tables.find(table => table.key === "imports")?.rows.some(row => row[0] === "unit.pas"));
});

void test("TD32 anonymous location records contribute useful totals without address lists", () => {
  const summary = buildTd32SymbolTables(info()).find(table => table.key === "semantics")!;

  assert.ok(summary.rows.some(row => row[0] === "Procedure code bytes (sum)" && row[1] === "64"));
  assert.ok(summary.rows.some(row => row[0] === "Optimized range bytes (sum)" && row[1] === "12"));
  assert.equal(summary.columns.includes("Address"), false);
});

void test("TD32 incomplete and malformed procedure descriptions keep explicit scope and debug status", () => {
  const subject = info();
  const data = subject.directories[0]!.subsections[1]!.data!;
  assert.ok(data.kind === "symbols");
  data.records[0]!.metadata!.debugRange = { start: 60, end: 70 };
  data.records[0]!.metadata!.scopeOffsets!.parent = 999;
  delete data.recordOffsets;
  const tables = buildTd32SymbolTables(subject);
  const procedures = tables.find(table => table.key === "procedures")!;

  assert.equal(procedures.rows[0]?.[2], "invalid debug span");
  assert.equal(procedures.rows[0]?.[4], "(unresolved parent)");
  assert.match(procedures.rows[0]![5]!, /offsets are unavailable/);
});

void test("TD32 semantic tables handle absent names and resolve valid parent symbols", () => {
  const subject = info();
  const data = subject.directories[0]!.subsections[1]!.data!;
  assert.ok(data.kind === "symbols");
  data.records.push({ type: 0x204, nameIndex: 2, metadata: { codeLength: 8, location: { segment: 1, offset: 96 },
    scopeOffsets: { parent: 4, end: 144, next: 0 } } }, { type: 6 },
  { type: 0x212, metadata: { rangeStart: 52, codeLength: 4 } }, { type: 0x213, metadata: { flags: 7 } },
  { type: 0x20, nameIndex: 1, metadata: { location: { segment: 1, offset: 32 } } }, { type: 6 });
  data.recordOffsets!.push(100, 144, 148, 160, 166, 190);
  const tables = buildTd32SymbolTables(subject);
  subject.directories[0]!.subsections.shift();
  const noNames = buildTd32SymbolTables(subject);

  assert.equal(tables.find(table => table.key === "procedures")!.rows[1]?.[4], "worker");
  assert.equal(tables.find(table => table.key === "procedures")!.rows[1]?.[2], "not stored");
  assert.equal(noNames.find(table => table.key === "procedures")!.rows[0]?.[0], "(unresolved name #1)");
  assert.equal(tables.find(table => table.key === "symbolmetadata")!.rows.at(-1)?.[2], "not stored");
  assert.ok(tables.find(table => table.key === "semantics")!.rows.some(row => row[0] === "Epilogue bytes (sum)" && row[1] === "4"));
  assert.deepEqual(buildTd32SymbolTables({ signature: "FB09", directories: [] }), []);
});
