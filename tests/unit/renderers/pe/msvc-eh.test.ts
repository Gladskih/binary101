import assert from "node:assert/strict";
import { test } from "node:test";
import { getMsvcEhTableModel, renderMsvcEh } from "../../../../renderers/pe/msvc-eh.js";
import type { MsvcEhAnalysis } from "../../../../analyzers/pe/msvc-eh/types.js";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/core/parse-result.js";

const cppAnalysis = (): MsvcEhAnalysis => ({ warnings: [], records: [{ handlerRva: 0x1000,
  evidence: "verified", functionRvas: [0x1100], functionInfo: { version: 4, rva: 0x2000,
    ipStates: [{ ipRva: 0x1100, state: -1 }], unwindActions: [], tryBlocks: [{ tryLow: 0,
      tryHigh: 0, catchHigh: 1, handlers: [{ handlerRva: 0x1120, typeDescriptorRva: 0,
        continuationRvas: [0x1110] },
      { handlerRva: 0x1140, typeDescriptorRva: 0x2100, continuationRvas: [] }] }] } }] });

void test("EH renderer separates verified records and unresolved metadata diagnostics", () => {
  const out: string[] = [];
  renderMsvcEh({ warnings: ["bad <metadata>"], records: [{ scopeTableRva: 0x2010, unwindInfoRva: 0x2000,
    handlerRva: 0x1000, evidence: "ntdll!<name>", functionRvas: [0x1100],
    scopes: [{ beginRva: 0x1100, endRva: 0x1110, filterRva: 1, targetRva: 0x1114 }] }] }, out);
  const html = out.join("");
  assert.match(html, /Microsoft-compatible exception handling/);
  assert.match(html, /<th[^>]*>.*Format/);
  assert.match(html, /ntdll!&lt;name>/);
  assert.match(html, /bad &lt;metadata>/);
  assert.doesNotMatch(html, /No EH|EH absent/);
});

void test("EH catch details preserve encoded continuations and typed descriptor RVAs", () => {
  const out: string[] = [];
  renderMsvcEh(cppAnalysis(), out);
  const html = out.join("");
  assert.match(html, /Verified catch handlers/);
  assert.match(html, /catch \(\.\.\.\)/);
  assert.match(html, /0x2100/);
  assert.match(html, /0x1110/);
  assert.match(html, /Not encoded/);
  assert.match(html, /<th class="peNumeric">Handler RVA<\/th>/);
  assert.match(html, /<td class="peNumeric">0x1120<\/td>/);
});

void test("EH tables expose stable paging and sorting values without dropping rows", () => {
  const analysis = cppAnalysis();
  analysis.records = Array.from({ length: 51 }, () => analysis.records[0]!);
  const pe = { msvcEh: analysis } as PeWindowsParseResult;
  const table = getMsvcEhTableModel(pe, "pe-msvc-eh");
  assert.ok(table);
  assert.equal(table.rowCount, 51);
  assert.ok(table.rowAt(50));
  assert.equal(table.rowAt(51), null);
  assert.equal(table.sortValueAt(0, 0), "FH4");
  assert.equal(table.sortValueAt(0, 9), "");
  assert.equal(table.sortValueAt(51, 0), "");
  assert.equal(getMsvcEhTableModel(pe, "other"), null);
  assert.equal(getMsvcEhTableModel({} as PeWindowsParseResult, "pe-msvc-eh"), null);
  const out: string[] = [];
  renderMsvcEh(analysis, out);
  assert.match(out.join(""), /data-paged-sortable-table-root/);
});

void test("SafeSEH registration does not invent zero counts or scope-table addresses", () => {
  const out: string[] = [];
  renderMsvcEh({ warnings: [], records: [{ handlerRva: 0x1000, evidence: "SafeSEH",
    functionRvas: [], registration: "_except_handler4" }] }, out);
  const html = out.join("");
  assert.match(html, /Not decoded/);
  assert.match(html, /SafeSEH entry/);
  assert.match(html, /Unresolved/);
  assert.doesNotMatch(html, /Verified catch handlers/);
});

void test("unresolved metadata diagnostics have no fabricated object table", () => {
  const out: string[] = [];
  renderMsvcEh({ warnings: ["metadata unavailable"], records: [] }, out);
  assert.doesNotMatch(out.join(""), /<table/);
  assert.match(out.join(""), /0 verified record/);
});

void test("EH table cells, headings and sort values preserve the verified facts", () => {
  const table = getMsvcEhTableModel({ msvcEh: cppAnalysis() } as PeWindowsParseResult, "pe-msvc-eh");
  assert.ok(table);
  assert.equal(table.pageSize, 50);
  assert.deepEqual(table.columns.map(column => column.label), ["Format", "Function RVAs", "Handler RVA",
    "Metadata RVA", "Unwind states", "Try/scopes", "Catches", "Evidence"]);
  assert.deepEqual(table.rowAt(0)?.cells.map(cell => cell.html),
    ["FH4", "0x1100", "0x1000", "0x2000", "0", "1", "2", "verified"]);
  assert.deepEqual(Array.from({ length: 8 }, (_, column) => table.sortValueAt(0, column)),
    ["FH4", "0x1100", "0x1000", "0x2000", "0", "1", "2", "verified"]);
  assert.deepEqual(table.columns.slice(1, 7).map(column => column.className),
    Array.from({ length: 6 }, () => "peNumeric"));
  assert.deepEqual(table.rowAt(0)?.cells.slice(1, 7).map(cell => cell.className),
    Array.from({ length: 6 }, () => "peNumeric"));
  assert.match(table.rowAt(0)?.additionalRowsHtml ?? "", /<td colspan="8">/);
});

void test("SEH and SafeSEH table values retain their distinct meaning", () => {
  const analysis: MsvcEhAnalysis = { warnings: [], records: [
    { handlerRva: 0x1000, functionRvas: [0x1100], evidence: "scope evidence", scopeTableRva: 0x2010,
      scopes: [{ beginRva: 0x1100, endRva: 0x1110, filterRva: 1, targetRva: 0x1114 }] },
    { handlerRva: 0x1000, functionRvas: [], evidence: "registration evidence", registration: "_except_handler4" }
  ] };
  const table = getMsvcEhTableModel({ msvcEh: analysis } as PeWindowsParseResult, "pe-msvc-eh");
  assert.ok(table);
  assert.deepEqual(table.rowAt(0)?.cells.map(cell => cell.html),
    ["SEH", "0x1100", "0x1000", "0x2010", "Not encoded", "1", "Not encoded", "scope evidence"]);
  assert.deepEqual(table.rowAt(1)?.cells.map(cell => cell.html), ["_except_handler4", "Unresolved", "0x1000",
    "SafeSEH entry", "Not decoded", "Not decoded", "Not decoded", "registration evidence"]);
  assert.equal(table.rowAt(0)?.additionalRowsHtml, "");
  assert.equal(table.rowAt(1)?.additionalRowsHtml, "");
});

void test("EH text explains the limits of confirmation and labels all catch columns", () => {
  const out: string[] = [];
  renderMsvcEh(cppAnalysis(), out);
  const html = out.join("");
  assert.match(html, /1 verified record\(s\)/);
  assert.match(html, /Only validated metadata is listed/);
  assert.match(html, /Unlisted or unresolved records do not establish the absence/);
  assert.match(html, /do not establish.*or identify the compiler/);
  assert.match(html, /TypeDescriptor RVA/);
  assert.match(html, /Continuation RVAs/);
  assert.match(html, /<td class="peNumeric">catch \(\.\.\.\)<\/td>/);
  assert.match(html, /<td class="peNumeric">0x1110<\/td>/);
});
