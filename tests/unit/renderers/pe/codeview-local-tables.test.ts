import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCodeViewLocalTables } from "../../../../renderers/pe/codeview-local-tables.js";
import { readLegacyCodeViewModuleSymbols } from "../../../../analyzers/pe/debug/legacy-codeview-symbols.js";
import { legacyReader } from "../../../fixtures/pe-legacy-codeview.js";
import { codeViewLocalModule, createPeWithCodeViewLocals } from "../../../fixtures/pe-codeview-locals-file.js";
import { parsePeHeaders } from "../../../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../../../analyzers/pe/debug/directory.js";
import type { LegacyCodeViewSymbols } from "../../../../analyzers/pe/debug/legacy-codeview-symbols.js";
import type { PeLegacyCodeViewInfo } from "../../../../analyzers/pe/debug/legacy-codeview.js";

const infoFor = (data: LegacyCodeViewSymbols): PeLegacyCodeViewInfo => ({ signature: "NB09",
  directories: [{ flags: 0, subsections: [{ type: 0x125, module: 7, offset: 8, size: 512, data }] }] });

void test("CodeView frame/local tables retain names, exact placements and per-description range totals", async () => {
  const warnings: string[] = [];
  const data = await readLegacyCodeViewModuleSymbols(legacyReader(codeViewLocalModule(), warnings));
  const tables = buildCodeViewLocalTables(infoFor(data), 0x8664);
  const frames = tables.find(table => table.key === "compilerFrames")!;
  const locals = tables.find(table => table.key === "localVariables")!;

  assert.deepEqual(warnings, []);
  assert.deepEqual(frames.rows[0]?.slice(0, 6), ["<inspect>&amp;", "64", "8", "16", "RSP", "RSP"]);
  assert.deepEqual(locals.rows[0], ["seed", "<inspect>&amp;", "#4097", "RCX", "parameter", "1", "64", "0",
    "validated procedure scope", "1", "7"]);
  assert.deepEqual(locals.rows[1]?.slice(3, 8), ["frame base - 8", "none", "1", "32", "8"]);
  assert.deepEqual(locals.rows[2]?.slice(3, 8), ["not stored", "optimized out", "0", "0", "0"]);
  assert.deepEqual(locals.rows[3]?.slice(3, 8), ["frame base - 16", "none", "1", "0 + full scope", "0"]);
  assert.ok(tables[0]!.rows.some(row => row[0] === "Optimized-out variables" && row[1] === "1"));
});

void test("CodeView local metadata survives PE debug-directory integration", async () => {
  const file = createPeWithCodeViewLocals();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const tables = buildCodeViewLocalTables(debug.entries[0]!.legacyCodeView!, core.coff.Machine);

  assert.equal(debug.warning, null);
  assert.equal(tables.find(table => table.key === "localVariables")?.rows.length, 4);
});

void test("CodeView local tables keep orphan and damaged records visible without inventing procedure names", () => {
  const data: LegacyCodeViewSymbols = { kind: "symbols", records: [
    { type: 0x113e, local: { typeIndex: 1 } },
    { type: 0x1142, localRange: { location: { kind: "frameRelative", offset: 0 }, gaps: [] } }
  ] };
  const tables = buildCodeViewLocalTables(infoFor(data));
  const locals = tables.find(table => table.key === "localVariables")!;

  assert.equal(locals.rows[0]?.[0], "(name unavailable)");
  assert.equal(locals.rows[0]?.[1], "(scope unresolved)");
  assert.match(locals.rows[0]?.[8] ?? "", /offsets/);
  assert.ok(tables[0]!.rows.some(row => row[0] === "Location ranges without a consecutive local"));
  assert.deepEqual(buildCodeViewLocalTables(infoFor({ kind: "symbols", encoding: "hll", records: data.records })), []);
  assert.deepEqual(buildCodeViewLocalTables({ signature: "NB09", directories: [] }), []);
});

void test("Range placements describe spilled subfields and unknown attributes semantically", async () => {
  const data = await readLegacyCodeViewModuleSymbols(legacyReader(codeViewLocalModule()));
  const range = data.records.find(record => record.type === 0x1142)!.localRange!;
  range.location = { kind: "registerRelative", register: 335, offset: -8 };
  range.attributes = 0x41;
  range.parentOffset = 9;
  const table = buildCodeViewLocalTables(infoFor(data), 0x8664).find(value => value.key === "localVariables")!;

  assert.equal(table.rows[1]?.[3], "RSP - 8; spilled member; parent offset 4; parent offset 9");
  range.location = { kind: "register", register: 328 };
  range.attributes = 3;
  assert.match(buildCodeViewLocalTables(infoFor(data), 0x8664).find(value => value.key === "localVariables")!
    .rows[1]![3]!, /may have no name; unknown attributes 0x2/);
});

void test("Incomplete or invalid ranges never turn into invented live-byte totals", async () => {
  const data = await readLegacyCodeViewModuleSymbols(legacyReader(codeViewLocalModule()));
  const range = data.records.find(record => record.type === 0x1142)!.localRange!;
  range.gaps = [{ offset: 24, length: 16 }];
  assert.equal(buildCodeViewLocalTables(infoFor(data)).find(value => value.key === "localVariables")!.rows[1]?.[7],
    "invalid gap list");
  range.gaps = [{ offset: 4, length: 8 }, { offset: 0, length: 1 }];
  assert.equal(buildCodeViewLocalTables(infoFor(data)).find(value => value.key === "localVariables")!.rows[1]?.[7],
    "invalid gap list");
  delete range.range;
  const row = buildCodeViewLocalTables(infoFor(data)).find(value => value.key === "localVariables")!.rows[1]!;
  assert.deepEqual(row.slice(5, 8), ["1", "unavailable", "invalid gap list"]);
  range.range = { offset: 16, section: 1, length: 0xf000 };
  assert.equal(buildCodeViewLocalTables(infoFor(data)).find(value => value.key === "localVariables")!.rows[1]?.[6],
    "unavailable");
});

void test("Legacy fixed locations and empty handler fields retain their own meanings", async () => {
  const data = await readLegacyCodeViewModuleSymbols(legacyReader(codeViewLocalModule()));
  const frame = data.records.find(record => record.frame)!.frame!;
  frame.handler = { section: 0, offset: 0 };
  frame.paddingBytes = 0;
  const variable = data.records.find(record => record.name === "gone")!;
  variable.local!.location = { kind: "frameRelative", offset: 0 };
  const tables = buildCodeViewLocalTables(infoFor(data));

  assert.equal(tables.find(value => value.key === "localVariables")?.rows[2]?.[3], "frame base + 0");
  assert.doesNotMatch(tables.find(value => value.key === "compilerFrames")!.rows[0]![6]!, /handler|padding begins/);
});
