import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeWithTd32Semantics } from "../../../../fixtures/pe-td32-semantics.js";
import { parsePeHeaders } from "../../../../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";
import { buildTd32Tables } from "../../../../../renderers/pe/td32-tables.js";

void test("TD32 semantic fields survive PE debug dispatch and populate named properties plus summaries", async () => {
  const file = createPeWithTd32Semantics();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const tables = buildTd32Tables(debug.entries[0]!.td32!);

  assert.equal(debug.warning, null);
  assert.equal(tables.find(table => table.key === "procedures")?.rows[0]?.[1], "64");
  assert.deepEqual(tables.find(table => table.key === "typeaggregates")?.rows[0]?.slice(0, 4),
    ["Widget", "Structure", "24", "2"]);
  assert.ok(tables.find(table => table.key === "typestatistics")?.rows.some(row => row.includes("Const")));
  assert.equal(tables.find(table => table.key === "typequalifiers"), undefined);
  assert.ok(tables.some(table => table.key !== "names" && table.rows.some(row => row.includes("count"))));
  assert.ok(tables.some(table => table.key !== "names" && table.rows.some(row => row.includes("read"))));
});
