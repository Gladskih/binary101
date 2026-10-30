import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWasm } from "../../../../analyzers/wasm/index.js";
import { wasmModule, wasmSection, wasmString } from "../../../fixtures/wasm-fixtures.js";

const imported = (descriptor: number[]): number[] =>
  [...wasmString("env"), ...wasmString("item"), ...descriptor];

void test("parses each external kind and exception tags", async () => {
  const result = (await parseWasm(wasmModule(wasmSection(1, [1, 0x60, 0, 0]),
    wasmSection(2, [5, ...imported([0, 0]), ...imported([1, 0x70, 0, 0]),
      ...imported([2, 0, 1]), ...imported([3, 0x7f, 0]), ...imported([4, 0, 0])]),
    wasmSection(13, [1, 0, 0]),
    wasmSection(7, [5, ...wasmString("function"), 0, 0, ...wasmString("table"), 1, 0,
      ...wasmString("memory"), 2, 0, ...wasmString("global"), 3, 0, ...wasmString("tag"), 4, 0]),
    wasmSection(12, [0]))))!;
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.imports.map(row => row.descriptor.kind),
    ["function", "table", "memory", "global", "tag"]);
  assert.deepEqual(result.tags, [0]);
  assert.equal(result.dataCount, 0);
});

void test("warns for unmodeled GC types and invalid external kinds", async () => {
  assert.match((await parseWasm(wasmModule(wasmSection(1, [1, 0x4e, 0]))))!.issues.join(" "),
    /Unsupported recursive\/GC/);
  assert.match((await parseWasm(wasmModule(wasmSection(2, [1, ...imported([9])]))))!.issues.join(" "),
    /Unsupported import kind/);
  assert.match((await parseWasm(wasmModule(wasmSection(7, [1, ...wasmString("bad"), 9, 0]))))!
    .issues.join(" "), /Unsupported export kind/);
});

void test("retains valid entries before a malformed declaration", async () => {
  const result = (await parseWasm(wasmModule(wasmSection(1, [2, 0x60, 0, 0, 0xff]))))!;
  assert.deepEqual(result.types, [{ params: [], results: [] }]);
  assert.equal(result.sections[0]?.status, "partial");
});
