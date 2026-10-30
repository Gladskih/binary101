import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWasm } from "../../../../analyzers/wasm/index.js";
import { wasmModule, wasmSection, wasmString } from "../../../fixtures/wasm-fixtures.js";

void test("checks each index space, duplicates, counts and start signature", async () => {
  const result = (await parseWasm(wasmModule(wasmSection(1, [1, 0x60, 1, 0x7f, 0]),
    wasmSection(3, [1, 0]), wasmSection(13, [1, 0, 2]),
    wasmSection(7, [2, ...wasmString("same"), 0, 2, ...wasmString("same"), 0, 0]),
    wasmSection(8, [0]), wasmSection(9, [1, 0, 0x41, 0, 0x0b, 1, 2]),
    wasmSection(12, [2]), wasmSection(11, [1, 0, 0x41, 0, 0x0b, 0]),
    wasmSection(0, [...wasmString("name"), ...wasmSection(1, [1, 2, ...wasmString("outside")])]))))!;
  const issues = result.issues.join(" ");
  assert.match(issues, /Tag type.*outside/);
  assert.match(issues, /Export same.*outside/);
  assert.match(issues, /Duplicate export name/);
  assert.match(issues, /Function\/code count mismatch/);
  assert.match(issues, /Data count mismatch/);
  assert.match(issues, /Data memory.*outside/);
  assert.match(issues, /Element table.*outside/);
  assert.match(issues, /Element function.*outside/);
  assert.match(issues, /Function name.*outside/);
  assert.match(issues, /Start function must/);
});

void test("resolves imported start functions and warns about out-of-range indices", async () => {
  const valid = (await parseWasm(wasmModule(wasmSection(1, [1, 0x60, 0, 0]),
    wasmSection(2, [1, ...wasmString("env"), ...wasmString("start"), 0, 0]), wasmSection(8, [0]))))!;
  assert.deepEqual(valid.issues, []);
  const invalid = (await parseWasm(wasmModule(wasmSection(3, [1, 9]), wasmSection(8, [3]))))!;
  assert.match(invalid.issues.join(" "), /Type reference.*outside/);
  assert.match(invalid.issues.join(" "), /Start function.*outside/);
});

void test("checks imported tag type indices and start result signatures", async () => {
  const tags = (await parseWasm(wasmModule(wasmSection(1, [1, 0x60, 0, 0]),
    wasmSection(2, [1, ...wasmString("env"), ...wasmString("tag"), 4, 0, 3]))))!;
  assert.match(tags.issues.join(" "), /Type reference: index 3 is outside 1 entries/);
  const start = (await parseWasm(wasmModule(wasmSection(1, [1, 0x60, 0, 1, 0x7f]),
    wasmSection(3, [1, 0]), wasmSection(8, [0]), wasmSection(10, [1, 4, 0, 0x41, 42, 0x0b]))))!;
  assert.match(start.issues.join(" "), /Start function must have no parameters or results/);
});
