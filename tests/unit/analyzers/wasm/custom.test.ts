import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWasm } from "../../../../analyzers/wasm/index.js";
import { wasmModule, wasmSection, wasmString } from "../../../fixtures/wasm-fixtures.js";

void test("keeps unknown custom sections opaque and skips unknown name subsections", async () => {
  const result = (await parseWasm(wasmModule(wasmSection(0, [...wasmString("vendor"), 0xff]),
    wasmSection(0, [...wasmString("name"), ...wasmSection(2, [0]), ...wasmSection(0, wasmString("module"))]),
    wasmSection(0, [...wasmString("target_features"), 2, 0x2d, ...wasmString("simd128"), 0,
      ...wasmString("unknown")]))))!;
  assert.equal(result.sections[0]?.status, "opaque");
  assert.equal(result.sections[0]?.customName, "vendor");
  assert.equal(result.moduleName, "module");
  assert.equal(result.features[0]?.prefix, "-");
  assert.match(result.issues.join(" "), /subsections.*order/);
  assert.match(result.issues.join(" "), /Unknown target feature prefix/);
});

void test("rejects name-map duplicate indices and truncated custom payloads", async () => {
  assert.match((await parseWasm(wasmModule(wasmSection(0, [...wasmString("name"),
    ...wasmSection(1, [2, 0, ...wasmString("one"), 0, ...wasmString("two")])]))))!
    .issues.join(" "), /strictly increasing/);
  assert.match((await parseWasm(wasmModule(wasmSection(0, [...wasmString("producers"), 1, 10, 0]))))!
    .issues.join(" "), /Truncated/);
});

void test("warns for duplicate name subsections and trailing subsection bytes", async () => {
  const duplicate = (await parseWasm(wasmModule(wasmSection(0, [...wasmString("name"),
    ...wasmSection(0, wasmString("first")), ...wasmSection(0, wasmString("second"))]))))!;
  assert.match(duplicate.issues.join(" "), /Name subsections are duplicated or out of order/);
  const trailing = (await parseWasm(wasmModule(wasmSection(0, [...wasmString("name"),
    ...wasmSection(0, [...wasmString("module"), 0])]))))!;
  assert.match(trailing.issues.join(" "), /trailing byte/);
  assert.equal(trailing.moduleName, "module");
});

void test("accepts both standard feature policies without warnings", async () => {
  const result = (await parseWasm(wasmModule(wasmSection(0, [...wasmString("target_features"),
    2, 0x2b, ...wasmString("simd128"), 0x2d, ...wasmString("atomics")]))))!;
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.features, [{ prefix: "+", name: "simd128" }, { prefix: "-", name: "atomics" }]);
});
