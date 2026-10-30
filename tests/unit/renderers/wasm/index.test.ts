import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWasm } from "../../../../analyzers/wasm/index.js";
import { renderWasm } from "../../../../renderers/wasm/index.js";
import { createWasmFile, wasmModule, wasmSection, wasmString } from "../../../fixtures/wasm-fixtures.js";

void test("renders deep analysis tables and instructions", async () => {
  const html = renderWasm((await parseWasm(createWasmFile()))!);
  assert.match(html, /WebAssembly module/);
  assert.match(html, /analysis-demo/);
  assert.match(html, /i32.add/);
  assert.match(html, /initialize/);
  assert.match(html, /producers/);
  assert.match(html, /Instructions \(4\)/);
  assert.match(html, /not executed/);
  assert.doesNotMatch(html, /<h4>Issues/);
});

void test("escapes HTML in every untrusted string, including names and warnings", async () => {
  const result = (await parseWasm(wasmModule(wasmSection(0,
    [...wasmString("name"), ...wasmSection(0, wasmString('<img src=x onerror="alert(1)">'))]))))!;
  result.issues.push("<script>alert(1)</script>");
  const html = renderWasm(result);
  assert.match(html, /&lt;img/);
  assert.match(html, /&lt;script/);
  assert.doesNotMatch(html, /<script|<img/);
});

void test("renders truncated headers and empty modules", async () => {
  const result = (await parseWasm(wasmModule()))!;
  result.version = null;
  assert.match(renderWasm(result), /Unknown/);
  assert.match(renderWasm(result), /None/);
});

void test("preserves HTML entities in names and diagnostics as literal source text", async () => {
  const result = (await parseWasm(wasmModule()))!;
  result.moduleName = "&lt;module&gt;";
  result.issues.push("name=&amp;entry");
  const html = renderWasm(result);
  assert.match(html, /&amp;lt;module&amp;gt;/);
  assert.match(html, /name=&amp;amp;entry/);
});
