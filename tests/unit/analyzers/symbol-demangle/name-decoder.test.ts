import assert from "node:assert/strict";
import { test } from "node:test";
import { createSymbolNameDecoder } from "../../../../analyzers/symbol-demangle/name-decoder.js";

void test("shared symbol routing keeps grammar identities and data evidence separate", async () => {
  const decode = createSymbolNameDecoder(assert.fail);

  assert.deepEqual(await decode("_Z1fi"),
    { text: "f(int)", language: "Itanium C++", symbolKind: undefined });
  assert.deepEqual(await decode("_Z5value"),
    { text: "value", language: "Itanium C++", symbolKind: "ItaniumData" });
  assert.deepEqual(await decode("_RC1a"),
    { text: "a", language: "Rust v0", symbolKind: undefined });
  assert.deepEqual(await decode("_D3foo3barf"),
    { text: "float foo.bar", language: "D", symbolKind: "DlangData" });
  assert.equal(await decode("_Zbroken"), null);
  assert.equal(await decode("_Rbroken"), null);
  assert.equal(await decode("_Dbroken"), null);
});

void test("ordinary names do not initialize any WASM", async () => {
  const decode = createSymbolNameDecoder(assert.fail, assert.fail, assert.fail, assert.fail);

  assert.equal(await decode(undefined), null);
  assert.equal(await decode(""), null);
  assert.equal(await decode("main"), null);
});
