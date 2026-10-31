import assert from "node:assert/strict";
import { test } from "node:test";
import { findRccArraySymbols } from "../../../../analyzers/embedded-resources/rcc-symbols.js";
import type { ResourceSymbol } from "../../../../analyzers/embedded-resources/types.js";

const symbols = (decoration: "c" | "coff" | "itanium", scope = "qrc.cpp"): ResourceSymbol[] =>
  ["struct", "name", "data"].map((kind, index) => {
    const name = `qt_resource_${kind}`;
    return { name: decoration === "c" ? name : decoration === "coff" ? `_${name}` : `_ZL${name.length}${name}`,
      offset: index * 16, size: 16, scope };
  });

for (const decoration of ["c", "coff", "itanium"] as const) {
  void test(`associates exact ${decoration} RCC symbols in the same translation unit`, () => {
    const values = symbols(decoration);
    assert.deepEqual(findRccArraySymbols(values), [{ tree: values[0], names: values[1], data: values[2] }]);
  });
  void test(`accepts GCC LTO suffixes on an unambiguous ${decoration} RCC triple`, () => {
    // GCC counts clones per assembler name, so these numbers need not agree.
    const values = symbols(decoration).map((value, index) =>
      ({ ...value, name: `${value.name}.lto_priv.${index}` }));
    assert.deepEqual(findRccArraySymbols(values), [{ tree: values[0], names: values[1], data: values[2] }]);
  });
}

void test("does not treat equal GCC clone counters as a resource-set identity", () => {
  const first = symbols("itanium").map(value => ({ ...value, name: `${value.name}.lto_priv.0` }));
  const second = symbols("itanium").map(value => ({ ...value, name: `${value.name}.lto_priv.1` }));
  assert.deepEqual(findRccArraySymbols([...first, ...second]), []);
  assert.deepEqual(findRccArraySymbols([...first, ...symbols("itanium")]), []);
  assert.equal(findRccArraySymbols([...first, ...second.map(value => ({ ...value, scope: "other.cpp" }))]).length, 2);
});

for (const suffix of [".lto_priv.", ".lto_priv.x", ".lto_priv.-1", ".lto_priv.1x",
  ".lto_priv.1.2", ".lto_priv.0.lto_priv.1"]) {
  void test(`rejects unsupported RCC symbol suffix ${suffix}`, () => {
    assert.deepEqual(findRccArraySymbols(symbols("itanium").map(value =>
      ({ ...value, name: value.name + suffix }))), []);
  });
}

void test("retains Itanium name-length validation after removing a GCC suffix", () => {
  assert.deepEqual(findRccArraySymbols(symbols("c").map(value =>
    ({ ...value, name: `_ZL1${value.name}.lto_priv.0` }))), []);
});

void test("rejects duplicate, unrelated, incomplete and incorrectly mangled array symbols", () => {
  const values = symbols("c");
  assert.deepEqual(findRccArraySymbols([...values, values[0]!]), []);
  assert.deepEqual(findRccArraySymbols(values.slice(1)), []);
  assert.deepEqual(findRccArraySymbols(values.map((value, index) => ({ ...value, scope: String(index) }))), []);
  assert.deepEqual(findRccArraySymbols(values.map(value => ({ ...value, name: `_ZL1${value.name}` }))), []);
  assert.deepEqual(findRccArraySymbols(values.map(value => ({ ...value, name: `${value.name}_fake` }))), []);
  assert.deepEqual(findRccArraySymbols(values.map(value => ({ ...value, name: `prefix${value.name}` }))), []);
  assert.deepEqual(findRccArraySymbols(symbols("coff").map(value =>
    ({ ...value, name: `prefix${value.name}` }))), []);
  assert.deepEqual(findRccArraySymbols(symbols("coff").map(value =>
    ({ ...value, name: `${value.name}suffix` }))), []);
  assert.deepEqual(findRccArraySymbols(symbols("itanium").map(value =>
    ({ ...value, name: `prefix${value.name}` }))), []);
  assert.deepEqual(findRccArraySymbols(symbols("itanium").map(value =>
    ({ ...value, name: `${value.name}suffix` }))), []);
  assert.deepEqual(findRccArraySymbols([...values, ...symbols("itanium", "other.cpp")]).length, 2);
});
