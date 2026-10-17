import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCoffSymbols } from "../../../../analyzers/coff/symbols.js";
import { createCoffSymbolNameDecoder, getCoffSymbolDisplayName } from
  "../../../../analyzers/coff/symbol-names.js";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { parsePe, isPeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import { createCoffSymbolTableModel } from "../../../../renderers/coff/debug.js";
import { createCoffLanguageSymbolTable, createPeCoffLanguageFile } from
  "../../../fixtures/coff-language-symbol.js";

for (const [name, text] of [["_RNvC1a4main", "a::main"], ["_D3foo3barf", "float foo.bar"]]) {
  void test(`PE COFF symbol tables display ${name} with stable raw sorting`, async () => {
    const pe = await parsePe(new File([createPeCoffLanguageFile(name!)], "languages.exe"));

    assert.ok(pe && isPeWindowsParseResult(pe) && pe.coffDebug);
    const symbol = pe.coffDebug.symbols[0]!;
    assert.equal(symbol.name, name);
    assert.equal(getCoffSymbolDisplayName(symbol), text);
    const model = createCoffSymbolTableModel(pe.coffDebug, "languages");
    assert.ok(model.rowAt(0)!.cells[1]!.html.includes(text!));
    assert.ok(model.rowAt(0)!.cells[1]!.html.includes(name!));
    assert.equal(model.sortValueAt!(0, 1), name);
  });
}

void test("a truncated COFF name that happens to form valid Rust remains raw", async () => {
  const bytes = createCoffLanguageSymbolTable("_RNvC1a4main", "truncated");
  const warnings: string[] = [];

  const parsed = await parseCoffSymbols(createFileRangeReader(new File([bytes], "truncated"),
    0, bytes.length), 0, 1, message => warnings.push(message));

  assert.equal(parsed.symbols[0]!.name, "_RNvC1a4main");
  assert.equal(getCoffSymbolDisplayName(parsed.symbols[0]!), "_RNvC1a4main");
  assert.ok(warnings.some(message => message.includes("not NUL-terminated")));
  assert.equal(getCoffSymbolDisplayName({ name: "raw" }), "raw");
});

void test("COFF decoding forwards initialization diagnostics and retains the raw name", async () => {
  const warnings: string[] = [];
  const decode = createCoffSymbolNameDecoder(message => warnings.push(message), report => async () => {
    report("offline");
    return null;
  });
  const symbol = { name: "_RC1a" };

  await decode(symbol);

  assert.deepEqual(warnings, ["COFF symbol demangling unavailable: offline"]);
  assert.equal(getCoffSymbolDisplayName(symbol), "_RC1a");
});
