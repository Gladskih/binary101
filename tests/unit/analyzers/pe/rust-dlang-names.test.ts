import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import { createPeExportNameDecoder, getPeExportDisplayName, isPeExportData } from
  "../../../../analyzers/pe/directories/export-names.js";
import { getImportFunctionDisplayName } from "../../../../analyzers/pe/imports/function-name.js";
import { createPeImportNamesFile } from "../../../fixtures/pe-import-names-file.js";

for (const [name, text] of [["_RNvC1a4main", "a::main"], ["_D3foo3barf", "float foo.bar"],
  ["__RNvC1a4main", "a::main"], ["__D3foo3barf", "float foo.bar"]] as const) {
  void test(`PE eager and delay imports decode ${name} without altering identity`, async () => {
    const pe = await parsePe(new File([createPeImportNamesFile(name)], "languages.exe"));

    assert.ok(pe && isPeWindowsParseResult(pe));
    const eager = pe.imports.entries[0]!.functions[250]!;
    const delayed = pe.delayImports!.entries[0]!.functions[250]!;
    assert.equal(eager.name, name);
    assert.equal(delayed.name, name);
    assert.equal(getImportFunctionDisplayName(eager), text);
    assert.equal(getImportFunctionDisplayName(delayed), text);
  });
}

void test("PE exports decode Rust paths and D data without treating Rust paths as data", async () => {
  const rust = ["_RNvC1a4main"];
  const dlang = ["_D3foo3barf", "_D3foo3Bar6__vtblZ"];
  const unknown = ["_Dmain", "_D3foo3barZ", "_D3foo3barFiZi", "_Rbroken"];
  const decode = createPeExportNameDecoder([]);

  await decode(rust, 0);
  await decode(dlang, 0);
  await decode(dlang, 1);
  await decode(unknown, 0);
  await decode(unknown, 1);
  await decode(unknown, 2);
  await decode(unknown, 3);

  assert.equal(getPeExportDisplayName(rust, 0), "a::main");
  assert.equal(getPeExportDisplayName(dlang, 0), "float foo.bar");
  assert.equal(getPeExportDisplayName(dlang, 1), "vtable for foo.Bar");
  assert.equal(isPeExportData(rust), false);
  assert.equal(isPeExportData(unknown), false);
  assert.equal(isPeExportData(dlang), true);
  assert.equal(getPeExportDisplayName(unknown, 2), "_D3foo3barFiZi");
  assert.equal(getPeExportDisplayName(unknown, 3), "_Rbroken");
});
