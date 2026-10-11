"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import {
  createImportFunctionNameDecoder, getImportFunctionDisplayName
} from "../../../../../analyzers/pe/imports/function-name.js";
import { readImportThunkFunctions32, readImportThunkFunctions64 } from
  "../../../../../analyzers/pe/imports/import-thunk-table.js";
import { readDelayThunkFunctions32, readDelayThunkFunctions64 } from
  "../../../../../analyzers/pe/imports/delay-thunk-table.js";
import {
  createImportNameThunksFile, createPeImportNamesFile
} from "../../../../fixtures/pe-import-names-file.js";

void test("PE imports decode Itanium names while preserving their linker identity", async () => {
  const decode = createImportFunctionNameDecoder(assert.fail);
  const symbol = { name: "_Z1fi" };

  await decode(symbol);

  assert.equal(getImportFunctionDisplayName(symbol), "f(int)");
  assert.deepEqual(symbol, { name: "_Z1fi" });
});

void test("failed Itanium loading warns once while MSVC imports still decode", async () => {
  const warnings: string[] = [];
  const decode = createImportFunctionNameDecoder(message => warnings.push(message), undefined,
    () => Promise.reject(new Error("offline")));
  const itanium = { name: "_Z1fi" };
  const microsoft = { name: "?f@@YAHH@Z" };

  await decode(itanium);
  await decode({ name: "_Z1fv" });
  await decode(microsoft);

  assert.equal(getImportFunctionDisplayName(itanium), "_Z1fi");
  assert.equal(getImportFunctionDisplayName(microsoft), "int __cdecl f(int)");
  assert.deepEqual(warnings, ["Import name demangling unavailable: offline"]);
});

void test("import presentation leaves exact raw names, metadata and ordinal identity intact", async () => {
  const warnings: string[] = [];
  const decode = createImportFunctionNameDecoder(message => warnings.push(message));
  const functions = [{ hint: 9, name: "?f@@YAHH@Z" }, { name: "?f@@YAHH@Ztail" },
    { ordinal: 7 }, { name: "_stdcall@8" }, { name: "?broken" }];

  for (const fn of functions) await decode(fn);

  assert.equal(getImportFunctionDisplayName(functions[0]!), "int __cdecl f(int)");
  assert.equal(getImportFunctionDisplayName({ ...functions[0] }), "?f@@YAHH@Z");
  assert.equal(getImportFunctionDisplayName(functions[1]!), "?f@@YAHH@Ztail");
  assert.equal(getImportFunctionDisplayName(functions[2]!), "");
  assert.equal(getImportFunctionDisplayName(functions[3]!), "_stdcall@8");
  assert.equal(getImportFunctionDisplayName(functions[4]!), "?broken");
  assert.deepEqual(functions[0], { hint: 9, name: "?f@@YAHH@Z" });
  assert.deepEqual(warnings, []);
});

void test("ordinary WinAPI, UCRT and ordinal imports never initialize the demangler", async () => {
  let loads = 0;
  const decode = createImportFunctionNameDecoder(assert.fail, () => {
    loads += 1;
    return Promise.reject(new Error("Unexpected WASM request"));
  });

  for (const fn of [{ name: "Sleep" }, { name: "printf" }, { name: "_printf" }, { ordinal: 7 }]) {
    await decode(fn);
  }

  assert.equal(loads, 0);
});

void test("full PE parsing demangles eager and delayed imports without altering linker names", async () => {
  const pe = await parsePe(new File([createPeImportNamesFile()], "imports.exe"));

  assert.ok(pe && isPeWindowsParseResult(pe));
  for (const functions of [pe.imports.entries[0]?.functions, pe.delayImports?.entries[0]?.functions]) {
    assert.ok(functions);
    assert.equal(functions[250]?.name, "??$square@H@demo@@YAHH@Z");
    assert.equal(getImportFunctionDisplayName(functions[250]!), "int __cdecl demo::square<int>(int)");
  }
});

void test("import loader failures warn once, preserve raw names and allow another file to recover", async () => {
  const warnings: string[] = [];
  const decode = createImportFunctionNameDecoder(message => warnings.push(message),
    () => Promise.reject(new Error("WASM unavailable")));
  const first = { name: "?f@@YAHH@Z" };
  const second = { name: "?value@demo@@3HA" };

  await decode(first);
  await decode(second);

  assert.deepEqual(warnings, ["Import name demangling unavailable: WASM unavailable"]);
  assert.equal(getImportFunctionDisplayName(first), first.name);
  assert.equal(getImportFunctionDisplayName(second), second.name);
  await createImportFunctionNameDecoder(message => warnings.push(message))(first);
  assert.equal(getImportFunctionDisplayName(first), "int __cdecl f(int)");
});

for (const width of [4, 8]) {
  for (const ending of ["terminated", "truncated"] as const) {
    void test(`${width * 8}-bit import readers only decode ${ending} names when NUL is present`, async () => {
      const name = "?f@@YAHH@Z";
      const bytes = createImportNameThunksFile(width, ending);
      const reader = createFileRangeReader(new File([bytes], "thunks"), 0, bytes.length);
      const warnings = new Set<string>();
      const mapped = (rva: number): number | null => rva < bytes.length ? rva : null;
      const ordinary = width === 4 ? readImportThunkFunctions32 : readImportThunkFunctions64;
      const delayed = width === 4 ? readDelayThunkFunctions32 : readDelayThunkFunctions64;

      const eager = await ordinary(reader, bytes.length, mapped, 8, message => warnings.add(message),
        (offset): offset is number => offset != null, () => 2);
      const delay = await delayed(reader, mapped, 8, warnings, () => 2);

      for (const parsed of [eager, delay]) {
        assert.equal(parsed.functions[0]?.name, name);
        assert.equal(getImportFunctionDisplayName(parsed.functions[0]!),
          ending === "terminated" ? "int __cdecl f(int)" : name);
      }
      assert.equal(warnings.size, ending === "terminated" ? 0 : 2);
    });
  }
}
