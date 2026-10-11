"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import type { Demangler, DemangleWithTextResult } from "llvm-msvc-demangle";
import { loadMsvcDemangler } from "../../../../../analyzers/pe/msvc-demangle/load.node.js";
import {
  createPeExportNameDecoder, getPeExportDisplayName
} from "../../../../../analyzers/pe/directories/export-names.js";

const stubDemangler = (result: DemangleWithTextResult): Demangler => ({
  demangle: () => result, demangleType: () => result,
  demangleWithText: () => result, demangleTypeWithText: () => result
});

void test("display names stay attached to individual aliases with identical source text", async () => {
  const names = ["?f@@YAHH@Z", "?f@@YAHH@Z"];

  await createPeExportNameDecoder([])(names, 0);

  assert.equal(getPeExportDisplayName(names, 0), "int __cdecl f(int)");
  assert.equal(getPeExportDisplayName(names, 1), "?f@@YAHH@Z");
});

void test("missing alias indexes do not initialize WASM or produce guessed text", async () => {
  let loads = 0;
  const decode = createPeExportNameDecoder([], () => {
    loads += 1;
    return loadMsvcDemangler();
  });

  await decode([], 0);
  await decode([], -1);

  assert.equal(loads, 0);
  assert.equal(getPeExportDisplayName([], 0), "");
});

for (const [name, text] of [
  ["?f@@YAHH@Z", "int __cdecl f(int)"],
  ["??0Widget@demo@@QEAA@XZ", "public: __cdecl demo::Widget::Widget(void)"],
  ["?value@demo@@3HA", "int demo::value"],
  ["??$square@H@demo@@YAHH@Z", "int __cdecl demo::square<int>(int)"]
]) {
  void test(`LLVM presents the export ${name} without changing its source`, async () => {
    const names = [name!];
    const issues: string[] = [];

    await createPeExportNameDecoder(issues)(names, 0);

    assert.equal(getPeExportDisplayName(names, 0), text);
    assert.deepEqual(names, [name]);
    assert.deepEqual(issues, []);
    assert.equal(getPeExportDisplayName([...names], 0), name);
  });
}

void test("ordinary, non-MSVC and oversized symbols do not initialize WASM", async () => {
  let loads = 0;
  const issues: string[] = [];
  const decode = createPeExportNameDecoder(issues, () => {
    loads += 1;
    return loadMsvcDemangler();
  });
  const names = ["", "PlainExport", "_stdcall@8", "_Z3foov", `?${"A".repeat(16 * 1024)}`];

  for (const [index] of names.entries()) await decode(names, index);

  assert.equal(loads, 0);
  assert.deepEqual(issues, []);
  assert.equal(getPeExportDisplayName(names, 4), names[4]);
});

void test("a name at the presentation length boundary still reaches LLVM", async () => {
  let loads = 0;
  const decode = createPeExportNameDecoder([], () => {
    loads += 1;
    return loadMsvcDemangler();
  });
  const name = `?${"A".repeat(16 * 1024 - 1)}`;

  await decode([name], 0);

  assert.equal(loads, 1);
});

void test("LLVM is initialized once and repeated export aliases are parsed once", async () => {
  const demangler = await loadMsvcDemangler();
  let loads = 0;
  let calls = 0;
  const decode = createPeExportNameDecoder([], async () => {
    loads += 1;
    return { ...demangler, demangleWithText(name) {
      calls += 1;
      return demangler.demangleWithText(name);
    } };
  });
  const first = ["?f@@YAHH@Z", "?broken", "?f@@YAHH@Ztail"];
  const second = [...first];

  for (const [index] of first.entries()) await decode(first, index);
  for (const [index] of second.entries()) await decode(second, index);

  assert.equal(loads, 1);
  assert.equal(calls, 3);
  assert.equal(getPeExportDisplayName(second, 0), "int __cdecl f(int)");
  assert.equal(getPeExportDisplayName(second, 1), "?broken");
  assert.equal(getPeExportDisplayName(second, 2), "?f@@YAHH@Ztail");
});

for (const status of ["error", "limit"] as const) {
  void test(`LLVM ${status} preserves exports, warns once, and stops using that instance`, async () => {
    const issues: string[] = [];
    let loads = 0;
    const decode = createPeExportNameDecoder(issues, async () => {
      loads += 1;
      return stubDemangler({ status, consumed: 0, ast: null, text: null,
        warnings: ["could not finish", "instance quarantined"] });
    });
    const names = ["?f@@YAHH@Z", "?value@demo@@3HA"];

    await decode(names, 0);
    await decode(names, 1);

    assert.deepEqual(issues, [
      "Export name demangling unavailable: could not finish; instance quarantined"
    ]);
    assert.equal(loads, 1);
    assert.equal(getPeExportDisplayName(names, 0), names[0]);
    assert.equal(getPeExportDisplayName(names, 1), names[1]);
  });
}

void test("an LLVM failure without diagnostics includes its status", async () => {
  const issues: string[] = [];
  const decode = createPeExportNameDecoder(issues, async () => stubDemangler({
    status: "error", consumed: 0, ast: null, text: null, warnings: []
  }));

  await decode(["?f@@YAHH@Z"], 0);

  assert.deepEqual(issues, ["Export name demangling unavailable: error"]);
});

for (const failure of [new Error("WASM unavailable"), "WASM unavailable"]) {
  void test("loader failures remain visible and another file can recover", async () => {
    const issues: string[] = [];
    const decode = createPeExportNameDecoder(issues, () => Promise.reject(failure));
    const names = ["?f@@YAHH@Z"];

    await decode(names, 0);
    await createPeExportNameDecoder([])(names, 0);

    assert.deepEqual(issues, ["Export name demangling unavailable: WASM unavailable"]);
    assert.equal(getPeExportDisplayName(names, 0), "int __cdecl f(int)");
  });
}
