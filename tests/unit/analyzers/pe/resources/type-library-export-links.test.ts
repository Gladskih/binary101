import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeTypeLibraryExports } from
  "../../../../../analyzers/pe/resources/type-library-export-links.js";
import { addTypeLibraryPreview } from
  "../../../../../analyzers/pe/resources/preview/type-library.js";
import type { PeResources } from "../../../../../analyzers/pe/resources/index.js";
import { createMsftLibrary } from "../../../../fixtures/type-library.js";

const resources = (): PeResources => ({ top: [], detail: [{ typeName: "TYPELIB", entries: [
  { id: 1, name: null, langs: [{ lang: 1033, dataRVA: 1, size: 1, codePage: 0,
    dataFileOffset: 0, reserved: 0,
    ...addTypeLibraryPreview(createMsftLibrary(), "TYPELIB", null)?.preview }] }
] }] });
const exports = () => ({ dllName: "module.dll", NumberOfFunctions: 2, issues: [], entries: [
  { ordinal: 1, rva: 4096, names: ["RunExport"] },
  { ordinal: 2, rva: 8192, names: ["Other"] }
] });
const moduleFunction = (data: PeResources) => {
  const type = data.detail[0]!.entries[0]!.langs[0]!.typeLibrary!.analysis!.types[0]!;
  // TYPEKIND 2 is TKIND_MODULE; only this kind provides DLL entries.
  // https://learn.microsoft.com/en-us/windows/win32/api/oaidl/ne-oaidl-typekind
  type.kind = 2;
  type.dll = "C:\\bin\\MODULE.dll";
  type.functions[0]!.entry = "RunExport";
  return type;
};

void test("links a type library module entry to an exact named PE export", () => {
  const data = resources();
  moduleFunction(data);
  const result = analyzeTypeLibraryExports(data, exports());
  assert.deepEqual(result.matches, [{ ordinal: 1, library: "Lib", module: "ITest",
    function: "Run", entry: "RunExport" }]);
  assert.deepEqual(result.warnings, []);
});

void test("links an ordinal entry without guessing from an interface method", () => {
  const data = resources();
  const type = moduleFunction(data);
  type.functions[0]!.entry = 2;
  const result = analyzeTypeLibraryExports(data, exports());
  assert.equal(result.matches[0]?.ordinal, 2);
  type.kind = 3;
  assert.deepEqual(analyzeTypeLibraryExports(data, exports()).matches, []);
});

void test("reports a missing explicit module export when the export table is complete", () => {
  const data = resources();
  moduleFunction(data).functions[0]!.entry = "Absent";
  const result = analyzeTypeLibraryExports(data, exports());
  assert.deepEqual(result.matches, []);
  assert.equal(result.warnings[0], "TYPELIB Lib module ITest function Run declares DLL entry " +
    "Absent, but module.dll has no matching export.");
});

void test("skips mismatched DLLs and incomplete export tables", () => {
  const data = resources();
  moduleFunction(data).dll = "external.dll";
  assert.deepEqual(analyzeTypeLibraryExports(data, exports()), { matches: [], warnings: [] });
  moduleFunction(data).functions[0]!.entry = "Absent";
  assert.deepEqual(analyzeTypeLibraryExports(data, { ...exports(), issues: ["truncated"] }).warnings,
    []);
  assert.deepEqual(analyzeTypeLibraryExports(data,
    { ...exports(), NumberOfFunctions: 3 }).warnings, []);
  assert.deepEqual(analyzeTypeLibraryExports(data, { ...exports(), dllName: "" }).warnings, []);
});

void test("ignores blank DLL entries and duplicate language views", () => {
  const data = resources();
  const type = moduleFunction(data);
  type.functions[0]!.entry = "";
  const blankNamedExport = exports();
  blankNamedExport.entries[0]!.names = [""];
  assert.deepEqual(analyzeTypeLibraryExports(data, blankNamedExport).matches, []);
  type.functions[0]!.entry = "RunExport";
  const language = data.detail[0]!.entries[0]!.langs[0]!;
  data.detail[0]!.entries[0]!.langs.push({ ...language, lang: 1041 });
  assert.equal(analyzeTypeLibraryExports(data, exports()).matches.length, 1);
});

void test("retains distinct module functions that point to one export", () => {
  const data = resources();
  const type = moduleFunction(data);
  type.functions.push({ ...type.functions[0]!, name: "OtherName" });
  assert.deepEqual(analyzeTypeLibraryExports(data, exports()).matches.map(match => match.function),
    ["Run", "OtherName"]);
});

void test("uses explicit fallbacks for unnamed libraries, modules, and functions", () => {
  const data = resources();
  const type = moduleFunction(data);
  data.detail[0]!.entries[0]!.langs[0]!.typeLibrary!.analysis!.name = null;
  data.detail[0]!.entries[0]!.name = "Named";
  type.name = null;
  type.functions[0]!.name = null;
  assert.deepEqual(analyzeTypeLibraryExports(data, exports()).matches[0],
    { ordinal: 1, library: "Named", module: "?", function: "?", entry: "RunExport" });
  type.functions[0]!.entry = "Absent";
  assert.match(analyzeTypeLibraryExports(data, exports()).warnings[0] ?? "",
    /TYPELIB Named module \? function \? declares DLL entry Absent/u);
  data.detail[0]!.entries[0]!.name = null;
  data.detail[0]!.entries[0]!.id = null;
  assert.equal(analyzeTypeLibraryExports(data, exports()).warnings[0]?.startsWith("TYPELIB ?"), true);
});

void test("does not treat a type library preview on another resource kind as TYPELIB", () => {
  const data = resources();
  moduleFunction(data);
  data.detail[0]!.typeName = "RCDATA";
  assert.deepEqual(analyzeTypeLibraryExports(data, exports()).matches, []);
});

void test("ignores libraries without a decoded module DLL entry", () => {
  const data = resources();
  assert.deepEqual(analyzeTypeLibraryExports(data, exports()), { matches: [], warnings: [] });
  moduleFunction(data).functions[0]!.entry = null;
  assert.deepEqual(analyzeTypeLibraryExports(data, exports()), { matches: [], warnings: [] });
  delete data.detail[0]!.entries[0]!.langs[0]!.typeLibrary!.analysis;
  assert.deepEqual(analyzeTypeLibraryExports(data, exports()), { matches: [], warnings: [] });
  assert.deepEqual(analyzeTypeLibraryExports(null, exports()), { matches: [], warnings: [] });
  assert.deepEqual(analyzeTypeLibraryExports(data, null), { matches: [], warnings: [] });
});
