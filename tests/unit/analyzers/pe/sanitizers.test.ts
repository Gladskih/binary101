import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeSanitizers } from "../../../../analyzers/pe/sanitizers.js";
import { parsePe, isPeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import { createSanitizerPeFile } from "../../../fixtures/sanitizer-pe-file.js";
import { sanitizerPe, sanitizerImport, sanitizerCoffDebug, sanitizerExports } from
  "../../../fixtures/sanitizer-metadata.js";

void test("reports PE runtime DLL dependencies and imported ABI symbols separately", () => {
  const pe = sanitizerPe();
  pe.imports.entries = [sanitizerImport("clang_rt.asan_dynamic-x86_64.dll",
    ["__asan_init", "__asan_report_load4"])];
  assert.deepEqual(analyzePeSanitizers(pe), [
    { tool: "ASan", kind: "dependency", source: "PE import DLL",
      name: "clang_rt.asan_dynamic-x86_64.dll" },
    ...["__asan_init", "__asan_report_load4"].map(name => ({ tool: "ASan", kind: "reference",
      source: "PE imports: clang_rt.asan_dynamic-x86_64.dll", name }))
  ]);
});

void test("does not infer instrumentation from malformed imports or bound names", () => {
  const pe = sanitizerPe();
  pe.imports.entries = [sanitizerImport("clang_rt.asan_dynamic-x86_64.dll",
    ["__asan_init", "__asan_report_load4"])];
  pe.imports.warning = "truncated";
  assert.deepEqual(analyzePeSanitizers(pe), []);
});

void test("normalizes only the additional C underscore on i386", () => {
  const pe = sanitizerPe();
  pe.imports.entries = [sanitizerImport("runtime.dll", ["___asan_init", "___asan_report_load4"])];
  assert.equal(analyzePeSanitizers(pe).length, 2);
  pe.coff.Machine = 0x8664; // IMAGE_FILE_MACHINE_AMD64 (PE specification).
  assert.deepEqual(analyzePeSanitizers(pe), []);
});

void test("empty PE metadata does not identify sanitizers", () => {
  assert.deepEqual(analyzePeSanitizers(sanitizerPe()), []);
});

void test("reports delayed imports while ignoring ordinals and unnamed entries", () => {
  const pe = sanitizerPe();
  pe.delayImports = { entries: [{ name: "clang_rt.asan_dynamic-x86_64.dll",
    Attributes: 1, ModuleHandleRVA: 0, ImportAddressTableRVA: 0, ImportNameTableRVA: 0,
    BoundImportAddressTableRVA: 0, UnloadInformationTableRVA: 0, TimeDateStamp: 0,
    functions: [{ ordinal: 1 }, {}, { name: "__asan_init" }, { name: "__asan_report_load4" }] }] };
  assert.deepEqual(analyzePeSanitizers(pe), [
    { tool: "ASan", kind: "dependency", source: "PE delay-load DLL",
      name: "clang_rt.asan_dynamic-x86_64.dll" },
    ...["__asan_init", "__asan_report_load4"].map(name => ({ tool: "ASan", kind: "reference",
      source: "PE delay imports: clang_rt.asan_dynamic-x86_64.dll", name }))
  ]);
  pe.delayImports.warning = "truncated";
  assert.deepEqual(analyzePeSanitizers(pe), []);
});

void test("ignores unterminated and missing import lookup tables", () => {
  const pe = sanitizerPe();
  pe.imports.entries = [sanitizerImport("custom.dll", ["__asan_init", "__asan_report_load4"])];
  pe.imports.entries[0]!.thunkTableTerminated = false;
  assert.deepEqual(analyzePeSanitizers(pe), []);
  pe.imports.entries[0]!.thunkTableTerminated = true;
  pe.imports.entries[0]!.lookupSource = "missing";
  assert.deepEqual(analyzePeSanitizers(pe), []);
  pe.imports.entries[0]!.lookupSource = "iat-fallback";
  pe.imports.entries[0]!.functions.push({ ordinal: 1 }, {});
  assert.equal(analyzePeSanitizers(pe).length, 2);
});

void test("preserves the actual decorated spelling of i386 evidence", () => {
  const pe = sanitizerPe();
  pe.imports.entries = [sanitizerImport("custom.dll", ["___asan_init", "___asan_report_load4"])];
  assert.deepEqual(analyzePeSanitizers(pe).map(row => row.name),
    ["___asan_init", "___asan_report_load4"]);
});

void test("recognizes mapped exports without claiming that the runtime is active", () => {
  const pe = sanitizerPe();
  pe.exports = sanitizerExports();
  assert.deepEqual(analyzePeSanitizers(pe), ["__asan_init", "__asan_report_load4"].map(name =>
    ({ name, tool: "ASan", kind: "definition", source: "PE exports" })));
  pe.exports.issues.push("truncated");
  assert.deepEqual(analyzePeSanitizers(pe), []);
});

for (const rva of [0, -1, 4160, Number.MAX_SAFE_INTEGER, Infinity, NaN, 4096.5]) {
  void test(`rejects unmapped or invalid export RVA ${rva}`, () => {
    const pe = sanitizerPe();
    pe.exports = sanitizerExports();
    pe.exports.entries[0]!.rva = rva;
    assert.deepEqual(analyzePeSanitizers(pe), []);
  });
}

void test("rejects forwarded exports and non-executable sections", () => {
  const pe = sanitizerPe();
  pe.exports = sanitizerExports();
  pe.exports.entries[0]!.forwarder = "other.__asan_init";
  assert.deepEqual(analyzePeSanitizers(pe), []);
  delete pe.exports.entries[0]!.forwarder;
  pe.sections[0]!.characteristics = 0;
  assert.deepEqual(analyzePeSanitizers(pe), []);
});

void test("recognizes executable COFF function definitions from both debug sources", () => {
  const pe = sanitizerPe();
  pe.coffDebug = sanitizerCoffDebug();
  assert.deepEqual(analyzePeSanitizers(pe).map(row => row.source),
    ["PE COFF symbols", "PE COFF symbols"]);
  pe.coffDebug.warnings = ["invalid string table"];
  assert.deepEqual(analyzePeSanitizers(pe), []);
  pe.coffDebug.warnings = [];
  pe.debug = { entry: null, entries: [{ coff: pe.coffDebug }] as
    NonNullable<NonNullable<typeof pe.debug>["entries"]> };
  delete pe.coffDebug;
  assert.deepEqual(analyzePeSanitizers(pe).map(row => row.source),
    ["PE debug COFF symbols", "PE debug COFF symbols"]);
});

void test("does not treat COFF data, unresolved names or out-of-section values as functions", () => {
  const pe = sanitizerPe();
  pe.coffDebug = sanitizerCoffDebug();
  pe.coffDebug.symbols[0]!.type = 0;
  assert.deepEqual(analyzePeSanitizers(pe), []);
  pe.coffDebug.symbols[0]!.type = 0x20;
  pe.coffDebug.symbols[0]!.nameSource = "unresolved";
  assert.deepEqual(analyzePeSanitizers(pe), []);
  pe.coffDebug.symbols[0]!.nameSource = "short";
  pe.coffDebug.symbols[0]!.value = 64;
  assert.deepEqual(analyzePeSanitizers(pe), []);
  pe.coffDebug.symbols[0]!.value = -1;
  assert.deepEqual(analyzePeSanitizers(pe), []);
  pe.coffDebug.symbols[0]!.sectionNumber = 0;
  assert.deepEqual(analyzePeSanitizers(pe), []);
  pe.coffDebug.symbols[0]!.name = "__asan_unknown";
  assert.deepEqual(analyzePeSanitizers(pe), []);
});

void test("uses race-only Go entry points and ignores race0.go stubs", () => {
  const pe = sanitizerPe();
  pe.goRuntime = { layout: "go1.20+", pointerSize: 8, pcHeaderAddress: 1n, moduleDataAddress: 1n,
    fileCount: 1, textRange: { start: 4096n, end: 4160n }, functions:
    ["runtime.raceread", "runtime.racewrite", "main.main"].map((name, index) =>
      ({ name, start: 4096n + BigInt(index), end: 4097n + BigInt(index) })) };
  assert.deepEqual(analyzePeSanitizers(pe), ["runtime.raceread", "runtime.racewrite"].map(name =>
    ({ tool: "Go race detector", kind: "definition", source: "Validated Go function metadata", name })));
  pe.goRuntime.functions[0]!.name = "runtime.raceinit";
  assert.deepEqual(analyzePeSanitizers(pe), []);
  pe.goRuntime.functions[1]!.name = "runtime.racefini";
  assert.deepEqual(analyzePeSanitizers(pe), []);
  pe.goRuntime.functions[0]!.name = "runtime.raceread";
  assert.deepEqual(analyzePeSanitizers(pe), []);
});

void test("does not treat a COFF FILE storage-class record as a runtime function", () => {
  const pe = sanitizerPe();
  pe.coffDebug = sanitizerCoffDebug();
  pe.coffDebug.symbols[0]!.storageClass = 103; // IMAGE_SYM_CLASS_FILE (PE/COFF spec).
  assert.deepEqual(analyzePeSanitizers(pe), []);
});

void test("accepts executable exports among other sections", () => {
  const pe = sanitizerPe();
  pe.exports = sanitizerExports();
  pe.sections.push({ ...pe.sections[0]!, characteristics: 0 });
  assert.equal(analyzePeSanitizers(pe).length, 2);
  pe.rvaToOff = () => null;
  assert.deepEqual(analyzePeSanitizers(pe), []);
});

for (const rva of [0, 4095, 4160]) {
  void test(`requires executable section bounds even if RVA ${rva} maps elsewhere`, () => {
    const pe = sanitizerPe();
    pe.exports = sanitizerExports();
    pe.rvaToOff = () => 512; // A mapper alone cannot establish executable code.
    pe.exports.entries[0]!.rva = rva;
    assert.deepEqual(analyzePeSanitizers(pe), []);
  });
}

void test("does not treat RVA zero as a function even in a malformed section starting at zero", () => {
  const pe = sanitizerPe();
  pe.sections[0]!.virtualAddress = 0;
  pe.exports = sanitizerExports();
  pe.exports.entries[0]!.rva = 0;
  pe.exports.entries[1]!.rva = 1;
  pe.rvaToOff = () => 512;
  assert.deepEqual(analyzePeSanitizers(pe), []);
});

void test("accepts static COFF functions alongside external functions", () => {
  const pe = sanitizerPe();
  pe.coffDebug = sanitizerCoffDebug();
  pe.coffDebug.symbols[0]!.storageClass = 3; // IMAGE_SYM_CLASS_STATIC (PE/COFF spec).
  assert.equal(analyzePeSanitizers(pe).length, 2);
});

void test("recognizes import evidence through the real PE parser", async () => {
  const pe = await parsePe(new File([createSanitizerPeFile()], "asan.exe"));
  assert.ok(pe && isPeWindowsParseResult(pe));
  assert.deepEqual(analyzePeSanitizers(pe), [
    { tool: "ASan", kind: "dependency", source: "PE import DLL",
      name: "clang_rt.asan_dynamic-i386.dll" },
    ...["__asan_init", "__asan_report_load4"].map(name => ({ tool: "ASan", kind: "reference",
      source: "PE imports: clang_rt.asan_dynamic-i386.dll", name }))
  ]);
});
