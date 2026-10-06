import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeElfSanitizers } from "../../../../analyzers/elf/sanitizers.js";
import { sanitizerElf, sanitizerStaticSymbol, sanitizerDynamicSymbol,
  sanitizerElfDefinitions, sanitizerElfSegmentDefinitions } from
  "../../../fixtures/sanitizer-metadata.js";

void test("recognizes undefined function references without needing section names", () => {
  const elf = sanitizerElf();
  elf.dynSymbols = { total: 2, issues: [], exportSymbols: [],
    importSymbols: ["__asan_init", "__asan_report_load4"].map(sanitizerDynamicSymbol) };
  assert.deepEqual(analyzeElfSanitizers(elf), ["__asan_init", "__asan_report_load4"].map(name =>
    ({ name, tool: "ASan", kind: "reference", source: "ELF dynamic symbols" })));
});

void test("recognizes function definitions in executable sections", () => {
  const elf = sanitizerElf();
  elf.symbolTables = [{ sectionIndex: 2, issues: [],
    entries: ["__asan_init", "__asan_report_load4"].map(sanitizerStaticSymbol) }];
  assert.deepEqual(analyzeElfSanitizers(elf), ["__asan_init", "__asan_report_load4"].map(name =>
    ({ name, tool: "ASan", kind: "definition", source: "ELF symbol table #2" })));
});

void test("ignores malformed symbol tables, non-functions and unmapped definitions", () => {
  const elf = sanitizerElf();
  elf.symbolTables = [{ sectionIndex: 2, issues: ["truncated"],
    entries: ["__asan_init", "__asan_report_load4"].map(sanitizerStaticSymbol) }];
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.symbolTables[0]!.issues = [];
  elf.symbolTables[0]!.entries[0]!.info = 17; // STT_OBJECT must not be treated as a function.
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.symbolTables[0]!.entries[0]!.info = 18;
  elf.symbolTables[0]!.entries[0]!.value = elf.sections[1]!.size;
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.symbolTables[0]!.entries[0]!.sectionIndex = 999;
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});

void test("does not combine definitions with undefined references", () => {
  const elf = sanitizerElf();
  elf.symbolTables = [{ sectionIndex: 2, issues: [], entries: [
    sanitizerStaticSymbol("__asan_init"),
    { ...sanitizerStaticSymbol("__asan_report_load4"), sectionIndex: 0, value: 0n }
  ] }];
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});

void test("accepts only the exact Go race build setting", () => {
  const elf = sanitizerElf();
  elf.goBuildInfo = { version: "go1.26", moduleInfo: "build\t-race=true\n" };
  assert.deepEqual(analyzeElfSanitizers(elf), [{ tool: "Go race detector",
    kind: "build-setting", source: "Go build information", name: "-race=true" }]);
  elf.goBuildInfo.moduleInfo = "build\t-race=false\nbuild\tldflags=-race=true\n";
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});

void test("empty metadata and section names alone do not identify sanitizers", () => {
  const elf = sanitizerElf();
  elf.sections[1]!.name = ".asan";
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});

void test("uses DT_NEEDED only when dynamic metadata parsed without warnings", () => {
  const elf = sanitizerElf();
  elf.dynamic = { needed: ["libasan.so.8"], soname: null, rpath: null, runpath: null,
    init: null, fini: null, preinitArray: null, initArray: null, finiArray: null,
    flags: null, flags1: null, issues: [] };
  assert.deepEqual(analyzeElfSanitizers(elf), [{ tool: "ASan", kind: "dependency",
    source: "ELF DT_NEEDED", name: "libasan.so.8" }]);
  elf.dynamic.issues.push("truncated string table");
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});

void test("rejects dynamic table warnings, data symbols and undefined local symbols", () => {
  const elf = sanitizerElf();
  elf.dynSymbols = { total: 2, issues: ["truncated"], exportSymbols: [],
    importSymbols: ["__asan_init", "__asan_report_load4"].map(sanitizerDynamicSymbol) };
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.dynSymbols.issues = [];
  elf.dynSymbols.importSymbols[0]!.type = 1;
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.dynSymbols.importSymbols[0]!.type = 0;
  elf.dynSymbols.importSymbols[0]!.bind = 0;
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.dynSymbols.importSymbols[0]!.bind = 2;
  assert.equal(analyzeElfSanitizers(elf).length, 2);
  elf.dynSymbols.importSymbols[0]!.name = "unrelated_function";
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});

void test("supports linked addresses while rejecting non-executable and truncated sections", () => {
  const elf = sanitizerElf();
  elf.header.type = 2; // ET_EXEC: st_value is a virtual address, not a section offset.
  elf.sections[1]!.addr = 4096n;
  elf.symbolTables = [{ sectionIndex: 2, issues: [], entries:
    ["__asan_init", "__asan_report_load4"].map(name =>
      ({ ...sanitizerStaticSymbol(name), value: 4097n })) }];
  assert.equal(analyzeElfSanitizers(elf).length, 2);
  elf.sections[1]!.flags = 0n;
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.sections[1]!.flags = 4n;
  elf.sections[1]!.offset = BigInt(elf.fileSize);
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.sections[1]!.offset = -1n;
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});

void test("validates file-backed PT_LOAD definitions when section headers are absent", () => {
  const elf = sanitizerElf();
  elf.sections = [];
  elf.header.type = 2;
  elf.programHeaders = [{ index: 0, type: 1, typeName: "PT_LOAD", offset: 0n,
    vaddr: 4096n, paddr: 4096n, filesz: 64n, memsz: 128n, flags: 1, flagNames: ["X"], align: 1n }];
  elf.dynSymbols = { total: 2, issues: [], importSymbols: [], exportSymbols:
    ["__asan_init", "__asan_report_load4"].map(name =>
      ({ ...sanitizerDynamicSymbol(name), shndx: 1, value: 4096n })) };
  assert.equal(analyzeElfSanitizers(elf).length, 2);
  elf.dynSymbols.exportSymbols[0]!.value = 4160n; // BSS-only bytes must not qualify.
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.dynSymbols.exportSymbols[0]!.value = 4096n;
  elf.dynSymbols.exportSymbols[0]!.shndx = 0xfff1; // SHN_ABS is not a mapped function definition.
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.dynSymbols.exportSymbols[0]!.shndx = 1;
  elf.programHeaders[0]!.flags = 0;
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.programHeaders[0]!.flags = 1;
  elf.programHeaders[0]!.offset = BigInt(elf.fileSize);
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});

void test("rejects reserved ELF bindings on apparent runtime definitions", () => {
  const elf = sanitizerElf();
  elf.symbolTables = [{ sectionIndex: 2, issues: [], entries:
    ["__asan_init", "__asan_report_load4"].map(name =>
      ({ ...sanitizerStaticSymbol(name), info: 0x32 })) }];
  // Binding 3 is reserved by the gABI; function names cannot make it trustworthy.
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});

void test("interprets ET_REL offsets even when the section has a nonzero address", () => {
  const elf = sanitizerElfDefinitions();
  elf.sections[1]!.addr = 4096n;
  elf.sections[1]!.offset = 0n;
  elf.sections[1]!.size = BigInt(elf.fileSize); // Exact end is inside the file.
  elf.symbolTables![0]!.entries[0]!.value = 0n; // First section byte is valid.
  assert.equal(analyzeElfSanitizers(elf).length, 2);
});

void test("accepts undefined static ABI references with their provenance", () => {
  const elf = sanitizerElfDefinitions();
  elf.symbolTables![0]!.entries.forEach(record => { record.sectionIndex = 0; });
  assert.deepEqual(analyzeElfSanitizers(elf), ["__asan_init", "__asan_report_load4"].map(name =>
    ({ name, tool: "ASan", kind: "reference", source: "ELF symbol table #2" })));
});

void test("rejects PROGBITS lookalikes and functions before a section's beginning", () => {
  const elf = sanitizerElfDefinitions();
  elf.sections[1]!.type = 8; // SHT_NOBITS has no file-backed code.
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.sections[1]!.type = 1;
  elf.symbolTables![0]!.entries[0]!.value = -1n;
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});

void test("does not use a segment to override present but invalid section metadata", () => {
  const elf = sanitizerElfSegmentDefinitions();
  elf.sections = sanitizerElf().sections;
  elf.sections[1]!.flags = 0n;
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});

void test("accepts an executable load segment among other segments at the exact file end", () => {
  const elf = sanitizerElfSegmentDefinitions();
  elf.programHeaders[0]!.offset = BigInt(elf.fileSize) - 64n;
  elf.programHeaders.push({ ...elf.programHeaders[0]!, flags: 0 });
  assert.equal(analyzeElfSanitizers(elf).length, 2);
});

void test("rejects reserved section indices at the boundary", () => {
  const elf = sanitizerElfSegmentDefinitions();
  elf.symbolTables![0]!.entries[0]!.sectionIndex = 0xff00; // SHN_LORESERVE, gABI 5.
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});

void test("rejects a non-load segment, a negative file offset and a function before the segment", () => {
  const elf = sanitizerElfSegmentDefinitions();
  elf.programHeaders[0]!.type = 2; // PT_DYNAMIC is not an executable mapping.
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.programHeaders[0]!.type = 1;
  elf.programHeaders[0]!.offset = -1n;
  assert.deepEqual(analyzeElfSanitizers(elf), []);
  elf.programHeaders[0]!.offset = 0n;
  elf.symbolTables![0]!.entries[0]!.value = 4095n;
  assert.deepEqual(analyzeElfSanitizers(elf), []);
});
