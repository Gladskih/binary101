import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { parseCoffObject } from "../../analyzers/coff/index.js";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";
import { readLegacyCodeViewModuleTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { buildCodeViewBuildTables } from "../../renderers/pe/codeview-build-tables.js";
import { buildCodeViewDerivedTables } from "../../renderers/pe/codeview-derived-tables.js";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";
import { codeViewInfoWithTypes } from "../fixtures/pe-codeview-callables.js";
import { MockFile } from "../helpers/mock-file.js";

const oracleIndex = (block: string, field: string): number => {
  const value = new RegExp(`^ {4}${field}:.*\\(0x([0-9A-F]+)\\)$`, "m").exec(block);
  assert.ok(value);
  return Number.parseInt(value[1]!, 16);
};

void test("MSVC build arguments and type source locations agree with unchanged LLVM", async () => {
  const object = resolve("scan-results/pe-debug-native/CompositeLinks.obj");
  execFileSync("C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/cl.exe",
    ["/nologo", "/TP", "/Z7", "/Od", "/c", resolve("tests/external/pe-debug-native/CompositeTypes.cpp"), `/Fo${object}`]);
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--codeview", object]).toString("utf8");
  const bytes = await readFile(object);
  const coff = await parseCoffObject(new MockFile(bytes));
  const section = coff?.sections.find(value => value.name.value === ".debug$T");
  assert.ok(section);
  const warnings: string[] = [];
  const types = await readLegacyCodeViewModuleTypes(legacyReader(bytes.subarray(section.pointerToRawData,
    section.pointerToRawData + section.sizeOfRawData), warnings));
  const sources = [...oracle.matchAll(/^ {2}UdtSourceLine \(0x([0-9A-F]+)\) \{[^]*?^ {2}\}/gm)];
  assert.equal(sources.length, 4);
  assert.deepEqual(types.records.filter(record => record.shape?.kind === "sourceLine")
    .map(record => ({ index: record.index, shape: record.shape })), sources.map(block => ({
      index: Number.parseInt(block[1]!, 16), shape: { kind: "sourceLine", typeIndex: oracleIndex(block[0], "UDT"),
        source: oracleIndex(block[0], "SourceFile"), line: Number(/LineNumber: (\d+)/.exec(block[0])![1]) }
    })));
  const build = /^ {2}BuildInfo \(0x([0-9A-F]+)\) \{[^]*?^ {2}\}/m.exec(oracle);
  assert.ok(build);
  const argumentsList = [...build[0].matchAll(/^ {6}ArgType: (.*) \(0x([0-9A-F]+)\)$/gm)];
  assert.equal(argumentsList.length, 5);
  assert.deepEqual(types.records.find(record => record.type === 0x1603)?.shape,
    { kind: "buildInfo", indices: argumentsList.map(value => Number.parseInt(value[2]!, 16)) });
  assert.deepEqual(buildCodeViewBuildTables(codeViewInfoWithTypes(types.records))
    .find(table => table.key === "buildInfo")?.rows.map(row => row[4]), argumentsList.map(value => value[1]));
  assert.deepEqual(warnings, []);
});

void test("embedded DMD derived class references agree with unchanged Microsoft cvdump", async () => {
  const path = resolve("scan-results/pe-debug-native/Legacy-members.exe");
  const oracle = execFileSync(resolve("scan-results/pe-debug-native/cvdump.exe"), ["-t", path]).toString("utf8");
  const file = new MockFile(await readFile(path));
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const info = debug.entries.find(entry => entry.legacyCodeView)?.legacyCodeView;
  assert.ok(info);
  const records = info.directories.flatMap(directory => directory.subsections)
    .flatMap(section => section.data?.kind === "types" ? section.data.records : []);
  const expected = [...oracle.matchAll(/derived\[\d+\] = [^\r\n]*\(([0-9A-Fa-f]+)\)/g)]
    .map(match => Number.parseInt(match[1]!, 16));
  assert.deepEqual(expected, [7]); // Actual DMD uses T_NOTTRANS; do not invent a class name.
  assert.deepEqual(records.flatMap(record => record.shape?.kind === "derived" ? record.shape.indices : []), expected);
  assert.ok(buildCodeViewDerivedTables(info)[0]?.rows.some(row => row[3] === "not translated"));
});
