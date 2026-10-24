import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { parseCoffObject } from "../../analyzers/coff/index.js";
import { readLegacyCodeViewModuleTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";
import { buildCodeViewFunctionTables } from "../../renderers/pe/codeview-function-tables.js";
import { codeViewInfoWithTypes } from "../fixtures/pe-codeview-callables.js";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";
import { MockFile } from "../helpers/mock-file.js";

const llvmMethod = (block: string) => {
  const access = /^ {6}AccessSpecifier:.*\(0x([0-9A-F]+)\)/mi.exec(block);
  const property = /^ {6}MethodKind:.*\(0x([0-9A-F]+)\)/mi.exec(block);
  const options = /^ {6}MethodOptions \[ \(0x([0-9A-F]+)/mi.exec(block);
  const type = /^ {6}Type:.*\(0x([0-9A-F]+)\)/mi.exec(block);
  const offset = /^ {6}VFTableOffset: 0x([0-9A-F]+)/mi.exec(block);
  assert.ok(access && type);
  return { attributes: Number.parseInt(access[1]!, 16) | Number.parseInt(property?.[1] ?? "0", 16) << 2
    | Number.parseInt(options?.[1] ?? "0", 16), typeIndex: Number.parseInt(type[1]!, 16),
  ...(offset ? { vtableOffset: Number.parseInt(offset[1]!, 16) | 0 } : {}) };
};

void test("MSVC overloaded method attributes and targets match unchanged LLVM and retain readable names", async () => {
  const object = resolve("scan-results/pe-debug-native/CompositeMethods.obj");
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
  const blocks = [...oracle.matchAll(/^ {2}MethodOverloadList \(0x([0-9A-F]+)\) \{[^]*?^ {2}\}/gm)];
  assert.equal(blocks.length, 6);
  assert.deepEqual(types.records.filter(record => record.shape?.kind === "methods")
    .map(record => ({ index: record.index, shape: record.shape })), blocks.map(block => ({
      index: Number.parseInt(block[1]!, 16), shape: { kind: "methods", methods:
        [...block[0].matchAll(/^ {4}Method \[[^]*?^ {4}\]/gm)].map(method => llvmMethod(method[0])) }
    })));
  const rows = buildCodeViewFunctionTables(codeViewInfoWithTypes(types.records))[0]!.rows;
  assert.equal(rows.filter(row => row[2] === "Packet::read").length, 2);
  assert.ok(rows.some(row => row[2] === "Base::read" && /vtable offset: 8 bytes/.test(row[7]!)));
  const slots = types.records.flatMap(record => record.shape?.kind === "vtableShape" ? record.shape.slots : []);
  assert.ok(slots.length > 0);
  assert.ok(slots.every(slot => slot === 5)); // CV_VTS_near32 in the MSVC artifact, including odd shapes.
  assert.deepEqual(warnings, []);
});

void test("embedded DMD virtual table descriptors agree with unchanged Microsoft cvdump", async () => {
  const filePath = resolve("scan-results/pe-debug-native/Legacy-members.exe");
  const oracle = execFileSync(resolve("scan-results/pe-debug-native/cvdump.exe"), ["-t", filePath]).toString("utf8");
  const file = new MockFile(await readFile(filePath));
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const records = debug.entries.flatMap(entry => entry.legacyCodeView?.directories ?? [])
    .flatMap(directory => directory.subsections)
    .flatMap(section => section.data?.kind === "types" ? section.data.records : []);
  const blocks = oracle.split(/(?=^0x[0-9a-f]+ :)/m).filter(block => /^0x[^\r\n]*LF_VTSHAPE/.test(block));
  assert.equal(blocks.length, 1);
  const names = ["NEAR", "FAR", "THIN", "OUTER", "META", "NEAR32", "FAR32", "UNUSED"];
  assert.deepEqual(records.filter(record => record.shape?.kind === "vtableShape").map(record => record.shape),
    blocks.map(block => ({ kind: "vtableShape", slots:
      [...block.matchAll(/^\s*\[\d+\]: (\w+)/gm)].map(match => names.indexOf(match[1]!)) })));
  assert.ok(oracle.includes("Number of entries : 6"));
});
