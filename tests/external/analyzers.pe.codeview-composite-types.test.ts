import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { parseCoffObject } from "../../analyzers/coff/index.js";
import { readLegacyCodeViewModuleTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";
import { MockFile } from "../helpers/mock-file.js";
import { codeViewTypeRows } from "../../renderers/pe/codeview-type-tables.js";

const llvmHex = (block: string, label: string): number => {
  const match = new RegExp(`^    ${label}:.*0x([0-9A-F]+)`, "mi").exec(block);
  assert.ok(match, `Missing LLVM field ${label}`);
  return Number.parseInt(match[1]!, 16);
};

void test("real MSVC 16-bit member-count overflow retains all 65536 fields and a visible diagnostic", async () => {
  const source = resolve("scan-results/pe-debug-native/LargeComposite.cpp");
  const object = resolve("scan-results/pe-debug-native/LargeComposite.obj");
  // Exactly 2^16 fields triggers the 16-bit LF_STRUCTURE count overflow in MSVC 14.51.
  await writeFile(source, "struct Wide { " + Array.from({ length: 65536 }, (_, index) =>
    `int field${index};`).join(" ") + " }; Wide sample;", "utf8");
  execFileSync("C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/cl.exe",
    ["/nologo", "/TP", "/Z7", "/Od", "/c", source, `/Fo${object}`]);
  const bytes = await readFile(object);
  const coff = await parseCoffObject(new MockFile(bytes));
  const section = coff?.sections.find(value => value.name.value === ".debug$T");
  assert.ok(section);
  const warnings: string[] = [];
  const types = await readLegacyCodeViewModuleTypes(legacyReader(bytes.subarray(section.pointerToRawData,
    section.pointerToRawData + section.sizeOfRawData), warnings));
  const wide = types.records.find(record => record.type === 0x1505 && record.name === "Wide");
  assert.ok(wide?.shape?.kind === "aggregate");
  assert.equal(wide.shape.memberCount, 0);
  assert.equal(wide.shape.size, "262144");
  assert.equal(types.records.flatMap(record => record.members ?? [])
    .filter(member => member.type === 0x150d).length, 65536);
  assert.match(codeViewTypeRows(types).find(row => row[1] === "Wide")![5]!,
    /^fields: 65536 records in \d+ lists; declared member count is too small$/);
  assert.deepEqual(warnings, []);
});

const llvmNumber = (block: string, label: string): number => {
  const match = new RegExp(`^    ${label}: (\\d+)`, "m").exec(block);
  assert.ok(match, `Missing LLVM field ${label}`);
  return Number(match[1]);
};

void test("MSVC composite sizes, properties and type-list references match unchanged LLVM", async () => {
  const object = resolve("scan-results/pe-debug-native/CompositeTypes.obj");
  // C++ is needed for class properties, virtual inheritance and overloaded members.
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
  const blocks = [...oracle.matchAll(/^ {2}(Struct|Union|Enum|Array) \(0x([0-9A-F]+)\) \{[^]*?^ {2}\}/gm)];
  assert.equal(blocks.length, 9);
  assert.deepEqual(types.records.filter(record => ["aggregate", "array"].includes(record.shape?.kind ?? ""))
    .map(record => ({ index: record.index, type: record.type, name: record.name, shape: record.shape })),
  blocks.map(block => ({
      index: Number.parseInt(block[2]!, 16), type: llvmHex(block[0], "TypeLeafKind"),
      name: /^ {4}Name: (.*)\r?$/m.exec(block[0])![1]!.replace(/\r$/, ""), shape: llvmShape(block[1]!, block[0])
    })));
  assert.deepEqual(warnings, []);
});

const llvmShape = (kind: string, block: string) => {
  if (kind === "Array") return { kind: "array", elementType: llvmHex(block, "ElementType"),
    indexType: llvmHex(block, "IndexType"), size: String(llvmNumber(block, "SizeOf")) };
  const common = { kind: "aggregate", memberCount: llvmNumber(block, kind === "Enum" ? "NumEnumerators" : "MemberCount"),
    properties: Number.parseInt(/^ {4}Properties \[ \(0x([0-9A-F]+)/mi.exec(block)![1]!, 16),
    fieldList: llvmHex(block, kind === "Enum" ? "FieldListType" : "FieldList") };
  if (kind === "Enum") return { ...common, underlyingType: llvmHex(block, "UnderlyingType") };
  return { ...common, size: String(llvmNumber(block, "SizeOf")),
    ...(kind === "Struct" ? { derivedTypes: llvmHex(block, "DerivedFrom"), vtableShape: llvmHex(block, "VShape") } : {}) };
};

const cvdumpStructure = (block: string) => {
  const index = /^0x([0-9a-f]+) :/.exec(block);
  const members = /# members = (\d+),\s+field list type 0x([0-9a-f]+)/.exec(block);
  const lists = /Derivation list type 0x([0-9a-f]+), VT shape type 0x([0-9a-f]+)/.exec(block);
  const size = /Size = (\d+), class name = ([^\r\n]+)/.exec(block);
  assert.ok(index && members && lists && size);
  return { index: Number.parseInt(index[1]!, 16), name: size[2], memberCount: Number(members[1]),
    fieldList: Number.parseInt(members[2]!, 16), derivedTypes: Number.parseInt(lists[1]!, 16),
    vtableShape: Number.parseInt(lists[2]!, 16), size: size[1] };
};

void test("embedded DMD class sizes and field-list references match unchanged Microsoft cvdump", async () => {
  const filePath = resolve("scan-results/pe-debug-native/Legacy-members.exe");
  const oracle = execFileSync(resolve("scan-results/pe-debug-native/cvdump.exe"), ["-t", filePath]).toString("utf8");
  const file = new MockFile(await readFile(filePath));
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const records = debug.entries.flatMap(entry => entry.legacyCodeView?.directories ?? [])
    .flatMap(directory => directory.subsections)
    .flatMap(section => section.data?.kind === "types" ? section.data.records : []);
  const blocks = oracle.split(/(?=^0x[0-9a-f]+ :)/m)
    .filter(block => /^0x[0-9a-f]+ :[^\r\n]*LF_STRUCTURE_16t/.test(block));
  assert.equal(blocks.length, 6);
  assert.deepEqual(records.filter(record => record.type === 4 || record.type === 5).map(record => {
    assert.ok(record.shape?.kind === "aggregate");
    return { index: record.index, name: record.name, memberCount: record.shape.memberCount,
      fieldList: record.shape.fieldList, derivedTypes: record.shape.derivedTypes,
      vtableShape: record.shape.vtableShape, size: record.shape.size };
  }), blocks.map(cvdumpStructure));
});
