import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { parseCoffObject } from "../../analyzers/coff/index.js";
import { readLegacyCodeViewModuleTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { buildCodeViewBuildTables } from "../../renderers/pe/codeview-build-tables.js";
import { buildCodeViewMemberTables } from "../../renderers/pe/codeview-member-tables.js";
import { codeViewInfoWithTypes } from "../fixtures/pe-codeview-callables.js";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";
import { MockFile } from "../helpers/mock-file.js";

const readObjectTypes = async (path: string, name: string) => {
  const bytes = await readFile(path);
  const coff = await parseCoffObject(new MockFile(bytes));
  const section = coff?.sections.find(value => value.name.value === name);
  assert.ok(section);
  const warnings: string[] = [];
  const types = await readLegacyCodeViewModuleTypes(legacyReader(bytes.subarray(section.pointerToRawData,
    section.pointerToRawData + section.sizeOfRawData), warnings));
  const oracle = execFileSync(resolve("scan-results/pe-debug-native/cvdump.exe"), ["-t", path],
    { maxBuffer: 16 * 1024 * 1024 }).toString("utf8");
  const identities = [...oracle.matchAll(/^0x([0-9a-f]+) : Length = \d+, Leaf = 0x([0-9a-f]+)/gmi)]
    .map(match => ({ type: Number.parseInt(match[2]!, 16), index: Number.parseInt(match[1]!, 16) }));
  assert.equal(types.records.length, identities.length);
  // cvdump prints PRECOMP at the imported range start; that marker is not a local type.
  assert.deepEqual(types.records.filter(record => record.type !== 0x1509)
    .map(record => ({ type: record.type, index: record.index })), identities.filter(record => record.type !== 0x1509));
  assert.deepEqual(warnings, []);
  return types.records;
};

void test("real MSVC precompiled creators and consumers retain every local index from unchanged Microsoft cvdump", async () => {
  const directory = resolve("scan-results/pe-debug-native/pch-reference");
  await mkdir(directory, { recursive: true });
  const compiler = "C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/cl.exe";
  const creator = resolve(directory, "PchCreator.obj");
  const consumer = resolve(directory, "PchConsumer.obj");
  const precompiled = resolve(directory, "PchHeader.pch");
  execFileSync(compiler, ["/nologo", "/TP", "/Z7", "/c", "/YcPchHeader.h", `/Fp${precompiled}`, `/Fo${creator}`,
    resolve("tests/external/pe-debug-native/PchCreator.cpp")]);
  execFileSync(compiler, ["/nologo", "/TP", "/Z7", "/c", "/YuPchHeader.h", `/Fp${precompiled}`, `/Fo${consumer}`,
    resolve("tests/external/pe-debug-native/PchConsumer.cpp")]);
  const creatorTypes = await readObjectTypes(creator, ".debug$P");
  const consumerTypes = await readObjectTypes(consumer, ".debug$T");
  const imported = consumerTypes[0]?.shape;
  const boundary = creatorTypes.find(record => record.type === 0x14)?.shape;
  assert.ok(imported?.kind === "precompiled");
  assert.ok(boundary?.kind === "endPrecompiled");
  assert.equal(imported.signature, boundary.signature);
  assert.equal(consumerTypes[0]?.index, undefined);
  assert.equal(consumerTypes[1]?.index, imported.start + imported.count);
  const info = codeViewInfoWithTypes(consumerTypes);
  const members = buildCodeViewMemberTables(info)[0]!.rows;
  assert.ok(members.some(row => row[3] === "count" && row[4] === "int32" && row[7] === "PchLocal"));
  assert.ok(members.some(row => row[3] === "base" && row[4]!.startsWith("unresolved type #") && row[7] === "PchLocal"));
  assert.ok(buildCodeViewBuildTables(info).find(table => table.key === "typeSources")?.rows
    .some(row => row[2] === "PchLocal" && row[3]!.endsWith("PchConsumer.cpp") && row[4] === "2"));
});
