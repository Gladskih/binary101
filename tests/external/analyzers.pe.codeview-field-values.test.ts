import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { readLegacyCodeViewModuleTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../analyzers/pe/debug/directory.js";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";
import { MockFile } from "../helpers/mock-file.js";

void test("real MSVC member type indices, field offsets and enum values match unchanged LLVM", async () => {
  const root = resolve("scan-results/pe-debug-native");
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--codeview",
    resolve(root, "Legacy-members-wide.obj")], { maxBuffer: 4 * 1024 * 1024 }).toString("utf8");
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader(await readFile(resolve(root, "codeview-wide-types.bin"))));
  const members = parsed.records.flatMap(record => record.members ?? []);
  const fields = [...oracle.matchAll(/^ {4}DataMember \{[^]*?^ {4}\}/gm)].map(match => match[0]);
  const enums = [...oracle.matchAll(/^ {4}Enumerator \{[^]*?^ {4}\}/gm)].map(match => match[0]);
  assert.equal(fields.length, 3);
  assert.equal(enums.length, 2);
  assert.deepEqual(members.filter(member => member.type === 0x150d).map(member => ({
    name: member.name, typeIndex: member.typeIndex, offset: member.offset, attributes: member.attributes
  })), fields.map(field => ({ name: /^ {6}Name: (.+)\r?$/m.exec(field)![1],
    typeIndex: Number.parseInt(/^ {6}Type:.*\(0x([0-9A-F]+)\)/mi.exec(field)![1]!, 16),
    offset: String(Number.parseInt(/^ {6}FieldOffset: 0x([0-9A-F]+)/mi.exec(field)![1]!, 16)),
    attributes: Number.parseInt(/^ {6}AccessSpecifier:.*\(0x([0-9A-F]+)\)/mi.exec(field)![1]!, 16) })));
  assert.deepEqual(members.filter(member => member.type === 0x1502).map(member => ({
    name: member.name, value: member.value })), enums.map(record => ({
    name: /^ {6}Name: (.+)\r?$/m.exec(record)![1], value: /^ {6}EnumValue: (.+)\r?$/m.exec(record)![1] })));
});

void test("real embedded DMD enum values and member offsets match unchanged Microsoft cvdump", async () => {
  const root = resolve("scan-results/pe-debug-native");
  const path = resolve(root, "Legacy-members.exe");
  const oracle = execFileSync(resolve(root, "cvdump.exe"), ["-t", path], { encoding: "utf8" });
  const file = new MockFile(await readFile(path));
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const parsed = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const members = parsed.entries.flatMap(entry => entry.legacyCodeView?.directories ?? [])
    .flatMap(directory => directory.subsections)
    .flatMap(section => section.data?.kind === "types" ? section.data.records : [])
    .flatMap(record => record.members ?? []);
  const values = [...oracle.matchAll(/LF_ENUMERATE,[^\r\n]*value = (-?\d+)/g)].map(match => match[1]);
  const offsets = [...oracle.matchAll(/LF_MEMBER_16t,[^\r\n]*offset = (-?\d+)/g)].map(match => match[1]);
  assert.equal(values.length, 2);
  assert.equal(offsets.length, 3);
  assert.deepEqual(members.filter(member => member.type === 0x403).map(member => member.value), values);
  assert.deepEqual(members.filter(member => member.type === 0x406).map(member => member.offset), offsets);
  assert.doesNotMatch(parsed.warning ?? "", /field list|field has|value is not/);
});
