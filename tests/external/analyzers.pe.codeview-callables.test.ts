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

const llvmHex = (text: string, field: string): number => {
  const match = new RegExp(`^    ${field}:.*\\(0x([0-9A-F]+)\\)\\r?$`, "mi").exec(text);
  assert.ok(match, `${field} is missing from unchanged LLVM output`);
  return Number.parseInt(match[1]!, 16);
};

const llvmInteger = (text: string, field: string): number => {
  const match = new RegExp(`^    ${field}: (-?[0-9]+)\\r?$`, "m").exec(text);
  assert.ok(match, `${field} is missing from unchanged LLVM output`);
  return Number(match[1]);
};

const llvmProcedure = (text: string) => {
  const member = text.startsWith("  MemberFunction");
  return { kind: member ? "memberFunction" : "procedure",
    returnType: llvmHex(text, "ReturnType"), callingConvention: llvmHex(text, "CallingConvention"),
    attributes: Number.parseInt(/FunctionOptions \[ \(0x([0-9A-F]+)\)/i.exec(text)![1]!, 16),
    parameterCount: llvmInteger(text, "NumParameters"), argumentList: llvmHex(text, "ArgListType"),
    ...(member ? { classType: llvmHex(text, "ClassType"), thisType: llvmHex(text, "ThisType"),
      thisAdjustment: llvmInteger(text, "ThisAdjustment") } : {}) };
};

const cvdumpIndex = (text: string): number => {
  const match = /(?:\(([0-9a-f]+)\)|0x([0-9a-f]+))/i.exec(text);
  assert.ok(match);
  return Number.parseInt(match.slice(1).find(Boolean)!, 16);
};

const cvdumpConvention = (text: string): number => {
  assert.match(text, /^(Pascal Near|C Near)$/);
  return text === "Pascal Near" ? 2 : 0;
};

void test("real MSVC procedure and member-function type fields agree with unchanged LLVM", async () => {
  const root = resolve("scan-results/pe-debug-native");
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--codeview",
    resolve(root, "Legacy-members-wide.obj")], { maxBuffer: 4 * 1024 * 1024 }).toString("utf8");
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader(await readFile(resolve(root, "codeview-wide-types.bin"))));
  const blocks = [...oracle.matchAll(/^ {2}(?:Procedure|MemberFunction) \(0x([0-9A-F]+)\) \{[^]*?^ {2}\}/gm)];
  assert.equal(blocks.length, 2);
  assert.deepEqual(parsed.records.filter(record => record.shape?.kind === "procedure" ||
    record.shape?.kind === "memberFunction").map(record => ({ index: record.index, shape: record.shape })),
  blocks.map(block => ({ index: Number.parseInt(block[1]!, 16), shape: llvmProcedure(block[0]) })));
});

void test("real DMD embedded procedure and argument references agree with unchanged Microsoft cvdump", async () => {
  const root = resolve("scan-results/pe-debug-native");
  const oracle = new TextDecoder("windows-1252").decode(execFileSync(resolve(root, "cvdump.exe"),
    ["-t", resolve(root, "Legacy-members.exe")], { maxBuffer: 4 * 1024 * 1024 }));
  const file = new MockFile(await readFile(resolve(root, "Legacy-members.exe")));
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const parsed = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const records = parsed.entries.flatMap(entry => entry.legacyCodeView?.directories ?? [])
    .flatMap(directory => directory.subsections)
    .flatMap(section => section.data?.kind === "types" ? section.data.records : []) ?? [];
  const calls = [...oracle.matchAll(/^0x([0-9a-f]+) :[^\r\n]*LF_PROCEDURE_16t[^]*?Return type = ([^,]+), Call type = ([^\r\n]+)[^]*?# Parms = (\d+), Arg list type = 0x([0-9a-f]+)/gm)];
  assert.equal(calls.length, 6);
  assert.deepEqual(records.filter(record => record.shape?.kind === "procedure").map(record => ({
    index: record.index, shape: record.shape })), calls.map(call => ({ index: Number.parseInt(call[1]!, 16),
    shape: { kind: "procedure", returnType: cvdumpIndex(call[2]!), callingConvention: cvdumpConvention(call[3]!),
    attributes: 0, parameterCount: Number(call[4]), argumentList: Number.parseInt(call[5]!, 16) } })));
  const lists = oracle.split(/(?=^0x[0-9a-f]+ :)/m).filter(block => /LF_ARGLIST_16t/.test(block));
  assert.equal(lists.length, 4);
  assert.deepEqual(records.filter(record => record.shape?.kind === "arguments").map(record => ({
    index: record.index, shape: record.shape })), lists.map(block => ({
    index: cvdumpIndex(block.split(" :")[0]!), shape: { kind: "arguments", types:
      [...block.matchAll(/list\[\d+\] = ([^\r\n]+)/g)].map(match => cvdumpIndex(match[1]!)) } })));
  assert.doesNotMatch(parsed.warning ?? "", /type name|LF_SKIP|attribute bits|calling convention/);
});
