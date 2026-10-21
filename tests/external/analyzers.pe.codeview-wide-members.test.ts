import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { readLegacyCodeViewModuleTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";

// These are unchanged MSVC /Z7 /utf-8 .debug$T records extracted with llvm-objcopy.
// The host is an actual COFF object, not a claimed natural inline-CodeView PE.
// Source: tests/external/pe-debug-native/LegacyMembersWide.cpp.
void test("MSVC wide-index CodeView retains LLVM member names and decorated type identities", async () => {
  const root = resolve("scan-results/pe-debug-native");
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--codeview",
    resolve(root, "Legacy-members-wide.obj")], { maxBuffer: 4 * 1024 * 1024 }).toString("utf8");
  const start = oracle.indexOf("CodeViewTypes [");
  const end = oracle.indexOf("CodeViewDebugInfo [");
  assert.ok(start >= 0 && end > start);
  const types = oracle.slice(start, end);
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader(await readFile(
    resolve(root, "codeview-wide-types.bin")), warnings));
  const names = parsed.records.flatMap(record => record.members ?? [])
    .flatMap(member => member.name === undefined ? [] : [member.name]);
  const identities = parsed.records.flatMap(record => record.uniqueName === undefined ? [] : [record.uniqueName]);

  assert.deepEqual(names, ["first", "last", "count", "ratio", "длина", "total", "Mode", "read"]);
  assert.deepEqual(names, [...types.matchAll(/^ {6}Name: (.+)\r?$/gm)].map(match => match[1]!.trim()));
  assert.deepEqual(identities, [".?AUPacket@@", ".?AW4Mode@Packet@@", ".?AUPacket@@"]);
  assert.deepEqual(identities, [...types.matchAll(/^ {4}LinkageName: (.+)\r?$/gm)].map(match => match[1]!.trim()));
  assert.deepEqual(warnings, []);
});
