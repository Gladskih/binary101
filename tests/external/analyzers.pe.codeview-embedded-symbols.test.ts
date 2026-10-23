import assert from "node:assert/strict";
import { test } from "node:test";
import { codeViewStoredTypeText } from "../fixtures/pe-codeview-type-strings.js";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";
import { readLegacyCodeViewModuleTypes } from "../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { readLegacyCodeViewSymbolRecords } from "../../analyzers/pe/debug/legacy-codeview-symbol-records.js";

// MSVC /Z7 output from CodeViewBased.c, unchanged COFF .debug$T, never executed.
void test("real MSVC based-pointer symbol name matches unchanged Microsoft cvdump", async () => {
  const path = resolve("scan-results/pe-debug-native/CodeViewBased.obj");
  const oracle = execFileSync(resolve("scan-results/pe-debug-native/cvdump.exe"), ["-t", path], { encoding: "utf8" });
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader(
    await readFile("scan-results/pe-debug-native/codeview-based-types.bin"), warnings));
  const symbols = parsed.records.flatMap(record => record.symbols ?? []);
  const match = /Based on value in symbol :\s*\(\w+\) S_GDATA32:[^\r\n]*, (.+)/.exec(oracle);

  assert.ok(match);
  assert.deepEqual(symbols, [{ type: 0x110d, name: match[1] }]);
  assert.equal(symbols[0]!.name, "base");
  assert.deepEqual(warnings, []);
});

// Deliberately controlled legacy union variants and LF_REFSYM, assembled by
// unchanged Clang; cvdump independently decodes their stored names and reason.
void test("controlled embedded symbols and pointer base names match unchanged cvdump", async () => {
  const path = resolve("scan-results/pe-debug-native/CodeViewEmbedded.obj");
  const oracle = execFileSync(resolve("scan-results/pe-debug-native/cvdump.exe"), ["-t", "-s", path], { encoding: "utf8" });
  const warnings: string[] = [];
  const types = await readLegacyCodeViewModuleTypes(legacyReader(
    await readFile("scan-results/pe-debug-native/codeview-embedded-types.bin"), warnings));
  const bytes = await readFile("scan-results/pe-debug-native/codeview-embedded-symbols.bin");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  assert.equal(view.getUint32(0, true), 4);
  assert.equal(view.getUint32(4, true), 0xf1);
  assert.equal(view.getUint32(8, true) + 12, bytes.length);
  const symbols = await readLegacyCodeViewSymbolRecords(legacyReader(bytes, warnings), 12, bytes.length);

  assert.deepEqual(codeViewStoredTypeText(types.records), [{ type: 2, strings: ["OldBase"] },
    { type: 0x1002, strings: ["WideBase"] },
    { type: 0x20c, symbols: [{ type: 0x110d, name: "referenced" }] }]);
  assert.deepEqual(types.records.flatMap(record => record.strings ?? []),
    [...oracle.matchAll(/name = '([^']*)'/g)].map(match => match[1]));
  assert.deepEqual(symbols, [{ type: 0x113b, discarded: { reason: 2, fileId: 0xffffffff, line: 0 },
    children: [{ type: 0x110d, name: "removedValue" }] }]);
  assert.deepEqual([...symbols.flatMap(record => record.children ?? []),
    ...types.records.flatMap(record => record.symbols ?? [])].map(record => record.name),
  [...oracle.matchAll(/S_GDATA32:[^\r\n]*, (.+)/g)].map(match => match[1]));
  assert.match(oracle, /S_DISCARDED: Not referenced/);
  assert.deepEqual(warnings, []);
});
