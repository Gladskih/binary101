import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { readLegacyCodeViewSymbols } from "../../analyzers/pe/debug/legacy-codeview-symbols.js";
import { createLegacyCodeView, legacyModule, legacyReader, legacySymbol,
  legacyU16, legacyU32 } from "../fixtures/pe-legacy-codeview.js";
import { createPeWithDebugPayloads } from "../fixtures/pe-debug-file.js";
import { codeViewTextRecord, codeViewUtf8 } from "../fixtures/pe-codeview-type-strings.js";
import { codeViewUtf16 } from "../fixtures/pe-codeview-symbol-strings.js";

const c13SymbolRanges = (bytes: Uint8Array): { start: number; end: number }[] => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const ranges: { start: number; end: number }[] = [];
  assert.equal(view.getUint32(0, true), 4);
  let offset = 4;
  while (offset < bytes.length) {
    assert.ok(offset + 8 <= bytes.length);
    const kind = view.getUint32(offset, true);
    const size = view.getUint32(offset + 4, true);
    assert.ok(size <= bytes.length - offset - 8);
    if (kind === 0xf1) ranges.push({ start: offset + 8, end: offset + 8 + size });
    offset = Math.ceil((offset + 8 + size) / 4) * 4;
  }
  return ranges;
};

// Genuine MSVC /Z7 /utf-8 __annotation output, checked by unchanged LLVM 22.1.6.
// The COFF .debug$S payload is unchanged; the resulting object is never executed.
void test("MSVC annotation strings match unchanged LLVM, including UTF-8 text", async () => {
  const path = resolve("scan-results/pe-debug-native/CodeViewAnnotations.obj");
  const bytes = await readFile("scan-results/pe-debug-native/codeview-annotation-symbols.bin");
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--codeview", path], { encoding: "utf8" });
  const warnings: string[] = [];
  const parsed = (await Promise.all(c13SymbolRanges(bytes).map(range =>
    readLegacyCodeViewSymbols(legacyReader(bytes, warnings), range.start, range.end)))).flatMap(value => value.records);
  const annotations = parsed.filter(record => record.type === 0x1019);
  const block = /AnnotationSym \{[^]*?Strings \[([^]*?)\]/.exec(oracle);

  assert.ok(block);
  assert.deepEqual(annotations, [{ type: 0x1019, strings: ["diagnostic", "stored detail", "имя"] }]);
  assert.deepEqual(annotations[0]!.strings, [...block[1]!.matchAll(/^ {8}(.+?)\r?$/gm)].map(match => match[1]));
  assert.deepEqual(warnings, []);
});

// Genuine MSVC LINK environment record from the existing /debugtype:cv,fixup fixture.
// Its unchanged module stream is exported by llvm-pdbutil; no PDB is opened by the app.
void test("MSVC linker environment strings match unchanged llvm-pdbutil", async () => {
  const path = resolve("scan-results/pe-debug-native/Fixup.pdb");
  const bytes = await readFile("scan-results/pe-debug-native/codeview-linker-module.bin");
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-pdbutil.exe", ["dump", "-modi=1", "-symbols", path],
    { encoding: "utf8" });
  const header = /^\s+(\d+) \| S_ENVBLOCK \[size = (\d+)\]/m.exec(oracle);
  assert.ok(header);
  const body = oracle.slice(header.index + header[0].length).split(/^\s*\d+ \| /m)[0]!;
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), Number(header[1]),
    Number(header[1]) + Number(header[2]));

  assert.equal(parsed.records.length, 1);
  assert.equal(parsed.records[0]!.type, 0x113d);
  assert.equal(parsed.records[0]!.strings?.length, 8);
  assert.deepEqual(parsed.records[0]!.strings, [...body.matchAll(/^ {11}- (.*?)\r?$/gm)].map(match => match[1]));
  assert.deepEqual(warnings, []);
});

// Deliberately synthesized records, assembled and decoded by unchanged LLVM 23.
void test("public hot-patch and indirect-register symbol layouts match LLVM 23", async () => {
  const root = "/mnt/c/Users/glads/source/binary101-pe-debug/scan-results/llvm23-resolute/root/usr/lib";
  const oracle = execFileSync("wsl", ["env", `LD_LIBRARY_PATH=${root}/x86_64-linux-gnu`,
    `${root}/llvm-23/bin/llvm-readobj`, "--codeview", "scan-results/pe-debug-native/CodeViewSymbolText.obj"],
  { encoding: "utf8" });
  const bytes = await readFile("scan-results/pe-debug-native/codeview-controlled-symbols.bin");
  const warnings: string[] = [];
  const parsed = (await Promise.all(c13SymbolRanges(bytes).map(range =>
    readLegacyCodeViewSymbols(legacyReader(bytes, warnings), range.start, range.end)))).flatMap(value => value.records);

  assert.deepEqual(parsed.filter(record => record.type !== 0x1116),
    [{ type: 0x1169, name: "patch_target" }, { type: 0x1171, name: "indirect_value" }]);
  assert.deepEqual(parsed.filter(record => record.type !== 0x1116).map(record => record.name),
    [...oracle.matchAll(/^ {6}(?:Name|VarName): (.+)$/gm)].map(match => match[1]));
  assert.deepEqual(warnings, []);
});

// Controlled PDBMAP placement; cvdump independently reads both wchar_t paths.
void test("CodeView UTF-16 PDB mapping agrees with Microsoft's unchanged cvdump", async () => {
  const record = codeViewTextRecord(0x1161, 4, [...codeViewUtf16("source.pdb"), ...codeViewUtf16("target.pdb")]);
  const module = legacyModule("pdb-map.obj");
  module[2] = 0; // No library reference is needed for this controlled module.
  const file = createPeWithDebugPayloads([{ type: 2, data: createLegacyCodeView([
    { type: 0x120, module: 1, data: module },
    { type: 0x125, module: 1, data: Uint8Array.from([...legacyU32(1), ...record]) }
  ]) }]);
  const path = resolve("scan-results/pe-debug-native/codeview-pdb-map.exe");
  await writeFile(path, file.data);
  const oracle = execFileSync(resolve("scan-results/pe-debug-native/cvdump.exe"), ["-s", path], { encoding: "utf8" });
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(record, warnings), 0, record.length);
  const match = /S_PDBMAP: (.+) -> (.+)\r?/.exec(oracle);

  assert.ok(match);
  assert.deepEqual(parsed.records, [{ type: 0x1161, strings: [match[1]!, match[2]!.trimEnd()] }]);
  assert.deepEqual(warnings, []);
});

for (const type of [0x1013, 0x113d]) {
  void test(`CodeView command block ${type} with an empty value matches unchanged cvdump`, async () => {
    const fields = [...codeViewUtf8("empty"), 0, ...codeViewUtf8("next"), ...codeViewUtf8("kept"), 0];
    const record = type === 0x113d ? codeViewTextRecord(type, 5, fields)
      : [...legacySymbol(type, "compiler", 22), ...fields];
    record.splice(0, 2, ...legacyU16(record.length - 2));
    const module = legacyModule("command.obj");
    module[2] = 0;
    const file = createPeWithDebugPayloads([{ type: 2, data: createLegacyCodeView([
      { type: 0x120, module: 1, data: module },
      { type: 0x125, module: 1, data: Uint8Array.from([...legacyU32(1), ...record]) }
    ]) }]);
    const path = resolve(`scan-results/pe-debug-native/codeview-command-${type}.exe`);
    await writeFile(path, file.data);
    const oracle = execFileSync(resolve("scan-results/pe-debug-native/cvdump.exe"), ["-s", path], { encoding: "utf8" });
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewSymbols(legacyReader(record, warnings), 0, record.length);

    assert.match(oracle, /empty = ''/);
    assert.match(oracle, /next = 'kept'/);
    assert.deepEqual(parsed.records[0]!.strings,
      [...oracle.matchAll(/^\s+(empty|next) = '(.*?)'\r?$/gm)].flatMap(match => [match[1], match[2]]));
    assert.deepEqual(warnings, []);
  });
}

void test("C13 compiler command block with an empty value matches unchanged cvdump", async () => {
  const path = resolve("scan-results/pe-debug-native/CodeViewSymbolText.obj");
  const oracle = execFileSync(resolve("scan-results/pe-debug-native/cvdump.exe"), ["-s", path], { encoding: "utf8" });
  const bytes = await readFile("scan-results/pe-debug-native/codeview-controlled-symbols.bin");
  const warnings: string[] = [];
  const parsed = (await Promise.all(c13SymbolRanges(bytes).map(range =>
    readLegacyCodeViewSymbols(legacyReader(bytes, warnings), range.start, range.end)))).flatMap(value => value.records);

  assert.match(oracle, /empty = ''/);
  assert.match(oracle, /next = 'kept'/);
  assert.deepEqual(parsed.find(record => record.type === 0x1116),
    { type: 0x1116, name: "compiler", strings: ["empty", "", "next", "kept"] });
  assert.deepEqual(warnings, []);
});
