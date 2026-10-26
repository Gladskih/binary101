import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { legacyReader } from "../fixtures/pe-legacy-codeview.js";
import { readLegacyCodeViewSymbols } from "../../analyzers/pe/debug/legacy-codeview-symbols.js";
import { analyzeCodeViewLocalScopes } from "../../analyzers/pe/debug/codeview-local-scopes.js";

const buildNativeLocals = async () => {
  const root = resolve("scan-results/local-native");
  await mkdir(root, { recursive: true });
  const object = resolve(root, "locals.obj");
  const pdb = resolve(root, "locals.pdb");
  execFileSync("C:/Program Files/LLVM/bin/clang-cl.exe", ["/nologo", "/Z7", "/O2", "/GS-", "/c",
    resolve("tests/external/pe-debug-native/CodeViewLocals.c"), `/Fo${object}`]);
  execFileSync("C:/Program Files/LLVM/bin/lld-link.exe", ["/dll", "/noentry", "/nodefaultlib", "/debug",
    "/incremental:no", `/out:${resolve(root, "locals.dll")}`, `/pdb:${pdb}`, object]);
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-pdbutil.exe",
    ["dump", "-modules", "-symbols", "-modi=0", pdb], { encoding: "utf8" });
  const stream = /debug stream: (\d+)/.exec(oracle);
  assert.ok(stream);
  const raw = resolve(root, "module.bin");
  execFileSync("C:/Program Files/LLVM/bin/llvm-pdbutil.exe", ["export", `--stream=${stream[1]}`, `--out=${raw}`, pdb]);
  return { oracle, bytes: await readFile(raw) };
};

const symbolBlocks = (oracle: string) => {
  const headers = [...oracle.matchAll(/^\s+(\d+) \| (S_\w+) \[size = (\d+)\]/gm)];
  return headers.map((header, index) => ({ offset: Number(header[1]), kind: header[2]!, size: Number(header[3]),
    text: oracle.slice(header.index, headers[index + 1]?.index) }));
};

const oracleRange = (text: string) => {
  const fields = /range start = ([\dA-Fa-f]+):([\dA-Fa-f]+), length = (\d+)/.exec(text)
    ?? /range = \[([\dA-Fa-f]+):([\dA-Fa-f]+),\+(\d+)\)/.exec(text);
  assert.ok(fields);
  // llvm-pdbutil MinimalSymbolDumper uses decimal fields with zero padding here.
  return { section: Number(fields[1]), offset: Number(fields[2]), length: Number(fields[3]) };
};

// Genuine linked native symbol bytes; LLVM's unchanged dumper supplies the oracle.
// The DLL is not executed and the application does not gain a PDB dependency.
void test("Native frame, local and range fields agree with unchanged LLVM and preserve scope identity", async () => {
  const { oracle, bytes } = await buildNativeLocals();
  const records = symbolBlocks(oracle);
  assert.ok(records.length > 10);
  const last = records.at(-1)!;
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 4, last.offset + last.size);
  const scopes = analyzeCodeViewLocalScopes(parsed);
  const locals = parsed.records.filter(record => record.local);
  const expectedLocals = records.filter(record => record.kind === "S_LOCAL");
  const frame = parsed.records.find(record => record.frame)!.frame!;
  const expectedFrame = /size = (\d+), padding size = (\d+), offset to padding = (\d+)[^]*?bytes of callee saved registers = (\d+)/
    .exec(oracle)!;

  assert.deepEqual([frame.frameBytes, frame.paddingBytes, frame.paddingOffset, frame.savedRegisterBytes],
    expectedFrame.slice(1).map(Number));
  assert.deepEqual(locals.map(record => record.name), expectedLocals.map(record => /`([^`]*)`/.exec(record.text)![1]));
  assert.deepEqual(locals.map(record => record.local!.typeIndex), expectedLocals.map(record =>
    Number.parseInt(/type=0x([\dA-Fa-f]+)/.exec(record.text)![1]!, 16)));
  assert.deepEqual(parsed.records.filter(record => record.localRange).map(record => record.localRange!.range),
    records.filter(record => record.kind.startsWith("S_DEFRANGE")).map(record => oracleRange(record.text)));
  assert.equal(locals.find(record => record.name === "seed")!.local!.flags, 1);
  assert.equal(locals.find(record => record.name === "branch")!.local!.flags, 0x100);
  assert.deepEqual(scopes.issues, []);
  assert.deepEqual(scopes.bindings.flatMap(binding => binding.issues), []);
  assert.ok(scopes.bindings.every(binding => binding.procedure?.name === "InspectLocals"));
  assert.equal(scopes.bindings.filter(binding => binding.record.localRange && binding.local).length, 4);
  assert.deepEqual(warnings, []);
});
