import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import { MockFile } from "../helpers/mock-file.js";

const inventory = (values: (string | number)[]): Record<string, number> => {
  const counts: Record<string, number> = {};
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
};

void test("v1 semantic inventories agree with unchanged LLVM on assembled and linked unwind directives", async () => {
  const object = resolve("scan-results/pe-debug-native/UnwindOperations.obj");
  const image = resolve("scan-results/pe-debug-native/UnwindOperations.dll");
  execFileSync("C:/Program Files/LLVM/bin/clang.exe", ["--target=x86_64-pc-windows-msvc", "-c",
    resolve("tests/external/pe-debug-native/UnwindOperations.s"), "-o", object]);
  execFileSync("C:/Program Files/LLVM/bin/lld-link.exe", ["/dll", "/noentry", "/nodefaultlib", `/out:${image}`, object]);
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--unwind", image]).toString("utf8");
  const file = new MockFile(await readFile(image));
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  assert.ok(parsed?.unwindInfoV12);
  const statistics = parsed.unwindInfoV12;

  assert.equal(statistics.blockCount, [...oracle.matchAll(/Version: 1/g)].length);
  assert.deepEqual(statistics.operationCounts, inventory([...oracle.matchAll(/^\s+0x[\dA-F]+: (\w+)/gm)]
    .map(match => match[1]!)));
  assert.deepEqual(statistics.allocationCounts, inventory([...oracle.matchAll(/ALLOC_(?:SMALL|LARGE) size=(\d+)/g)]
    .map(match => Number(match[1]))));
  assert.deepEqual(statistics.registerCounts, inventory([...oracle.matchAll(/(?:SAVE_\w+|PUSH_NONVOL) reg=(\w+)/g)]
    .map(match => match[1]!)));
  assert.deepEqual(statistics.saveOffsetCounts, inventory([...oracle.matchAll(/SAVE_\w+ reg=\w+, offset=(0x[\dA-F]+)/g)]
    .map(match => Number(match[1]))));
  assert.deepEqual(statistics.prologSizeCounts, inventory([...oracle.matchAll(/PrologSize: (\d+)/g)]
    .map(match => Number(match[1]))));
  assert.deepEqual(statistics.frameRegisterCounts, { RBP: 1 });
  assert.deepEqual(statistics.frameOffsetCounts, { 32: 1 });
  assert.equal(statistics.incompleteBlockCount, 0);
  assert.deepEqual(parsed.issues, []);
});

const v2Image = async (): Promise<MockFile> => {
  const object = resolve("scan-results/pe-debug-native/UnwindEpilogs.obj");
  const image = resolve("scan-results/pe-debug-native/UnwindEpilogs.dll");
  execFileSync("C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/MSVC/14.51.36231/" +
    "bin/Hostx64/x64/cl.exe", ["/nologo", "/O2", "/GS-", "/c", "/d2epilogunwind", `/Fo${object}`,
    resolve("tests/external/pe-debug-native/UnwindEpilogs.c")]);
  execFileSync("C:/Program Files/LLVM/bin/lld-link.exe", ["/dll", "/noentry", "/nodefaultlib", `/out:${image}`, object]);
  return new MockFile(await readFile(image));
};

void test("MSVC v2 scopes agree with LLVM for at-end and equivalent explicit-offset encodings", async () => {
  const file = await v2Image();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const directory = core.dataDirs.find(value => value.name === "EXCEPTION");
  assert.ok(directory);
  const pdata = core.rvaToOff(directory.rva);
  assert.ok(pdata != null);
  const view = new DataView(file.data.buffer, file.data.byteOffset, file.data.byteLength);
  const xdata = core.rvaToOff(view.getUint32(pdata + 8, true));
  assert.ok(xdata != null);
  const original = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  assert.ok(original?.unwindInfoV12);
  const firstLength = file.data[xdata + 4]!;
  assert.equal(file.data[xdata + 5], 0x16); // MSVC AtEnd=true.
  assert.equal(file.data[xdata + 10], 0); // Fourth EPILOG slot is padding.
  assert.equal(file.data[xdata + 11], 6);
  // Controlled alternate encoding: replace the implicit final scope with an explicit
  // offset using the existing padding slot. This variant is not compiler output.
  file.data[xdata + 5] = 6;
  file.data[xdata + 10] = firstLength;
  const image = resolve("scan-results/pe-debug-native/UnwindEpilogs-explicit.dll");
  await writeFile(image, file.data);
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--unwind", image]).toString("utf8");
  const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  assert.ok(parsed?.unwindInfoV12);

  assert.match(oracle, /Version: 2/);
  assert.match(oracle, /EPILOG atend=no/);
  assert.equal(parsed.epilogScopeCount, [...oracle.matchAll(/EPILOG offset=/g)].length);
  assert.equal(parsed.epilogScopeCount, original.epilogScopeCount);
  assert.equal(parsed.epilogUnwindInfoCount, 1);
  assert.deepEqual(parsed.unwindInfoV12.operationCounts, original.unwindInfoV12.operationCounts);
  assert.deepEqual(parsed.unwindInfoV12.allocationCounts, { 432: 1 });
  assert.deepEqual(parsed.issues, []);
});
