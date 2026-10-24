import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import { MockFile } from "../helpers/mock-file.js";

void test("ARM64 shared unwind inventories match unchanged LLVM and assembler directives", async () => {
  const object = resolve("scan-results/UnwindArm64.obj"), image = resolve("scan-results/UnwindArm64.dll");
  execFileSync("C:/Program Files/LLVM/bin/clang.exe", ["--target=aarch64-pc-windows-msvc", "-c",
    resolve("tests/external/pe-debug-native/UnwindArm64.s"), "-o", object]);
  execFileSync("C:/Program Files/LLVM/bin/lld-link.exe", ["/dll", "/noentry", "/nodefaultlib", `/out:${image}`, object]);
  const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--unwind", image]).toString("utf8");
  const file = new MockFile(await readFile(image));
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  assert.ok(parsed?.arm64Unwind);

  assert.equal(parsed.functionCount, [...oracle.matchAll(/RuntimeFunction \{/g)].length);
  assert.deepEqual(parsed.rangeLengths, [...oracle.matchAll(/FunctionLength: (\d+)/g)].map(value => Number(value[1])));
  assert.deepEqual(parsed.arm64Packed?.frameSizeCounts,
    { [Number(/FrameSize: (\d+)/.exec(oracle)![1])]: 1 });
  assert.equal(parsed.arm64Unwind.blockCount, 1);
  assert.equal(parsed.arm64Unwind.incompleteBlockCount, 0);
  assert.deepEqual(parsed.arm64Unwind.registerCounts, { D8: 1, D9: 1, X21: 1, X22: 1, X19: 1, X20: 1, X29: 1, LR: 1 });
  assert.deepEqual(parsed.arm64Unwind.preIndexAdjustmentCounts, { 96: 1 });
  assert.deepEqual(parsed.arm64Unwind.saveOffsetCounts, { 16: 1, 32: 1, 48: 1 });
  assert.deepEqual(parsed.arm64Unwind.operationCounts,
    { set_fp: 1, save_fregp: 1, save_next: 1, save_regp: 1, save_fplr_x: 1, end: 1 });
  assert.match(oracle, /EpilogueOffset: 1/);
  assert.match(oracle, /stp d8, d9, \[sp, #48\]/);
  assert.match(oracle, /stp x19, x20, \[sp, #16\]/);
  assert.match(oracle, /stp x29, x30, \[sp, #-96\]!/);
  assert.match(oracle, /save next/);
  assert.deepEqual(parsed.issues, []);
});
