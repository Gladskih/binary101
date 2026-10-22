import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import { parseExceptionDebugInfo } from "../../analyzers/pe/debug/exception.js";
import { MockFile } from "../helpers/mock-file.js";
import type { ArmntPackedStatistics } from "../../analyzers/pe/exception/armnt-packed-types.js";

// Clang 22.1.6 builds ExceptionArm.c at -O0 and -O2 -fomit-frame-pointer.
// Other cases are unchanged LLVM 23.1.3 assembler fixtures, emitted by llvm-mc 23.1.5,
// linked with the local handler stubs. No resulting executable or DLL is executed.
// https://github.com/llvm/llvm-project/tree/llvmorg-23.1.3/llvm/test/MC/ARM
// The oracle is unchanged llvm-readobj 22.1.6, including decoded lengths and handlers.
const codeRva = (address: string, base: number): number => {
  const rva = Number.parseInt(address, 16) - base;
  return rva - (rva & 1); // The stored low bit selects Thumb state, not the instruction byte.
};

const inventory = (values: number[]): Record<number, number> =>
  values.reduce<Record<number, number>>((counts, value) => {
    counts[value] = (counts[value] ?? 0) + 1;
    return counts;
  }, {});

const verifyPacked = (statistics: ArmntPackedStatistics | undefined, oracle: string): void => {
  assert.equal(statistics ? Object.values(statistics.returnKinds).reduce((sum, count) => sum + count, 0) : 0,
    [...oracle.matchAll(/ReturnType:/g)].length);
  if (!statistics) return;
  assert.deepEqual(statistics.returnKinds, {
    popPc: [...oracle.matchAll(/ReturnType: pop \{pc\}/g)].length,
    branch16: [...oracle.matchAll(/ReturnType: bx <reg>/g)].length,
    branch32: [...oracle.matchAll(/ReturnType: b\.w <target>/g)].length,
    noEpilog: [...oracle.matchAll(/ReturnType: \(no epilogue\)/g)].length
  });
  assert.equal(statistics.homesParametersCount, [...oracle.matchAll(/HomedParameters: Yes/g)].length);
  assert.equal(statistics.savesLinkRegisterCount, [...oracle.matchAll(/LinkRegister: Yes/g)].length);
  assert.equal(statistics.frameChainCount, [...oracle.matchAll(/Chaining: Yes/g)].length);
  assert.deepEqual(statistics.stackAdjustments,
    inventory([...oracle.matchAll(/StackAdjustment: (\d+)/g)].map(match => Number(match[1]))));
};

for (const name of ["raw-exception-armnt.exe", "raw-exception-armnt-packed.exe", "armnt-seh.dll",
  "armnt-seh-packed.dll", "armnt-seh-epilog-sharing.dll", "armnt-seh-epilog-packing.dll"]) {
  void test(`ARMNT image and raw debug copy match LLVM: ${name}`, async () => {
    const path = `scan-results/pe-debug-native/${name}`;
    const file = new MockFile(await readFile(path));
    const core = await parsePeHeaders(file);
    assert.ok(core?.opt && core.opt.Magic !== 0x107);
    const imageBase = Number(core.opt.ImageBase);
    const directory = core.dataDirs.find(entry => entry.name === "EXCEPTION");
    assert.ok(directory);
    const offset = core.rvaToOff(directory.rva);
    assert.ok(offset != null);
    const expected = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
    const copy = new MockFile(Uint8Array.from([...file.data,
      ...file.data.subarray(offset, offset + directory.size)]));
    const copied = await parseExceptionDebugInfo(copy, core.rvaToOff, 0, file.size,
      directory.size, core.coff.Machine, assert.fail);
    const oracle = execFileSync("C:/Program Files/LLVM/bin/llvm-readobj.exe", ["--unwind", path], { encoding: "utf8" });

    assert.ok(expected);
    assert.equal(expected.functionCount, [...oracle.matchAll(/RuntimeFunction \{/g)].length);
    assert.deepEqual(expected.beginRvas,
      [...oracle.matchAll(/Function: (0x[0-9A-F]+)/g)].map(match => codeRva(match[1]!, imageBase)));
    assert.deepEqual(expected.rangeLengths,
      [...oracle.matchAll(/FunctionLength: (\d+)/g)].map(match => Number(match[1])));
    assert.deepEqual(expected.handlerRvas, [...new Set(
      [...oracle.matchAll(/Routine: (0x[0-9A-F]+)/g)].map(match => codeRva(match[1]!, imageBase)))]);
    assert.equal(expected.handlerUnwindInfoCount, [...oracle.matchAll(/Routine:/g)].length);
    assert.equal(expected.fragmentEntryCount, [...oracle.matchAll(/Fragment: Yes/g)].length);
    verifyPacked(expected.armntPacked, oracle);
    assert.equal(expected.invalidEntryCount, 0);
    assert.deepEqual(expected.issues, []);
    assert.deepEqual(copied, expected);
  });
}
