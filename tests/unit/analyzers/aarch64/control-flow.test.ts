import assert from "node:assert/strict";
import { test } from "node:test";
import { createDisassembler, type Disassembler } from "llvm-aarch64-disasm";
import { walkAarch64ControlFlow } from "../../../../analyzers/aarch64/control-flow.js";
import type { ElfInstructionSetReport } from "../../../../analyzers/elf/disassembly-types.js";
import { aarch64Code, aarch64Options } from "../../../fixtures/aarch64-code.js";

const decoder = await createDisassembler();
const emptyReport = (): ElfInstructionSetReport => ({
  bitness: 64, bytesSampled: 0, bytesDecoded: 0, instructionCount: 0,
  invalidInstructionCount: 0, instructionSets: [], issues: []
});

const walkWords = async (words: number[], seeds = [0x1000n]): Promise<ElfInstructionSetReport> => {
  const file = aarch64Code(words);
  const report = emptyReport();
  await walkAarch64ControlFlow(decoder, async address => {
    const offset = Number(address - 0x1000n);
    return offset < 0 ? new Uint8Array() : file.data.subarray(offset, offset + 4);
  }, seeds, aarch64Options(file.size), report);
  return report;
};

// Branch/extension encodings: https://github.com/Gladskih/llvm-aarch64-disasm/blob/main/test/decode.test.mjs
void test("AArch64 conditional branches, calls, loops and duplicate seeds decode each address once", async () => {
  // b.eq +8; ret; bl +8; b -12 (back to ret); ret
  const report = await walkWords([0x54000040, 0xd65f03c0, 0x94000002, 0x17fffffd, 0xd65f03c0],
    [0x1000n, 0x1000n]);

  assert.equal(report.instructionCount, 5);
  assert.equal(report.bytesDecoded, 20);
  assert.equal(report.invalidInstructionCount, 0);
  assert.deepEqual(report.issues, []);
});

void test("AArch64 indirect calls fall through and indirect branches stop", async () => {
  const report = await walkWords([0xd63f0000, 0xd61f0000, 0xffffffff]); // blr x0; br x0

  assert.equal(report.instructionCount, 2);
  assert.equal(report.invalidInstructionCount, 0);
});

void test("AArch64 invalid words stop only their path and soft-fail stays visible", async () => {
  // ldp x0,x0,[x1] twice (soft-fail); invalid; ret (separate seed).
  const report = await walkWords([0xa9400020, 0xa9400020, 0xffffffff, 0xd65f03c0], [0x1000n, 0x100cn]);

  assert.equal(report.instructionCount, 3);
  assert.equal(report.invalidInstructionCount, 1);
  assert.deepEqual(report.issues, ["LLVM reported soft-fail instructions."]);
});

void test("AArch64 ignores invalid addresses and ends at unavailable bytes", async () => {
  const report = await walkWords([], [-4n, 1n << 64n, 0x1001n, 0x1000n]);

  assert.equal(report.instructionCount, 0);
  assert.equal(report.issues.length, 3);
  assert.ok(report.issues.every(issue => issue.includes("invalid or unaligned")));
});

void test("AArch64 rejects empty decoder responses without inventing counts", async () => {
  const report = emptyReport();
  const broken: Disassembler = { decode: () => [] };

  await assert.rejects(walkAarch64ControlFlow(broken, async () => new Uint8Array(4),
    [0x1000n], aarch64Options(4), report), /returned no instruction/);
  assert.equal(report.instructionCount, 0);
});

void test("AArch64 address arithmetic wraps at the 64-bit boundary", async () => {
  const report = emptyReport();
  const addresses: bigint[] = [];
  await walkAarch64ControlFlow(decoder, async address => {
    addresses.push(address);
    return aarch64Code([address === 0n ? 0xd65f03c0 : 0xd503201f]).data;
  }, [0xfffffffffffffffen - 2n], aarch64Options(8), report);

  assert.deepEqual(addresses, [0xfffffffffffffffen - 2n, 0n]);
  assert.equal(report.instructionCount, 2);
});

void test("AArch64 returns terminate paths even if more code follows", async () => {
  const report = await walkWords([0xd65f03c0, 0xd503201f]);

  assert.equal(report.instructionCount, 1);
});

for (const interval of [undefined, 0, -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
  const intervalOptions = interval === undefined ? {} : { yieldEveryInstructions: interval };
  void test(`AArch64 invalid yield interval ${interval} retains responsive progress`, async () => {
    // 1024 is the default scheduling interval, independent of the ISA word size.
    const file = aarch64Code(Array<number>(1025).fill(0xd503201f));
    const stages: number[] = [];
    const controller = new AbortController();
    const opts = { ...aarch64Options(file.size), ...intervalOptions };
    opts.signal = controller.signal;
    opts.onProgress = progress => {
      stages.push(progress.instructionCount);
      if (progress.instructionCount > 0) controller.abort();
    };
    const report = emptyReport();
    await walkAarch64ControlFlow(decoder, async address => {
      const offset = Number(address - 0x1000n);
      return file.data.subarray(offset, offset + 4);
    }, [0x1000n], opts, report);

    assert.deepEqual(stages, [0, 1024]);
    assert.equal(report.instructionCount, 1024);
  });
}
