import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeElfInstructionSets } from "../../../../analyzers/elf/disassembly-analyze.js";
import { aarch64Code, aarch64Options } from "../../../fixtures/aarch64-code.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("AArch64 follows branches and preserves SVE or SME requirements", async () => {
  // b +8; invalid (unreachable); add z0.s,z0.s,z0.s; ret.
  const file = aarch64Code([0x14000002, 0xffffffff, 0x04a00000, 0xd65f03c0]);
  const report = await analyzeElfInstructionSets(file, aarch64Options(file.size));

  assert.equal(report.instructionCount, 3);
  assert.equal(report.bytesDecoded, 12);
  assert.equal(report.invalidInstructionCount, 0);
  assert.ok(report.instructionSets.some(set => /FEAT_SVE or FEAT_SME/.test(set.label)));
  assert.equal(report.seedSummary?.uniqueEntrypoints, 1);
  assert.equal(report.decoderVersion, "LLVM 21.1.8");
});

void test("AArch64 instructions remain little endian in big endian ELF and ELF32", async () => {
  const file = aarch64Code([0xd503201f, 0xd65f03c0]); // nop; ret
  const report = await analyzeElfInstructionSets(file, {
    ...aarch64Options(file.size), littleEndian: false, is64Bit: false
  });

  assert.equal(report.bitness, 64);
  assert.equal(report.instructionCount, 2);
  assert.deepEqual(report.issues, []);
});

void test("AArch64 reports truncated instructions and oversized segments", async () => {
  const file = new MockFile(new Uint8Array([0x1f, 0x20]), "truncated.elf");
  const report = await analyzeElfInstructionSets(file, aarch64Options(file.size + 4));

  assert.equal(report.invalidInstructionCount, 1);
  assert.equal(report.bytesDecoded, 0);
  assert.equal(report.bytesSampled, 2);
  assert.ok(report.issues.some(issue => /extends past end of file; truncating/.test(issue)));
  assert.ok(report.issues.some(issue => /Truncated AArch64 instruction at 0x1000/.test(issue)));
});

void test("AArch64 cancellation and throwing progress callbacks are safe", async () => {
  const file = aarch64Code([0xd503201f, 0xd65f03c0]);
  const controller = new AbortController();
  const stages: string[] = [];
  const report = await analyzeElfInstructionSets(file, {
    ...aarch64Options(file.size), signal: controller.signal, yieldEveryInstructions: 1,
    onProgress: progress => {
      stages.push(progress.stage);
      if (progress.instructionCount === 1) controller.abort();
      throw new Error("UI callback failed");
    }
  });

  assert.equal(report.instructionCount, 1);
  assert.ok(report.issues.some(issue => /cancelled/.test(issue)));
  assert.deepEqual(stages, ["loading", "decoding", "decoding", "done"]);
});

void test("AArch64 can sample code at virtual address zero", async () => {
  const file = aarch64Code([0xd65f03c0]);
  const opts = aarch64Options(file.size);
  opts.entrypointVaddr = 0n;
  opts.programHeaders[0]!.vaddr = 0n;
  const report = await analyzeElfInstructionSets(file, opts);

  assert.equal(report.instructionCount, 1);
  assert.equal(report.seedSummary?.uniqueEntrypoints, 1);
});

void test("AArch64 rejects unavailable regions and invalid virtual ranges", async () => {
  const file = aarch64Code([0xd65f03c0]);
  const opts = aarch64Options(file.size);
  opts.programHeaders = [-1n, BigInt(file.size), 1n << 64n].map(offset => ({
    ...opts.programHeaders[0]!, offset
  }));
  opts.programHeaders.push({ ...opts.programHeaders[0]!, offset: 0n, vaddr: -1n });
  opts.programHeaders.push({ ...opts.programHeaders[0]!, offset: 0n, vaddr: (1n << 64n) - 1n });
  const report = await analyzeElfInstructionSets(file, opts);

  assert.equal(report.bytesSampled, 0);
  assert.equal(report.issues.filter(issue => /out-of-bounds/.test(issue)).length, 5);
  assert.ok(report.issues.some(issue => /No executable/.test(issue)));
});

void test("AArch64 reports read failures and pre-cancellation", async () => {
  const file = aarch64Code([0xd65f03c0]);
  const controller = new AbortController();
  controller.abort();
  const stages: string[] = [];
  const cancelled = await analyzeElfInstructionSets(file, {
    ...aarch64Options(file.size), signal: controller.signal,
    onProgress: progress => { stages.push(progress.stage); }
  });
  file.slice = () => { throw new Error("read failed"); };
  const failed = await analyzeElfInstructionSets(file, aarch64Options(file.size));

  assert.equal(cancelled.instructionCount, 0);
  assert.ok(cancelled.issues.some(issue => /cancelled/.test(issue)));
  assert.deepEqual(stages, ["loading", "done"]);
  assert.equal(failed.instructionCount, 0);
  assert.ok(failed.issues.some(issue => /read failed/.test(issue)));
});

void test("AArch64 supports high addresses and warns about unaligned seeds", async () => {
  const file = aarch64Code([0xd65f03c0]);
  const opts = aarch64Options(file.size);
  opts.entrypointVaddr = 0x1_0000_0000n;
  opts.programHeaders[0]!.vaddr = opts.entrypointVaddr;
  const high = await analyzeElfInstructionSets(file, opts);
  opts.entrypointVaddr += 1n;
  const unaligned = await analyzeElfInstructionSets(file, opts);

  assert.equal(high.instructionCount, 1);
  assert.equal(unaligned.instructionCount, 0);
  assert.ok(unaligned.issues.some(issue => /unaligned/.test(issue)));
});

void test("AArch64 reads bounded windows from large executable segments", async () => {
  const bytes = new Uint8Array(128 * 1024);
  bytes.set(aarch64Code([0xd503201f, 0xd65f03c0]).data);
  const file = new MockFile(bytes, "large.elf");
  const slice = file.slice.bind(file);
  const reads: number[] = [];
  file.slice = (start, end) => {
    reads.push((end ?? file.size) - (start ?? 0));
    return slice(start, end);
  };
  const report = await analyzeElfInstructionSets(file, aarch64Options(file.size));

  assert.equal(report.instructionCount, 2);
  // Shared range reader's documented production window is 64 KiB.
  assert.ok(reads.every(size => size <= 64 * 1024));
  assert.equal(reads.length, 1);
});

void test("AArch64 never completes truncated code using bytes outside its section", async () => {
  const file = aarch64Code([0xd503201f, 0xd65f03c0, 0xd65f03c0]);
  const report = await analyzeElfInstructionSets(file, {
    ...aarch64Options(file.size), programHeaders: [], sections: [{
      index: 0, nameOff: 0, name: ".text", type: 1, typeName: "PROGBITS",
      flags: 4n, flagNames: ["EXECINSTR"], addr: 0x1000n, offset: 0n,
      size: 6n, link: 0, info: 0, addralign: 4n, entsize: 0n
    }]
  });

  assert.equal(report.bytesSampled, 6);
  assert.equal(report.bytesDecoded, 4);
  assert.equal(report.instructionCount, 1);
  assert.equal(report.invalidInstructionCount, 1);
  assert.ok(report.issues.some(issue => /Truncated AArch64 instruction at 0x1004/.test(issue)));
});

void test("AArch64 clamps nonzero file offsets and accepts the highest aligned address", async () => {
  const file = aarch64Code([0xffffffff, 0xd65f03c0]);
  const opts = aarch64Options(file.size);
  opts.programHeaders[0]!.offset = 4n;
  const truncated = await analyzeElfInstructionSets(file, opts);
  opts.programHeaders[0]!.filesz = 4n;
  opts.programHeaders[0]!.vaddr = 0xfffffffffffffffcn;
  opts.entrypointVaddr = 0xfffffffffffffffcn;
  const high = await analyzeElfInstructionSets(file, opts);

  assert.equal(truncated.instructionCount, 1);
  assert.equal(truncated.bytesSampled, 4);
  assert.ok(truncated.issues.some(issue => /extends past end of file/.test(issue)));
  assert.equal(high.instructionCount, 1);
  assert.deepEqual(high.issues, []);
});

void test("AArch64 stops direct branches outside executable ranges", async () => {
  const file = aarch64Code([0x14000002]); // b +8, outside the four-byte segment.
  const report = await analyzeElfInstructionSets(file, aarch64Options(file.size));

  assert.equal(report.instructionCount, 1);
  assert.equal(report.bytesDecoded, 4);
  assert.equal(report.invalidInstructionCount, 0);
  assert.deepEqual(report.issues, []);
});
