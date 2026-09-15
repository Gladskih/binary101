import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeInstructionSets } from "../../../../../analyzers/pe/disassembly/analyze.js";
import type { AnalyzePeInstructionSetOptions } from "../../../../../analyzers/pe/disassembly/types.js";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { aarch64Code } from "../../../../fixtures/aarch64-code.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import { analyzePeAarch64InstructionSets } from "../../../../../analyzers/pe/disassembly/aarch64.js";

const options = (size: number): AnalyzePeInstructionSetOptions => ({
  // Microsoft PE format: ARM64 = 0xaa64; IMAGE_SCN_MEM_EXECUTE = 0x20000000.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  coffMachine: 0xaa64, is64Bit: true, imageBase: 0x140000000n, entrypointRva: 0x1000,
  rvaToOff: rva => rva >= 0x1000 && rva < 0x1000 + size ? rva - 0x1000 : null,
  sections: [{ name: inlinePeSectionName(".text"), virtualAddress: 0x1000, virtualSize: size,
    sizeOfRawData: size, pointerToRawData: 0, characteristics: 0x20000000 }]
});

void test("PE ARM64 uses metadata seeds once", async () => {
  const file = aarch64Code([0xd65f03c0, 0x04a00000, 0xd65f03c0]);
  const opts = options(file.size);
  const report = await analyzePeInstructionSets(createFileRangeReader(file, 0, file.size), {
    ...opts, exportRvas: [0x1004], unwindBeginRvas: [0x1004], tlsCallbackRvas: [0x1004],
    extraEntrypoints: [{ source: "test", rvas: [0x1004] }]
  });

  assert.equal(report.instructionCount, 3);
  assert.equal(report.bytesDecoded, file.size);
});

void test("PE ARM64 stops at section boundaries without decoding file padding", async () => {
  const file = aarch64Code([0xd503201f, 0xd65f03c0]);
  const opts = options(file.size);
  opts.sections[0]!.virtualSize = 6;
  const report = await analyzePeInstructionSets(createFileRangeReader(file, 0, file.size), opts);

  assert.equal(report.instructionCount, 1);
  assert.equal(report.invalidInstructionCount, 1);
  assert.equal(report.bytesSampled, 6);
  assert.ok(report.issues.some(issue => /Truncated AArch64 instruction/.test(issue)));
});

void test("PE ARM64 clamps file truncation and reports inconsistent header bitness", async () => {
  const file = aarch64Code([0xd65f03c0]);
  const report = await analyzePeInstructionSets(createFileRangeReader(file, 0, file.size), {
    ...options(file.size + 4), is64Bit: false
  });

  assert.equal(report.instructionCount, 1);
  assert.equal(report.bitness, 64);
  assert.equal(report.bytesSampled, 4);
  assert.ok(report.issues.some(issue => /past end of file/.test(issue)));
  assert.ok(report.issues.some(issue => /32-bit/.test(issue)));
});

void test("PE ARM64 cancellation preserves partial results and survives UI exceptions", async () => {
  const file = aarch64Code([0xd503201f, 0xd65f03c0]);
  const controller = new AbortController();
  const stages: string[] = [];
  const report = await analyzePeInstructionSets(createFileRangeReader(file, 0, file.size), {
    ...options(file.size), signal: controller.signal, yieldEveryInstructions: 1,
    onProgress: progress => {
      stages.push(progress.stage);
      if (progress.instructionCount === 1) controller.abort();
      throw new Error("UI");
    }
  });

  assert.equal(report.instructionCount, 1);
  assert.ok(report.issues.includes("Disassembly cancelled."));
  assert.deepEqual(stages, ["loading", "decoding", "decoding", "done"]);
});

void test("PE ARM64 rejects a negative image base without throwing", async () => {
  const file = aarch64Code([0xd65f03c0]);
  const report = await analyzePeInstructionSets(createFileRangeReader(file, 0, file.size), {
    ...options(file.size), imageBase: -1n
  });

  assert.equal(report.instructionCount, 0);
  assert.ok(report.issues.some(issue => /ImageBase/.test(issue)));
});

void test("PE ARM64 follows branches and preserves alternative feature requirements", async () => {
  // b +8; unreachable invalid; SVE add; ret (encodings cited in aarch64-code fixture).
  const file = aarch64Code([0x14000002, 0xffffffff, 0x04a00000, 0xd65f03c0]);
  const report = await analyzePeInstructionSets(createFileRangeReader(file, 0, file.size),
    options(file.size), async () => { throw new Error("x86 decoder must not load"); });

  assert.equal(report.instructionCount, 3);
  assert.equal(report.bytesDecoded, 12);
  assert.equal(report.bytesSampled, file.size);
  assert.equal(report.invalidInstructionCount, 0);
  assert.equal(report.decoderVersion, "LLVM 21.1.8");
  assert.ok(report.instructionSets.some(set => /FEAT_SVE or FEAT_SME/.test(set.label)));
  assert.deepEqual(report.issues, []);
});

for (const field of ["pointerToRawData", "virtualSize", "virtualAddress", "sizeOfRawData"] as const) {
  for (const invalid of [-1, NaN, 1.5, 0x1_0000_0000]) {
    void test(`PE ARM64 rejects invalid ${field}: ${invalid}`, async () => {
      const file = aarch64Code([0xd65f03c0]);
      const opts = options(file.size);
      opts.sections[0]![field] = invalid;
      const report = await analyzePeAarch64InstructionSets(
        createFileRangeReader(file, 0, file.size), opts);

      assert.equal(report.bytesSampled, 0);
      assert.equal(report.instructionCount, 0);
      assert.ok(report.issues.some(issue => /out-of-bounds/.test(issue)));
    });
  }
}

void test("PE ARM64 rejects overflowing RVA ranges and file offsets past EOF", async () => {
  const file = aarch64Code([0xd65f03c0]);
  const opts = options(file.size);
  const section = opts.sections[0]!;
  opts.sections = [{ ...section, virtualAddress: 0xffff_fffe },
    { ...section, pointerToRawData: file.size + 1 }];
  const report = await analyzePeAarch64InstructionSets(createFileRangeReader(file, 0, file.size), opts);

  assert.equal(report.bytesSampled, 0);
  assert.equal(report.issues.filter(issue => /out-of-bounds/.test(issue)).length, 2);
});

void test("PE ARM64 rejects non-executable, empty and unavailable sections", async () => {
  const file = aarch64Code([0xd65f03c0]);
  const opts = options(file.size);
  const section = opts.sections[0]!;
  opts.sections = [{ ...section, characteristics: 0 }, { ...section, sizeOfRawData: 0 },
    { ...section, pointerToRawData: file.size }];
  const report = await analyzePeAarch64InstructionSets(createFileRangeReader(file, 0, file.size), opts);

  assert.equal(report.bytesSampled, 0);
  assert.ok(report.issues.includes("No executable bytes available for AArch64 disassembly."));
});

void test("PE ARM64 accepts raw size fallback and nonzero raw offsets", async () => {
  const file = aarch64Code([0xffffffff, 0xd65f03c0]);
  const opts = options(4);
  opts.sections[0]!.pointerToRawData = 4;
  opts.sections[0]!.virtualSize = 0;
  opts.rvaToOff = () => 4;
  const report = await analyzePeAarch64InstructionSets(createFileRangeReader(file, 0, file.size), opts);

  assert.equal(report.instructionCount, 1);
  assert.equal(report.bytesSampled, 4);
  assert.deepEqual(report.issues, []);
});

void test("PE ARM64 catches code read failures and always reports completion", async () => {
  const stages: string[] = [];
  const report = await analyzePeAarch64InstructionSets({ size: 4,
    read: async () => { throw new Error("read"); },
    readBytes: async () => { throw new Error("read bytes"); }
  }, { ...options(4), onProgress: progress => stages.push(progress.stage) });

  assert.equal(report.instructionCount, 0);
  assert.ok(report.issues.some(issue => /AArch64 disassembly failed.*read bytes/.test(issue)));
  assert.deepEqual(stages, ["loading", "decoding", "done"]);
});

void test("PE ARM64 honours pre-cancellation before reading code", async () => {
  const controller = new AbortController();
  const stages: string[] = [];
  controller.abort();
  const report = await analyzePeAarch64InstructionSets({ size: 4,
    read: async () => { throw new Error("unexpected read"); },
    readBytes: async () => { throw new Error("unexpected read"); }
  }, { ...options(4), signal: controller.signal,
    onProgress: progress => stages.push(progress.stage) });

  assert.deepEqual(report.issues, ["Disassembly cancelled."]);
  assert.deepEqual(stages, ["loading", "done"]);
});

for (const branch of [0x17ffffff, 0x14000001]) {
  void test(`PE ARM64 never reads outside code for branch ${branch}`, async () => {
    // A64 B immediate: signed imm26 scaled by four, here -4 and +4.
    // https://github.com/llvm/llvm-project/blob/llvmorg-21.1.8/llvm/lib/Target/AArch64/AArch64InstrFormats.td
    const file = aarch64Code([branch]);
    const reader = createFileRangeReader(file, 0, file.size);
    const reads: number[][] = [];
    const report = await analyzePeAarch64InstructionSets({ ...reader,
      readBytes: async (offset, size) => {
        reads.push([offset, size]);
        return reader.readBytes(offset, size);
      }
    }, options(file.size));

    assert.deepEqual(reads, [[0, 4]]);
    assert.equal(report.instructionCount, 1);
    assert.deepEqual(report.issues, []);
  });
}

void test("PE ARM64 accepts the last four RVA bytes and image base zero", async () => {
  const file = aarch64Code([0xd65f03c0]);
  const opts = options(file.size);
  opts.imageBase = 0n;
  opts.entrypointRva = 0xffff_fffc;
  opts.sections[0]!.virtualAddress = opts.entrypointRva;
  opts.rvaToOff = () => 0;
  const report = await analyzePeAarch64InstructionSets(createFileRangeReader(file, 0, file.size), opts);

  assert.equal(report.instructionCount, 1);
  assert.deepEqual(report.issues, []);
});

void test("PE ARM64 samples multiple executable sections independently", async () => {
  const file = aarch64Code([0xd65f03c0, 0xd65f03c0]);
  const opts = options(4);
  opts.sections.push({ ...opts.sections[0]!, virtualAddress: 0x2000, pointerToRawData: 4 });
  opts.exportRvas = [0x2000];
  opts.rvaToOff = rva => rva === 0x2000 ? 4 : 0;
  const report = await analyzePeAarch64InstructionSets(createFileRangeReader(file, 0, file.size), opts);

  assert.equal(report.instructionCount, 2);
  assert.equal(report.bytesSampled, 8);
  assert.deepEqual(report.issues, []);
});

void test("PE ARM64 rejects an image base above 64 bits", async () => {
  const file = aarch64Code([0xd65f03c0]);
  const report = await analyzePeAarch64InstructionSets(createFileRangeReader(file, 0, file.size), {
    ...options(file.size), imageBase: 0x1_0000_0000_0000_0000n
  });

  assert.equal(report.instructionCount, 0);
  assert.deepEqual(report.issues, ["ImageBase is outside the 64-bit address range."]);
});

void test("PE ARM64 rejects unaligned seeds and stops branches outside executable bytes", async () => {
  const file = aarch64Code([0x14000002]); // b +8, outside this four-byte section.
  const report = await analyzePeAarch64InstructionSets(createFileRangeReader(file, 0, file.size), {
    ...options(file.size), exportRvas: [0x1001]
  });

  assert.equal(report.instructionCount, 1);
  assert.ok(report.issues.some(issue => /unaligned/.test(issue)));
});

void test("PE ARM64 visibly skips mapped seeds outside executable raw bytes", async () => {
  const file = aarch64Code([0xd65f03c0]);
  const opts = options(file.size);
  const report = await analyzePeAarch64InstructionSets(createFileRangeReader(file, 0, file.size), {
    ...opts, exportRvas: [0x100], rvaToOff: () => 0
  });

  assert.equal(report.instructionCount, 1);
  assert.ok(report.issues.some(issue => /0x100.*executable.*bytes/.test(issue)));
});

void test("PE ARM64 reuses file windows for descending function seeds", async () => {
  // RET encoding: LLVM AArch64 RET in aarch64-code.ts. Span three 64 KiB windows.
  const file = aarch64Code(Array.from({ length: 49152 }, () => 0xd65f03c0));
  const opts = options(file.size);
  const reads: number[][] = [];
  const trackedFile = { size: file.size, slice: (start: number, end: number) => {
    reads.push([start, end]);
    return file.slice(start, end);
  } } as File;

  const report = await analyzePeAarch64InstructionSets(
    createFileRangeReader(trackedFile, 0, file.size), {
      ...opts, exportRvas: [0x1004, 0x1008, 0x10000, 0x11000, 0x11004]
    });

  assert.equal(report.instructionCount, 6);
  assert.deepEqual(report.issues, []);
  assert.deepEqual(reads, [[61440, 126976], [0, 65536]]);
});

void test("PE ARM64 page reads preserve words in unaligned sections and truncated tails", async () => {
  // NOP; RET, with the final RET truncated. Encodings: aarch64-code.ts.
  const file = new File([new Uint8Array(3), aarch64Code([0xd503201f, 0xd65f03c0]).data
    .slice(0, 7)], "unaligned.exe");
  const opts = options(file.size);
  opts.sections[0]!.virtualAddress = 0xfff9;
  opts.entrypointRva = 0xfffc;
  opts.rvaToOff = rva => rva - 0xfff9;
  const reader = createFileRangeReader(file, 0, file.size);
  const reads: number[][] = [];

  const report = await analyzePeAarch64InstructionSets({ ...reader,
    readBytes: async (offset, size) => {
      reads.push([offset, size]);
      return reader.readBytes(offset, size);
    }
  }, opts);

  assert.equal(report.instructionCount, 1);
  assert.equal(report.invalidInstructionCount, 1);
  assert.deepEqual(reads, [[0, 7], [7, 3]]);
  assert.deepEqual(report.issues, ["Truncated AArch64 instruction at 0x140010000."]);
});
