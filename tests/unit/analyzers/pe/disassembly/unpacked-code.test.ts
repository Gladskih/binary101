import assert from "node:assert/strict";
import { test } from "node:test";
import { IMAGE_FILE_MACHINE_I386 } from "../../../../../analyzers/coff/machine.js";
import { createMemoryRangeReader } from "../../../../../analyzers/memory-range-reader.js";
import { parseForUi } from "../../../../../analyzers/index.js";
import { isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { analyzePeInstructionSets } from "../../../../../analyzers/pe/disassembly/index.js";
import type { AnalyzePeInstructionSetOptions } from "../../../../../analyzers/pe/disassembly/types.js";
import { collectPeUnpackedCode, selectPeUnpackedCode }
  from "../../../../../analyzers/pe/disassembly/unpacked-code.js";
import { CRINKLER_30_PREFIX, CRINKLER_30_TINY } from "../../../../fixtures/crinkler-bytes.js";

const seedAddress = 0x2000;
const options = (): AnalyzePeInstructionSetOptions => ({
  coffMachine: IMAGE_FILE_MACHINE_I386,
  is64Bit: false,
  imageBase: 0x400000n,
  entrypointRva: 1,
  headerRvaLimit: 3,
  rvaToOff: rva => rva >= 1 && rva < 3 ? rva - 1 : null,
  sections: [],
  unpackedCode: {
    name: "Fixture",
    rvaStart: seedAddress,
    // vmovaps xmm1,xmm5 (AVX), then near RET. Intel SDM, Vol. 2, MOVAPS and RET.
    data: new Uint8Array([0xc5, 0xf8, 0x28, 0xcd, 0xc3])
  }
});

void test("ISA counts include reachable instructions from the file and unpacked seed", async () => {
  // NOP and RET in the file do not account for the AVX instruction.
  const reader = createMemoryRangeReader(new Uint8Array([0x90, 0xc3]));
  const report = await analyzePeInstructionSets(reader, options());

  assert.equal(report.instructionCount, 4);
  assert.equal(report.bytesDecoded, 7);
  assert.deepEqual(report.unpackedCode, { name: "Fixture", entrypointRva: seedAddress });
  assert.equal(report.instructionSets.find(set => set.id === "AVX")?.instructionCount, 1);
});

void test("ISA skips unpacked bytes that overlap a sampled file region", async () => {
  const opts = options();
  opts.unpackedCode = { ...opts.unpackedCode!, rvaStart: opts.entrypointRva };
  const reader = createMemoryRangeReader(new Uint8Array([0x90, 0xc3]));
  const report = await analyzePeInstructionSets(reader, opts);

  assert.equal(report.instructionCount, 2);
  assert.equal(report.unpackedCode, undefined);
  assert.match(report.issues.join(" "), /overlap/);
});

void test("ISA allows file samples adjacent to either end of the unpacked bytes", () => {
  const unpacked = options().unpackedCode!;
  const issues: string[] = [];
  const data = new Uint8Array(1);

  const selected = selectPeUnpackedCode(unpacked, [
    { rvaStart: unpacked.rvaStart - data.length, data },
    { rvaStart: unpacked.rvaStart + unpacked.data.length, data }
  ], issues);

  assert.equal(selected, unpacked);
  assert.deepEqual(issues, []);
});

void test("one overlapping range is sufficient to reject the unpacked sample", () => {
  const unpacked = options().unpackedCode!;
  const issues: string[] = [];
  const data = new Uint8Array(1);

  const selected = selectPeUnpackedCode(unpacked, [
    { rvaStart: unpacked.rvaStart - data.length, data },
    { rvaStart: unpacked.rvaStart, data }
  ], issues);

  assert.equal(selected, undefined);
  assert.match(issues.join(" "), /overlap/);
});

void test("ISA rejects an unpacked RVA range that wraps past the PE address space", async () => {
  const opts = options();
  // An RVA is a 32-bit address, and this sample is longer than one byte.
  opts.unpackedCode = { ...opts.unpackedCode!, rvaStart: 0xffff_ffff };
  const reader = createMemoryRangeReader(new Uint8Array([0x90, 0xc3]));
  const report = await analyzePeInstructionSets(reader, opts);

  assert.equal(report.instructionCount, 2);
  assert.equal(report.unpackedCode, undefined);
  assert.match(report.issues.join(" "), /outside the 32-bit RVA range/);
});

void test("unpacked instructions contribute ISA counts without creating file-backed links", async () => {
  const opts = options();
  opts.dataRvas = [seedAddress]; // A file data label does not describe unpacked memory.
  // CPUID followed by RET. The packed file still contains only NOP and RET.
  opts.unpackedCode = { ...opts.unpackedCode!, data: new Uint8Array([0x0f, 0xa2, 0xc3]) };
  const report = await analyzePeInstructionSets(
    createMemoryRangeReader(new Uint8Array([0x90, 0xc3])), opts);

  assert.equal(report.instructionCount, 4);
  assert.equal(report.specialInstructions.length, 0);
});

void test("accepts a verified complete Crinkler Tiny buffer and keeps its real destination RVA",
  async () => {
    const result = await parseForUi(new File([Buffer.from(CRINKLER_30_TINY, "hex")], "tiny.bin"));
    assert.equal(result.analyzer, "pe");
    assert.ok(result.parsed && isPeWindowsParseResult(result.parsed));

    const unpacked = collectPeUnpackedCode(result.parsed);

    assert.equal(unpacked?.imageBase, 0x400000n);
    assert.equal(unpacked?.code.rvaStart, 0x20000);
    assert.equal(unpacked?.code.data.length, 114);
    assert.equal(result.parsed.rvaToOff(0x20000), null);
  });

for (const [profile, input] of [
  ["standard", CRINKLER_30_PREFIX], ["incomplete tiny", CRINKLER_30_TINY.slice(0, -20)]
] as const) {
  void test(`only verified unpacked output supplies an ISA seed (${profile})`, async () => {
    const result = await parseForUi(new File([Buffer.from(input, "hex")], "packed.bin"));
    assert.equal(result.analyzer, "pe");
    assert.ok(result.parsed && isPeWindowsParseResult(result.parsed));

    assert.equal(collectPeUnpackedCode(result.parsed), null);
  });
}

void test("requires the decoded Crinkler buffer to match its declared output size", async () => {
  const result = await parseForUi(new File([Buffer.from(CRINKLER_30_TINY, "hex")], "tiny.bin"));
  assert.equal(result.analyzer, "pe");
  assert.ok(result.parsed && isPeWindowsParseResult(result.parsed));
  const finding = result.parsed.packers?.reports[0]?.findings[0];
  assert.ok(finding?.id === "crinkler" && finding.tiny);
  finding.tiny.size += 1;

  assert.equal(collectPeUnpackedCode(result.parsed), null);
});

void test("requires the entire decoded Crinkler buffer to fit in its image", async () => {
  const result = await parseForUi(new File([Buffer.from(CRINKLER_30_TINY, "hex")], "tiny.bin"));
  assert.equal(result.analyzer, "pe");
  assert.ok(result.parsed && isPeWindowsParseResult(result.parsed));
  const finding = result.parsed.packers?.reports[0]?.findings[0];
  assert.ok(finding?.id === "crinkler" && finding.decoded);
  const { imageBase, unpackedVa } = finding.layout;
  finding.layout.imageSize = unpackedVa - imageBase + finding.decoded.data.length - 1;

  assert.equal(collectPeUnpackedCode(result.parsed), null);
});
