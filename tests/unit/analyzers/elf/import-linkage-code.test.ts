import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86-disasm";
import { createElfImportCodeCollector } from "../../../../analyzers/elf/import-linkage-code.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { analyzeElfInstructionSets } from "../../../../analyzers/elf/disassembly.js";

const codeImage = () => {
  const { elf } = dynamicRelocationFixture();
  elf.importLinkage = { binding: "Lazy binding permitted", issues: [], links: [{
    relocationIndex: 0, kind: "GOT slot", loadSegments: [0], sections: [],
    relroSegments: [], issues: [] }] };
  elf.relocations = { tables: [], issues: [], entries: [{ tableIndex: 0, recordOffset: 0,
    type: 6, symbolIndex: 1, symbol: null, addend: 0n, target: null, offset: 0x2000n }] };
  return elf;
};

const collectInstructions = (bytes: number[], elf = codeImage()) => {
  const collector = createElfImportCodeCollector(iced, elf.importLinkage, elf.relocations);
  const decoder = new iced.Decoder(64, Uint8Array.from(bytes), iced.DecoderOptions.None);
  decoder.ip = 0x1000n;
  while (decoder.canDecode) {
    const instruction = decoder.decode();
    collector.record(instruction);
    instruction.free();
  }
  decoder.free();
  return collector.findings();
};

void test("connects direct calls and RIP-relative slot branches without executing code", () => {
  const { elf } = dynamicRelocationFixture();
  elf.importLinkage = { binding: "Lazy binding permitted", issues: [], links: [{
    relocationIndex: 0, kind: "PLT slot", loadSegments: [0], sections: [],
    relroSegments: [], issues: [] }] };
  elf.relocations = { tables: [], issues: [], entries: [{ tableIndex: 0, recordOffset: 0,
    type: 7, symbolIndex: 1, symbol: null, addend: 0n, target: null, offset: 0x2000n }] };
  const collector = createElfImportCodeCollector(iced, elf.importLinkage, elf.relocations);
  // CALL next instruction; JMP [RIP+disp32] to slot 0x2000. Intel SDM Vol. 2.
  const decoder = new iced.Decoder(64, Uint8Array.from([
    0xe8, 0, 0, 0, 0, 0xff, 0x25, 0xf5, 0x0f, 0, 0
  ]), iced.DecoderOptions.None);
  decoder.ip = 0x1000n;
  const call = decoder.decode();
  const jump = decoder.decode();
  collector.record(call);
  collector.record(jump);
  assert.deepEqual(collector.findings(), [{ slotAddress: 0x2000n, stubAddresses: [0x1005n],
    references: [
      { kind: "Indirect jump", count: 1, sampleAddresses: [0x1005n] },
      { kind: "Call to stub", count: 1, sampleAddresses: [0x1000n] }
    ] }]);
  call.free();
  jump.free();
  decoder.free();
});

void test("recognizes ENDBR landing pads and tail branches to decoded stubs", () => {
  // JMP to ENDBR64; JMP [RIP+0xff1] references 0x2000 at nextIP 0x100f.
  assert.deepEqual(collectInstructions([
    0xe9, 0, 0, 0, 0, 0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25, 0xf1, 0x0f, 0, 0
  ]), [{ slotAddress: 0x2000n, stubAddresses: [0x1009n, 0x1005n], references: [
    { kind: "Indirect jump", count: 1, sampleAddresses: [0x1009n] },
    { kind: "Jump to stub", count: 1, sampleAddresses: [0x1000n] }
  ] }]);
});

void test("combines calls to multiple stubs for one slot", () => {
  assert.deepEqual(collectInstructions([
    0xe8, 0, 0, 0, 0, 0xff, 0x25, 0xf5, 0x0f, 0, 0,
    0xe8, 0, 0, 0, 0, 0xff, 0x25, 0xea, 0x0f, 0, 0
  ]), [{ slotAddress: 0x2000n, stubAddresses: [0x1005n, 0x1010n], references: [
    { kind: "Indirect jump", count: 2, sampleAddresses: [0x1005n, 0x1010n] },
    { kind: "Call to stub", count: 2, sampleAddresses: [0x1000n, 0x100bn] }
  ] }]);
});

void test("counts indirect call sites with bounded samples and ignores register and TLS targets", () => {
  // Each CALL [RIP+disp32] has a different displacement to the same 0x2000 slot.
  assert.deepEqual(collectInstructions([
    0xff, 0x15, 0xfa, 0x0f, 0, 0,
    0xff, 0x15, 0xf4, 0x0f, 0, 0,
    0xff, 0x15, 0xee, 0x0f, 0, 0,
    0xff, 0x15, 0xe8, 0x0f, 0, 0
  ]), [{ slotAddress: 0x2000n, stubAddresses: [], references: [
    { kind: "Indirect call", count: 4, sampleAddresses: [0x1000n, 0x1006n, 0x100cn] }
  ] }]);
  assert.deepEqual(collectInstructions([0x64, 0xff, 0x15, 0xf9, 0x0f, 0, 0]), []);
  assert.deepEqual(collectInstructions([0x65, 0xff, 0x15, 0xf9, 0x0f, 0, 0]), []);
  assert.deepEqual(collectInstructions([0xff, 0xd0, 0xff, 0xe0]), []);
  assert.deepEqual(collectInstructions([0xff, 0x15, 0, 0, 0, 0]), []);
  assert.deepEqual(collectInstructions([0x0f]), []);
});

void test("does not collect evidence for absent, unmapped or generic relocation links", () => {
  const elf = codeImage();
  elf.importLinkage!.links[0]!.loadSegments = [];
  assert.deepEqual(collectInstructions([0xff, 0x15, 0xfa, 0x0f, 0, 0], elf), []);
  elf.importLinkage!.links[0]!.loadSegments = [0];
  elf.importLinkage!.links[0]!.kind = "Other symbol relocation";
  assert.deepEqual(collectInstructions([0xff, 0x15, 0xfa, 0x0f, 0, 0], elf), []);
  assert.deepEqual(createElfImportCodeCollector(iced).findings(), []);
});

void test("collects linkage during the existing ISA pass and skips unreachable instructions", async () => {
  const elf = codeImage();
  const bytes = Uint8Array.from([0xff, 0x15, 0xfa, 0x0f, 0, 0, 0xc3,
    0xff, 0x15, 0xf3, 0x0f, 0, 0]);
  const report = await analyzeElfInstructionSets(new File([bytes], "code.elf"), {
    machine: 62, fileType: 3, is64Bit: true, littleEndian: true,
    entrypointVaddr: 0x1000n, sections: [], importLinkage: elf.importLinkage!,
    relocations: elf.relocations!, programHeaders: [{ ...elf.programHeaders[0]!,
      flags: 5, filesz: BigInt(bytes.length), memsz: BigInt(bytes.length) }]
  });
  assert.deepEqual(report.importCode, [{ slotAddress: 0x2000n, stubAddresses: [], references: [
    { kind: "Indirect call", count: 1, sampleAddresses: [0x1000n] }
  ] }]);
});
