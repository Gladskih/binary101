"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeElfInstructionSets } from "../../analyzers/elf/disassembly.js";
import type { ElfProgramHeader, ElfSectionHeader } from "../../analyzers/elf/types.js";
import { MockFile } from "../helpers/mock-file.js";

const ph = (overrides: Partial<ElfProgramHeader>): ElfProgramHeader =>
  ({
    type: 1,
    typeName: "PT_LOAD",
    offset: 0n,
    vaddr: 0n,
    paddr: 0n,
    filesz: 0n,
    memsz: 0n,
    flags: 0,
    flagNames: [],
    align: 0n,
    index: 0,
    ...overrides
  }) as unknown as ElfProgramHeader;

const sec = (overrides: Partial<ElfSectionHeader>): ElfSectionHeader =>
  ({
    nameOff: 0,
    type: 1,
    typeName: null,
    flags: 0n,
    flagNames: [],
    addr: 0n,
    offset: 0n,
    size: 0n,
    link: 0,
    info: 0,
    addralign: 0n,
    entsize: 0n,
    index: 0,
    ...overrides
  }) as unknown as ElfSectionHeader;

const buildTwoExecSegments = (): ElfProgramHeader[] => [
  ph({ index: 0, type: 1, flags: 0x1, vaddr: 0x1000n, offset: 0x0n, filesz: 1n, memsz: 1n }),
  ph({ index: 1, type: 1, flags: 0x1, vaddr: 0x2000n, offset: 0x100n, filesz: 4n, memsz: 4n })
];

void test("analyzeElfInstructionSets seeds from SHT_INIT_ARRAY when entrypoint is zero", async () => {
  const bytes = new Uint8Array(0x208);
  bytes[0x00] = 0x00; // invalid
  bytes.set([0xc5, 0xf8, 0x28, 0xcd], 0x100); // vmovaps xmm1,xmm5 (AVX)
  new DataView(bytes.buffer).setBigUint64(0x200, 0x2000n, true);
  const file = new MockFile(bytes, "seed-init-array.bin");

  const report = await analyzeElfInstructionSets(file, {
    machine: 62,
    is64Bit: true,
    littleEndian: true,
    entrypointVaddr: 0n,
    programHeaders: buildTwoExecSegments(),
    sections: [sec({ index: 1, name: ".init_array", type: 14, offset: 0x200n, size: 8n })]
  });

  const ids = new Set(report.instructionSets.map(set => set.id));
  assert.ok(ids.has("AVX"));
  assert.ok(!report.issues.some(issue => issue.toLowerCase().includes("falling back")));
});

void test("analyzeElfInstructionSets seeds from SHT_DYNSYM STT_FUNC symbols when entrypoint is zero", async () => {
  const bytes = new Uint8Array(0x220);
  bytes[0x00] = 0x00; // invalid
  bytes.set([0xc5, 0xf8, 0x28, 0xcd], 0x100); // vmovaps xmm1,xmm5 (AVX)
  const dynsym = new DataView(bytes.buffer, 0x200, 24);
  dynsym.setUint8(4, 0x12); // STT_FUNC
  dynsym.setUint16(6, 1, true); // defined
  dynsym.setBigUint64(8, 0x2000n, true); // st_value
  const file = new MockFile(bytes, "seed-dynsym.bin");

  const report = await analyzeElfInstructionSets(file, {
    machine: 62,
    is64Bit: true,
    littleEndian: true,
    entrypointVaddr: 0n,
    programHeaders: buildTwoExecSegments(),
    sections: [sec({ index: 1, name: ".dynsym", type: 11, offset: 0x200n, size: 24n, entsize: 24n })]
  });

  const ids = new Set(report.instructionSets.map(set => set.id));
  assert.ok(ids.has("AVX"));
  assert.ok(!report.issues.some(issue => issue.toLowerCase().includes("falling back")));
});

void test("analyzeElfInstructionSets seeds from DT_INIT_ARRAY pointers when entrypoint is zero", async () => {
  const bytes = new Uint8Array(0x260);
  bytes[0x00] = 0x00; // invalid
  bytes.set([0xc5, 0xf8, 0x28, 0xcd], 0x100); // vmovaps xmm1,xmm5 (AVX)
  new DataView(bytes.buffer).setBigUint64(0x200, 0x2000n, true); // init array[0]

  const dyn = new DataView(bytes.buffer, 0x220, 0x30);
  dyn.setBigInt64(0x00, 25n, true); // DT_INIT_ARRAY
  dyn.setBigUint64(0x08, 0x3000n, true);
  dyn.setBigInt64(0x10, 27n, true); // DT_INIT_ARRAYSZ
  dyn.setBigUint64(0x18, 8n, true);
  dyn.setBigInt64(0x20, 0n, true); // DT_NULL
  dyn.setBigUint64(0x28, 0n, true);

  const file = new MockFile(bytes, "seed-dt-init-array.bin");
  const report = await analyzeElfInstructionSets(file, {
    machine: 62,
    is64Bit: true,
    littleEndian: true,
    entrypointVaddr: 0n,
    programHeaders: [
      ...buildTwoExecSegments(),
      ph({ index: 2, type: 1, flags: 0, vaddr: 0x3000n, offset: 0x200n, filesz: 8n, memsz: 8n }),
      ph({ index: 3, type: 2, flags: 0, vaddr: 0x5000n, offset: 0x220n, filesz: 0x30n, memsz: 0x30n })
    ],
    sections: []
  });

  const ids = new Set(report.instructionSets.map(set => set.id));
  assert.ok(ids.has("AVX"));
  assert.ok(!report.issues.some(issue => issue.toLowerCase().includes("falling back")));
});

void test("analyzeElfInstructionSets seeds from .eh_frame_hdr start PCs when entrypoint is zero", async () => {
  const bytes = new Uint8Array(0x240);
  bytes[0x00] = 0x00; // invalid
  bytes.set([0xc5, 0xf8, 0x28, 0xcd], 0x100); // vmovaps xmm1,xmm5 (AVX)

  const eh = new DataView(bytes.buffer, 0x200, 32);
  eh.setUint8(0, 1); // version
  eh.setUint8(1, 0x04); // eh_frame_ptr_enc: udata8
  eh.setUint8(2, 0x03); // fde_count_enc: udata4
  eh.setUint8(3, 0x04); // table_enc: udata8
  eh.setBigUint64(4, 0n, true); // eh_frame_ptr
  eh.setUint32(12, 1, true); // fde_count
  eh.setBigUint64(16, 0x2000n, true); // start_pc
  eh.setBigUint64(24, 0n, true); // fde_ptr

  const file = new MockFile(bytes, "seed-eh-frame-hdr.bin");
  const report = await analyzeElfInstructionSets(file, {
    machine: 62,
    is64Bit: true,
    littleEndian: true,
    entrypointVaddr: 0n,
    programHeaders: [
      ...buildTwoExecSegments(),
      ph({ index: 2, type: 0x6474e550, flags: 0, vaddr: 0x5000n, offset: 0x200n, filesz: 32n, memsz: 32n })
    ],
    sections: []
  });

  const ids = new Set(report.instructionSets.map(set => set.id));
  assert.ok(ids.has("AVX"));
  assert.ok(!report.issues.some(issue => issue.toLowerCase().includes("falling back")));
});

