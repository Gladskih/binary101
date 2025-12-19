"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ElfProgramHeader, ElfSectionHeader } from "../../analyzers/elf/types.js";
import { collectElfDisassemblySeedsFromEhFrameHdr } from "../../analyzers/elf/disassembly-seeds-eh-frame-hdr.js";
import { MockFile } from "../helpers/mock-file.js";

const ph = (overrides: Partial<ElfProgramHeader>): ElfProgramHeader =>
  ({
    type: 0,
    typeName: null,
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

void test("collectElfDisassemblySeedsFromEhFrameHdr reads start PCs from a simple .eh_frame_hdr", async () => {
  const bytes = new Uint8Array(32);
  const dv = new DataView(bytes.buffer);
  dv.setUint8(0, 1); // version
  dv.setUint8(1, 0x04); // eh_frame_ptr_enc: udata8
  dv.setUint8(2, 0x03); // fde_count_enc: udata4
  dv.setUint8(3, 0x04); // table_enc: udata8
  dv.setBigUint64(4, 0n, true); // eh_frame_ptr
  dv.setUint32(12, 1, true); // fde_count
  dv.setBigUint64(16, 0x2000n, true); // start_pc
  dv.setBigUint64(24, 0n, true); // fde_ptr (ignored)

  const file = new MockFile(bytes, "eh-frame-hdr.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromEhFrameHdr({
    file,
    programHeaders: [ph({ type: 0x6474e550, offset: 0n, vaddr: 0x5000n, filesz: 32n })],
    sections: [sec({ name: ".eh_frame_hdr" })],
    is64: true,
    littleEndian: true,
    issues
  });

  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0]?.vaddrs, [0x2000n]);
});

void test("collectElfDisassemblySeedsFromEhFrameHdr reports unexpected versions", async () => {
  const bytes = new Uint8Array(4);
  const dv = new DataView(bytes.buffer);
  dv.setUint8(0, 2); // version
  dv.setUint8(1, 0x04);
  dv.setUint8(2, 0x03);
  dv.setUint8(3, 0x04);

  const file = new MockFile(bytes, "eh-frame-hdr-v2.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromEhFrameHdr({
    file,
    programHeaders: [ph({ type: 0x6474e550, offset: 0n, vaddr: 0x5000n, filesz: 4n })],
    sections: [],
    is64: true,
    littleEndian: true,
    issues
  });

  assert.equal(groups.length, 0);
  assert.ok(issues.some(issue => issue.includes(".eh_frame_hdr has unexpected version 2.")));
});

void test("collectElfDisassemblySeedsFromEhFrameHdr supports omit/uleb128 and pcrel sdata4 start PCs", async () => {
  const bytes = new Uint8Array(16);
  const dv = new DataView(bytes.buffer);
  dv.setUint8(0, 1); // version
  dv.setUint8(1, 0xff); // eh_frame_ptr_enc: omit
  dv.setUint8(2, 0x01); // fde_count_enc: uleb128
  dv.setUint8(3, 0x1b); // table_enc: sdata4 | pcrel
  dv.setUint8(4, 1); // fde_count = 1 (uleb128)
  dv.setInt32(5, -0x3005, true); // start_pc => 0x2000 via pcrel
  dv.setInt32(9, 0, true); // fde_ptr (ignored)

  const file = new MockFile(bytes, "eh-frame-hdr-uleb.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromEhFrameHdr({
    file,
    programHeaders: [ph({ type: 0x6474e550, offset: 0n, vaddr: 0x5000n, filesz: 16n })],
    sections: [],
    is64: true,
    littleEndian: true,
    issues
  });

  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0]?.vaddrs, [0x2000n]);
});

void test("collectElfDisassemblySeedsFromEhFrameHdr locates .eh_frame_hdr via section headers", async () => {
  const bytes = new Uint8Array(20);
  const dv = new DataView(bytes.buffer);
  dv.setUint8(0, 1); // version
  dv.setUint8(1, 0x03); // eh_frame_ptr_enc: udata4
  dv.setUint8(2, 0x03); // fde_count_enc: udata4
  dv.setUint8(3, 0x03); // table_enc: udata4
  dv.setUint32(4, 0, true);
  dv.setUint32(8, 1, true);
  dv.setUint32(12, 0x2000, true); // start_pc
  dv.setUint32(16, 0, true);

  const file = new MockFile(bytes, "eh-frame-hdr-section.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromEhFrameHdr({
    file,
    programHeaders: [],
    sections: [sec({ name: ".eh_frame_hdr", offset: 0n, size: 20n, addr: 0x5000n })],
    is64: false,
    littleEndian: true,
    issues
  });

  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0]?.vaddrs, [0x2000n]);
});

void test("collectElfDisassemblySeedsFromEhFrameHdr rejects indirect encodings", async () => {
  const bytes = new Uint8Array(4);
  const dv = new DataView(bytes.buffer);
  dv.setUint8(0, 1); // version
  dv.setUint8(1, 0x80); // eh_frame_ptr_enc: indirect
  dv.setUint8(2, 0x03);
  dv.setUint8(3, 0x03);

  const file = new MockFile(bytes, "eh-frame-hdr-indirect.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromEhFrameHdr({
    file,
    programHeaders: [ph({ type: 0x6474e550, offset: 0n, vaddr: 0x5000n, filesz: 4n })],
    sections: [],
    is64: false,
    littleEndian: true,
    issues
  });

  assert.equal(groups.length, 0);
  assert.ok(issues.some(issue => issue.includes("unsupported eh_frame_ptr encoding")));
});

void test("collectElfDisassemblySeedsFromEhFrameHdr supports sleb128 sign extension", async () => {
  const bytes = new Uint8Array(8);
  const dv = new DataView(bytes.buffer);
  dv.setUint8(0, 1); // version
  dv.setUint8(1, 0xff); // eh_frame_ptr_enc: omit
  dv.setUint8(2, 0x01); // fde_count_enc: uleb128
  dv.setUint8(3, 0x19); // table_enc: sleb128 | pcrel
  dv.setUint8(4, 1); // fde_count
  dv.setUint8(5, 0x7f); // start_pc raw = -1 (sleb128)
  dv.setUint8(6, 0x00); // fde_ptr raw = 0

  const file = new MockFile(bytes, "eh-frame-hdr-sleb.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromEhFrameHdr({
    file,
    programHeaders: [ph({ type: 0x6474e550, offset: 0n, vaddr: 0x5000n, filesz: 8n })],
    sections: [],
    is64: false,
    littleEndian: true,
    issues
  });

  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0]?.vaddrs, [0x5004n]);
});

