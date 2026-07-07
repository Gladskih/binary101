"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as realIced from "iced-x86";
import { createFileRangeReader } from "../../../../../../analyzers/file-range-reader.js";
import { analyzePeEntrypointDisassembly } from "../../../../../../analyzers/pe/disassembly/index.js";
import type { IcedModule } from "../../../../../../analyzers/pe/disassembly/entrypoint/iced.js";
import { inlinePeSectionName } from "../../../../../../analyzers/pe/sections/name.js";
import type { PeSection } from "../../../../../../analyzers/pe/types.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_I386,
  createExecutableSection
} from "../../../../../helpers/pe-entrypoint-disassembly-fixture.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

const realIcedModule = realIced as unknown as IcedModule;
// Microsoft PE section flags for initialized, readable data in synthetic fixtures.
const IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
const IMAGE_SCN_MEM_READ = 0x40000000;

const rvaToOff = (rva: number): number | null => {
  if (rva >= 0x1000 && rva < 0x1040) return rva - 0x1000;
  if (rva >= 0x2000 && rva < 0x2008) return 0x40 + rva - 0x2000;
  return null;
};

const dataSection = (sizeOfRawData: number): PeSection => ({
  name: inlinePeSectionName(".rdata"),
  virtualSize: sizeOfRawData,
  virtualAddress: 0x2000,
  sizeOfRawData,
  pointerToRawData: 0x40,
  characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
});

const findCodeTargetInstruction = (
  result: Awaited<ReturnType<typeof analyzePeEntrypointDisassembly>>,
  rva: number
) => result.blocks
  .flatMap(block => block.instructions)
  .find(instruction => instruction.target?.kind === "code" && instruction.target.rva === rva);

void test("analyzePeEntrypointDisassembly follows indirect jumps through image slots", async () => {
  const bytes = new Uint8Array(0x44);
  bytes.set([0xff, 0x25, 0x00, 0x20, 0x40, 0x00]);
  bytes.set([0x90, 0xc3], 0x10);
  bytes.set([0x10, 0x10, 0x40, 0x00], 0x40);
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(bytes, "indirect-memory-slot.exe"), 0, bytes.length),
    {
      coffMachine: IMAGE_FILE_MACHINE_I386,
      is64Bit: false,
      imageBase: 0x400000n,
      entrypointRva: 0x1000,
      rvaToOff,
      sections: [
        createExecutableSection({ virtualSize: 0x40, sizeOfRawData: 0x40 }),
        dataSection(4)
      ]
    },
    async () => realIcedModule
  );
  const target = result.blocks[0]?.instructions[0]?.target;

  assert.deepEqual(target, { kind: "code", rva: 0x1010, followed: true });
  assert.equal(result.blocks[1]?.kind, "followed-jump");
  assert.equal(result.blocks[1]?.startRva, 0x1010);
  assert.deepEqual(result.blocks[1]?.instructions.map(instruction => instruction.text), [
    "nop",
    "ret"
  ]);
});

void test("analyzePeEntrypointDisassembly follows RIP-relative indirect image slots", async () => {
  const bytes = new Uint8Array(0x48);
  bytes.set([0xff, 0x25, 0xfa, 0x0f, 0x00, 0x00]);
  bytes.set([0x90, 0xc3], 0x10);
  bytes.set([0x10, 0x10, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00], 0x40);
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(bytes, "rip-relative-indirect-slot.exe"), 0, bytes.length),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0x140000000n,
      entrypointRva: 0x1000,
      rvaToOff,
      sections: [
        createExecutableSection({ virtualSize: 0x40, sizeOfRawData: 0x40 }),
        dataSection(8)
      ]
    },
    async () => realIcedModule
  );
  const target = result.blocks[0]?.instructions[0]?.target;

  assert.deepEqual(target, { kind: "code", rva: 0x1010, followed: true });
  assert.equal(result.blocks[1]?.kind, "followed-jump");
  assert.equal(result.blocks[1]?.startRva, 0x1010);
});

void test("analyzePeEntrypointDisassembly ignores truncated indirect image slots", async () => {
  const bytes = new Uint8Array(0x42);
  bytes.set([0xff, 0x25, 0x00, 0x20, 0x40, 0x00]);
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(bytes, "truncated-indirect-memory-slot.exe"), 0, bytes.length),
    {
      coffMachine: IMAGE_FILE_MACHINE_I386,
      is64Bit: false,
      imageBase: 0x400000n,
      entrypointRva: 0x1000,
      rvaToOff,
      sections: [
        createExecutableSection({ virtualSize: 0x40, sizeOfRawData: 0x40 }),
        dataSection(4)
      ]
    },
    async () => realIcedModule
  );

  assert.equal(result.blocks[0]?.instructions[0]?.target, undefined);
  assert.ok(result.issues.some(issue => /stopped at control-flow instruction/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly reads mapped image memory during emulation", async () => {
  const bytes = new Uint8Array(0x44);
  bytes.set([0xa1, 0x00, 0x20, 0x40, 0x00]);
  bytes.set([0xa3, 0x00, 0x30, 0x40, 0x00], 0x05);
  bytes.set([0xff, 0x15, 0x00, 0x30, 0x40, 0x00], 0x0a);
  bytes.set([0x90, 0xc3], 0x30);
  bytes.set([0x30, 0x10, 0x40, 0x00], 0x40);
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(bytes, "image-memory-emulation.exe"), 0, bytes.length),
    {
      coffMachine: IMAGE_FILE_MACHINE_I386,
      is64Bit: false,
      imageBase: 0x400000n,
      entrypointRva: 0x1000,
      rvaToOff,
      sections: [
        createExecutableSection({ virtualSize: 0x40, sizeOfRawData: 0x40 }),
        dataSection(4)
      ]
    },
    async () => realIcedModule
  );
  const instruction = findCodeTargetInstruction(result, 0x1030);

  assert.deepEqual(instruction?.target, { kind: "code", rva: 0x1030, followed: true });
  assert.equal(result.blocks.some(block => block.startRva === 0x1030), true);
});

void test("analyzePeEntrypointDisassembly follows targets copied by rep movsd", async () => {
  const bytes = new Uint8Array(0x44);
  bytes.set([0xb8, 0x00, 0x20, 0x40, 0x00]);
  bytes.set([0xe8, 0x16, 0x00, 0x00, 0x00], 0x05);
  bytes.set([0xc3], 0x0a);
  bytes.set([0xbf, 0x00, 0x30, 0x40, 0x00], 0x20);
  bytes.set([0x89, 0xc6], 0x25);
  bytes.set([0xb9, 0x01, 0x00, 0x00, 0x00], 0x27);
  bytes.set([0xf3, 0xa5], 0x2c);
  bytes.set([0xff, 0x15, 0x00, 0x30, 0x40, 0x00], 0x2e);
  bytes.set([0xc3], 0x34);
  bytes.set([0x90, 0xc3], 0x38);
  bytes.set([0x38, 0x10, 0x40, 0x00], 0x40);
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(bytes, "rep-movsd-target.exe"), 0, bytes.length),
    {
      coffMachine: IMAGE_FILE_MACHINE_I386,
      is64Bit: false,
      imageBase: 0x400000n,
      entrypointRva: 0x1000,
      rvaToOff,
      sections: [
        createExecutableSection({ virtualSize: 0x40, sizeOfRawData: 0x40 }),
        dataSection(4)
      ]
    },
    async () => realIcedModule
  );
  const instruction = findCodeTargetInstruction(result, 0x1038);

  assert.deepEqual(instruction?.target, { kind: "code", rva: 0x1038, followed: true });
  assert.equal(result.blocks.some(block => block.startRva === 0x1038), true);
  assert.equal(result.issues.some(issue => /unknown indirect call/i.test(issue)), false);
});
