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
  if (rva >= 0x2000 && rva < 0x2004) return 0x40 + rva - 0x2000;
  return null;
};

const dataSection = (sizeOfRawData: number): PeSection => ({
  name: inlinePeSectionName(".rdata"),
  virtualSize: 4,
  virtualAddress: 0x2000,
  sizeOfRawData,
  pointerToRawData: 0x40,
  characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
});

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
