"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import {
  analyzePeEntrypointDisassembly,
  type PeEntrypointInstructionTarget
} from "../../analyzers/pe/disassembly/index.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  IMAGE_FILE_MACHINE_I386,
  createExecutableSection
} from "../helpers/pe-entrypoint-disassembly-fixture.js";

const assertKnownReturnTarget = (
  target: PeEntrypointInstructionTarget | undefined
): Extract<PeEntrypointInstructionTarget, { kind: "return"; rva: number }> => {
  assert.equal(target?.kind, "return");
  assert.ok(target && "rva" in target);
  return target;
};

const analyzeRealEntrypoint = (bytes: Uint8Array) =>
  analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(bytes, "entry.exe"), 0, bytes.length),
    {
      coffMachine: IMAGE_FILE_MACHINE_I386,
      is64Bit: false,
      imageBase: 0n,
      entrypointRva: 0x1000,
      headerRvaLimit: 0x400,
      rvaToOff: rva => rva - 0x1000,
      sections: [createExecutableSection({ virtualSize: bytes.length, sizeOfRawData: bytes.length })]
    },
    async () => iced
  );

void test("analyzePeEntrypointDisassembly follows a return address changed on the stack", async () => {
  const bytes = new Uint8Array([
    0xe8, 0x02, 0x00, 0x00, 0x00,
    0x90,
    0xcc,
    0xc7, 0x04, 0x24, 0x0f, 0x10, 0x00, 0x00,
    0xc3,
    0xc3
  ]);
  const result = await analyzeRealEntrypoint(bytes);
  const returnTarget = result.blocks[1]?.instructions.at(-1)?.target;

  assert.equal(result.blocks.length, 3);
  assert.equal(result.blocks[1]?.kind, "followed-call");
  assert.equal(result.blocks[1]?.startRva, 0x1007);
  assert.equal(result.blocks[2]?.kind, "followed-return");
  assert.equal(result.blocks[2]?.startRva, 0x100f);
  assert.equal(assertKnownReturnTarget(returnTarget).rva, 0x100f);
  assert.ok(!result.blocks.some(block => block.startRva === 0x1005));
});

void test("analyzePeEntrypointDisassembly keeps separate return contexts for one callee", async () => {
  const bytes = new Uint8Array([
    0xe8, 0x0b, 0x00, 0x00, 0x00,
    0x90,
    0xe8, 0x05, 0x00, 0x00, 0x00,
    0xc3,
    0x90, 0x90, 0x90, 0x90,
    0xc3
  ]);
  const result = await analyzeRealEntrypoint(bytes);
  const calleeBlocks = result.blocks.filter(block => block.kind === "followed-call");

  assert.equal(calleeBlocks.length, 2);
  assert.deepEqual(calleeBlocks.map(block => block.sourceInstructionRva), [0x1000, 0x1006]);
  assert.ok(result.blocks.some(block => block.kind === "followed-return" && block.startRva === 0x100b));
});
