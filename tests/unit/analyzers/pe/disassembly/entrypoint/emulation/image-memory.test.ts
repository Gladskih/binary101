"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { FileRangeReader } from "../../../../../../../analyzers/file-range-reader.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointInstruction
} from "../../../../../../../analyzers/pe/disassembly/index.js";
import {
  createEmulationState,
  emulateInstruction
} from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/index.js";
import {
  known,
  type EmulationState
} from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/state.js";
import {
  invalidateTouchedMemory,
  preloadImageMemoryForInstruction
} from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/image-memory.js";
import {
  fixtureIced,
  implicitMem,
  instruction as ins,
  mem,
  reg
} from "../../../../../../helpers/pe-entrypoint-emulation-fixture.js";
import { IMAGE_FILE_MACHINE_I386 } from "../../../../../../helpers/pe-entrypoint-disassembly-fixture.js";
import { inlinePeSectionName } from "../../../../../../../analyzers/pe/sections/name.js";
import type { PeSection } from "../../../../../../../analyzers/pe/types.js";

const IMAGE_BASE = 0x400000n;
const EMPTY_VIEW = new DataView(new ArrayBuffer(0));
const IMAGE_DWORD = 0x12345678n;
const ZERO_FILL_RVA = 0x3000;
const ZERO_FILL_RAW_SIZE = 0x10;
const ZERO_FILL_VIRTUAL_SIZE = 0x30;

const imageAddress = (rva: number): bigint => IMAGE_BASE + BigInt(rva);

const createReader = (bytes: Uint8Array): FileRangeReader => {
  const read = async (offset: number, size: number): Promise<DataView> => {
    if (offset < 0 || size <= 0 || offset >= bytes.length) return EMPTY_VIEW;
    return new DataView(
      bytes.buffer,
      bytes.byteOffset + offset,
      Math.min(size, bytes.length - offset)
    );
  };
  return {
    size: bytes.length,
    read,
    readBytes: async (offset, size) => {
      const view = await read(offset, size);
      return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    }
  };
};

const createOptions = (
  rvaToOff: AnalyzePeEntrypointDisassemblyOptions["rvaToOff"] = rva =>
    rva < 0x100 ? rva : null
): AnalyzePeEntrypointDisassemblyOptions => ({
  coffMachine: IMAGE_FILE_MACHINE_I386,
  is64Bit: false,
  imageBase: IMAGE_BASE,
  entrypointRva: 0x1000,
  rvaToOff,
  sections: []
});

const createZeroFilledSection = (overrides: Partial<PeSection> = {}): PeSection => ({
  name: inlinePeSectionName(".bss"),
  virtualSize: ZERO_FILL_VIRTUAL_SIZE,
  virtualAddress: ZERO_FILL_RVA,
  sizeOfRawData: ZERO_FILL_RAW_SIZE,
  pointerToRawData: 0,
  characteristics: 0,
  ...overrides
});

const renderedInstruction = (): PeEntrypointInstruction => ({
  rva: 0,
  fileOffset: 0,
  text: ""
});

const preload = async (
  bytes: Uint8Array,
  state: EmulationState,
  decoded: Parameters<typeof preloadImageMemoryForInstruction>[4],
  opts = createOptions()
): ReturnType<typeof preloadImageMemoryForInstruction> =>
  preloadImageMemoryForInstruction(createReader(bytes), opts, fixtureIced, state, decoded);

void test("preloadImageMemoryForInstruction makes mapped operands visible to emulation", async () => {
  const bytes = new Uint8Array(0x20);
  bytes.set([0x78, 0x56, 0x34, 0x12], 0x10);
  const state = createEmulationState(32);
  const decoded = ins("Mov", [reg("EAX"), mem("UInt32", undefined, imageAddress(0x10))]);

  await preload(bytes, state, decoded);
  assert.equal(emulateInstruction(fixtureIced, decoded, renderedInstruction(), state), true);

  assert.deepEqual(state.registers.get("RAX"), known(IMAGE_DWORD, 32));
});

void test("invalidateTouchedMemory removes transient image-backed operands", async () => {
  const bytes = new Uint8Array(0x20);
  bytes.set([0x78, 0x56, 0x34, 0x12], 0x10);
  const state = createEmulationState(32);
  const decoded = ins("Mov", [reg("EAX"), mem("UInt32", undefined, imageAddress(0x10))]);
  const preloaded = await preload(bytes, state, decoded);

  assert.deepEqual(state.memory.get(imageAddress(0x10).toString()), known(IMAGE_DWORD, 32));
  invalidateTouchedMemory(state, preloaded);

  assert.equal(state.memory.get(imageAddress(0x10).toString()), undefined);
});

void test("preloadImageMemoryForInstruction ignores truncated image operands", async () => {
  const bytes = new Uint8Array(0x12);
  bytes.set([0x78, 0x56], 0x10);
  const state = createEmulationState(32);
  const decoded = ins("Mov", [reg("EAX"), mem("UInt32", undefined, imageAddress(0x10))]);

  await preload(bytes, state, decoded);

  assert.equal(state.memory.get(imageAddress(0x10).toString()), undefined);
});

void test("preloadImageMemoryForInstruction reads PE zero-filled section tails", async () => {
  const state = createEmulationState(32);
  const address = imageAddress(ZERO_FILL_RVA + ZERO_FILL_RAW_SIZE + 4);
  const decoded = ins("Mov", [reg("EAX"), mem("UInt32", undefined, address)]);

  await preload(new Uint8Array(0), state, decoded, {
    ...createOptions(() => null),
    sections: [createZeroFilledSection()]
  });
  assert.equal(emulateInstruction(fixtureIced, decoded, renderedInstruction(), state), true);

  assert.deepEqual(state.registers.get("RAX"), known(0n, 32));
});

void test("preloadImageMemoryForInstruction does not zero-fill raw bytes with no offset", async () => {
  const state = createEmulationState(32);
  const decoded = ins("Mov", [
    reg("EAX"),
    mem("UInt32", undefined, imageAddress(ZERO_FILL_RVA + 4))
  ]);

  await preload(new Uint8Array(0), state, decoded, {
    ...createOptions(() => null),
    sections: [createZeroFilledSection()]
  });

  assert.equal(state.memory.get(imageAddress(ZERO_FILL_RVA + 4).toString()), undefined);
});

void test("preloadImageMemoryForInstruction ignores reads crossing into zero-fill", async () => {
  const state = createEmulationState(32);
  const address = imageAddress(ZERO_FILL_RVA + ZERO_FILL_RAW_SIZE - 2);
  const decoded = ins("Mov", [reg("EAX"), mem("UInt32", undefined, address)]);

  await preload(new Uint8Array(0), state, decoded, {
    ...createOptions(() => null),
    sections: [createZeroFilledSection()]
  });

  assert.equal(state.memory.get(address.toString()), undefined);
});

void test("preloadImageMemoryForInstruction makes mapped REP MOVS sources visible", async () => {
  const bytes = new Uint8Array(8);
  bytes.set([0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55]);
  const state = createEmulationState(32, { DF: false });
  const source = imageAddress(0x2000);
  const destination = imageAddress(0x3000);
  const decoded = ins("Movsd", [
    implicitMem("MemoryESEDI", "UInt32"),
    implicitMem("MemorySegESI", "UInt32")
  ], { repeatPrefix: "rep" });
  state.registers.set("RSI", known(source, 32));
  state.registers.set("RDI", known(destination, 32));
  state.registers.set("RCX", known(2n, 32));

  await preload(bytes, state, decoded, createOptions(rva =>
    rva >= 0x2000 && rva < 0x2008 ? rva - 0x2000 : null
  ));
  assert.equal(emulateInstruction(fixtureIced, decoded, renderedInstruction(), state), true);

  assert.deepEqual(state.memory.get(destination.toString()), known(0x11223344n, 32));
  assert.deepEqual(state.memory.get((destination + 4n).toString()), known(0x55667788n, 32));
});
