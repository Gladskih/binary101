"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { IcedInstructionObject } from "../../../../../../../analyzers/pe/disassembly/entrypoint/iced.js";
import { createEmulationState } from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/index.js";
import type { CanonicalRegister } from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/registers.js";
import { executeStringInstruction } from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/strings.js";
import {
  emulateFixtures, fixtureIced, imm, implicitMem, instruction as ins, mem, reg
} from "../../../../../../helpers/pe-entrypoint-emulation-fixture.js";
import {
  bitsOf, bytesOf, distantFixtureDestination, fixtureAddressPair,
  fixtureAddressPairRequiring32BitPointers, fixtureValue, highFixtureAddressPair,
  sparseElementCount
} from "../../../../../../helpers/pe-entrypoint-emulation-values.js";

type StringMnemonic = Extract<Parameters<typeof ins>[0], "Movsb" | "Movsw" | "Movsd" | "Movsq">;
type StringMemoryKind = Parameters<typeof implicitMem>[0];
type StringMemorySize = Parameters<typeof implicitMem>[1];
type RegisterName = Parameters<typeof reg>[0];
type KnownBits = 8 | 16 | 32 | 64;

// 64-bit mode makes MOVS use RSI/RDI/RCX unless a test explicitly passes 32-bit mode.
const createX64State = () => createEmulationState(64);

const emulateInstructionsWithState = (
  instructions: readonly IcedInstructionObject[],
  bitness: 32 | 64 = 64
): ReturnType<typeof emulateFixtures>["state"] => emulateFixtures(instructions, bitness).state;

const stringMove = (
  mnemonic: StringMnemonic,
  destination: StringMemoryKind,
  source: StringMemoryKind,
  size: StringMemorySize,
  spec: Parameters<typeof ins>[2] = {}
): IcedInstructionObject =>
  ins(mnemonic, [implicitMem(destination, size), implicitMem(source, size)], spec);

const repeatedStringMove = (
  mnemonic: StringMnemonic,
  destination: StringMemoryKind,
  source: StringMemoryKind,
  size: StringMemorySize
): IcedInstructionObject =>
  stringMove(mnemonic, destination, source, size, { repeatPrefix: "rep" });

const moveImmediate = (
  register: RegisterName,
  value: bigint,
  opKind: Parameters<typeof imm>[1] = "Immediate32"
): IcedInstructionObject => ins("Mov", [reg(register), imm(value, opKind)]);

const storeRegister = (
  size: Parameters<typeof mem>[0],
  base: RegisterName,
  register: RegisterName,
  displacement = 0n
): IcedInstructionObject => ins("Mov", [mem(size, base, displacement), reg(register)]);

const expectKnownMemory = (
  state: ReturnType<typeof emulateInstructionsWithState>,
  address: bigint,
  value: bigint,
  bits: KnownBits
): void => {
  assert.deepEqual(state.memory.get(address.toString()), { kind: "known", value, bits });
};

const expectKnownRegister = (
  state: ReturnType<typeof emulateInstructionsWithState>,
  register: CanonicalRegister,
  value: bigint,
  bits: KnownBits
): void => {
  assert.deepEqual(state.registers.get(register), { kind: "known", value, bits });
};

void test("executeStringInstruction ignores non-string operands", () => {
  const state = createX64State();

  assert.equal(
    executeStringInstruction(
      fixtureIced,
      state,
      moveImmediate("EAX", fixtureValue(1, bitsOf("UInt32")))
    ),
    false
  );
  assert.equal(executeStringInstruction(
    fixtureIced,
    state,
    ins("Movsd", [mem("UInt32", "RDI"), mem("UInt32", "RSI")])
  ), false);
});

void test("executeStringInstruction reports handled string moves", () => {
  const state = createX64State();

  assert.equal(executeStringInstruction(
    fixtureIced,
    state,
    stringMove("Movsb", "MemoryESRDI", "MemorySegRSI", "UInt8")
  ), true);
});

void test("emulateInstruction copies one dword string move without REP", () => {
  const pointers = fixtureAddressPair();
  const counter = fixtureValue(1, bitsOf("UInt32"));
  const value = fixtureValue(2, bitsOf("UInt32"));
  const state = emulateInstructionsWithState([
    moveImmediate("RSI", pointers.source),
    moveImmediate("RDI", pointers.destination),
    moveImmediate("ECX", counter),
    moveImmediate("EAX", value),
    storeRegister("UInt32", "RSI", "EAX"),
    ins("Cld"),
    stringMove("Movsd", "MemoryESRDI", "MemorySegRSI", "UInt32")
  ]);

  expectKnownMemory(state, pointers.destination, value, bitsOf("UInt32"));
  expectKnownRegister(state, "RSI", pointers.source + bytesOf("UInt32"), bitsOf("UInt64"));
  expectKnownRegister(state, "RDI", pointers.destination + bytesOf("UInt32"), bitsOf("UInt64"));
  expectKnownRegister(state, "RCX", counter, bitsOf("UInt64"));
});

void test("emulateInstruction copies repeated dword string moves when DF is clear", () => {
  const { source, destination } = highFixtureAddressPair();
  const firstValue = fixtureValue(3, bitsOf("UInt32"));
  const secondValue = fixtureValue(4, bitsOf("UInt32"));
  // Two elements are the minimal repeated MOVS case that proves the second cell is copied.
  const count = 2n;
  const state = emulateInstructionsWithState([
    moveImmediate("RSI", source, "Immediate64"),
    moveImmediate("RDI", destination, "Immediate64"),
    moveImmediate("ECX", count),
    moveImmediate("EAX", firstValue),
    storeRegister("UInt32", "RSI", "EAX"),
    moveImmediate("EAX", secondValue),
    storeRegister("UInt32", "RSI", "EAX", bytesOf("UInt32")),
    ins("Cld"),
    repeatedStringMove("Movsd", "MemoryESRDI", "MemorySegRSI", "UInt32")
  ]);

  expectKnownMemory(state, destination, firstValue, bitsOf("UInt32"));
  expectKnownMemory(state, destination + bytesOf("UInt32"), secondValue, bitsOf("UInt32"));
  expectKnownRegister(state, "RSI", source + count * bytesOf("UInt32"), bitsOf("UInt64"));
  expectKnownRegister(state, "RDI", destination + count * bytesOf("UInt32"), bitsOf("UInt64"));
  expectKnownRegister(state, "RCX", 0n, bitsOf("UInt64"));
});

void test("emulateInstruction copies repeated dword string moves backward when DF is set", () => {
  const pointers = fixtureAddressPair();
  const source = pointers.source + bytesOf("UInt32");
  const destination = pointers.destination + bytesOf("UInt32");
  const firstValue = fixtureValue(5, bitsOf("UInt32"));
  const secondValue = fixtureValue(6, bitsOf("UInt32"));
  // Two elements are the minimal case that proves DF decrements before the next copy.
  const count = 2n;
  const state = emulateInstructionsWithState([
    moveImmediate("RSI", source),
    moveImmediate("RDI", destination),
    moveImmediate("ECX", count),
    moveImmediate("EAX", firstValue),
    storeRegister("UInt32", "RSI", "EAX"),
    moveImmediate("EAX", secondValue),
    storeRegister("UInt32", "RSI", "EAX", -bytesOf("UInt32")),
    ins("Std"),
    repeatedStringMove("Movsd", "MemoryESRDI", "MemorySegRSI", "UInt32")
  ]);

  expectKnownMemory(state, destination, firstValue, bitsOf("UInt32"));
  expectKnownMemory(state, destination - bytesOf("UInt32"), secondValue, bitsOf("UInt32"));
  expectKnownRegister(state, "RSI", pointers.source - bytesOf("UInt32"), bitsOf("UInt64"));
  expectKnownRegister(state, "RDI", pointers.destination - bytesOf("UInt32"), bitsOf("UInt64"));
  expectKnownRegister(state, "RCX", 0n, bitsOf("UInt64"));
});

void test("emulateInstruction handles 32-bit address-size repeated string moves", () => {
  const pointers = fixtureAddressPairRequiring32BitPointers();
  const value = fixtureValue(7, bitsOf("UInt32"));
  const state = emulateInstructionsWithState([
    moveImmediate("ESI", pointers.source),
    moveImmediate("EDI", pointers.destination),
    moveImmediate("ECX", 1n),
    moveImmediate("EAX", value),
    storeRegister("UInt32", "ESI", "EAX"),
    ins("Cld"),
    repeatedStringMove("Movsd", "MemoryESEDI", "MemorySegESI", "UInt32")
  ], 32);

  expectKnownMemory(state, pointers.destination, value, bitsOf("UInt32"));
  expectKnownRegister(state, "RSI", pointers.source + bytesOf("UInt32"), bitsOf("UInt32"));
  expectKnownRegister(state, "RDI", pointers.destination + bytesOf("UInt32"), bitsOf("UInt32"));
  expectKnownRegister(state, "RCX", 0n, bitsOf("UInt32"));
});

void test("emulateInstruction handles 16-bit address-size repeated string moves", () => {
  const pointers = fixtureAddressPair();
  const value = fixtureValue(8, bitsOf("UInt16"));
  const state = emulateInstructionsWithState([
    moveImmediate("ESI", pointers.source),
    moveImmediate("EDI", pointers.destination),
    moveImmediate("ECX", 1n),
    moveImmediate("EAX", value),
    storeRegister("UInt16", "ESI", "AX"),
    ins("Cld"),
    repeatedStringMove("Movsw", "MemoryESDI", "MemorySegSI", "UInt16")
  ], 32);

  expectKnownMemory(state, pointers.destination, value, bitsOf("UInt16"));
  expectKnownRegister(state, "RSI", pointers.source + bytesOf("UInt16"), bitsOf("UInt32"));
  expectKnownRegister(state, "RDI", pointers.destination + bytesOf("UInt16"), bitsOf("UInt32"));
  expectKnownRegister(state, "RCX", 0n, bitsOf("UInt32"));
});

void test("emulateInstruction handles byte and qword string move sizes", () => {
  const bytePointers = fixtureAddressPair();
  const qwordPointers = fixtureAddressPair(1);
  const byteValue = fixtureValue(9, bitsOf("UInt8"));
  const qwordValue = fixtureValue(10, bitsOf("UInt64"));
  const byteState = emulateInstructionsWithState([
    moveImmediate("RSI", bytePointers.source),
    moveImmediate("RDI", bytePointers.destination),
    moveImmediate("ECX", 1n),
    moveImmediate("EAX", byteValue),
    storeRegister("UInt8", "RSI", "AL"),
    ins("Cld"),
    repeatedStringMove("Movsb", "MemoryESRDI", "MemorySegRSI", "UInt8")
  ]);
  const qwordState = emulateInstructionsWithState([
    moveImmediate("RSI", qwordPointers.source),
    moveImmediate("RDI", qwordPointers.destination),
    moveImmediate("ECX", 1n),
    moveImmediate("RAX", qwordValue, "Immediate64"),
    storeRegister("UInt64", "RSI", "RAX"),
    ins("Cld"),
    repeatedStringMove("Movsq", "MemoryESRDI", "MemorySegRSI", "UInt64")
  ]);

  expectKnownMemory(byteState, bytePointers.destination, byteValue, bitsOf("UInt8"));
  expectKnownRegister(byteState, "RSI", bytePointers.source + bytesOf("UInt8"), bitsOf("UInt64"));
  expectKnownMemory(qwordState, qwordPointers.destination, qwordValue, bitsOf("UInt64"));
  expectKnownRegister(
    qwordState,
    "RSI",
    qwordPointers.source + bytesOf("UInt64"),
    bitsOf("UInt64")
  );
});

void test("emulateInstruction invalidates repeated string moves when DF is unknown", () => {
  const pointers = fixtureAddressPair();
  const state = emulateInstructionsWithState([
    moveImmediate("RSI", pointers.source),
    moveImmediate("RDI", pointers.destination),
    moveImmediate("ECX", 1n),
    repeatedStringMove("Movsd", "MemoryESRDI", "MemorySegRSI", "UInt32")
  ]);

  assert.deepEqual(state.registers.get("RSI"), { kind: "unknown" });
  assert.deepEqual(state.registers.get("RDI"), { kind: "unknown" });
  assert.deepEqual(state.registers.get("RCX"), { kind: "unknown" });
  assert.equal(state.memory.get(pointers.destination.toString()), undefined);
});

void test("emulateInstruction sparsely copies large non-overlapping repeated string moves", () => {
  const pointers = fixtureAddressPair();
  const destination = distantFixtureDestination();
  const count = sparseElementCount();
  const firstValue = fixtureValue(11, bitsOf("UInt32"));
  const lastValue = fixtureValue(12, bitsOf("UInt32"));
  const staleValue = fixtureValue(13, bitsOf("UInt32"));
  const lastOffset = (count - 1n) * bytesOf("UInt32");
  const afterRangeOffset = count * bytesOf("UInt32");
  const state = emulateInstructionsWithState([
    moveImmediate("RSI", pointers.source),
    moveImmediate("RDI", destination, "Immediate64"),
    moveImmediate("ECX", count),
    moveImmediate("EAX", firstValue),
    storeRegister("UInt32", "RSI", "EAX"),
    moveImmediate("EAX", lastValue),
    storeRegister("UInt32", "RSI", "EAX", lastOffset),
    moveImmediate("EAX", staleValue),
    storeRegister("UInt32", "RDI", "EAX"),
    storeRegister("UInt32", "RDI", "EAX", lastOffset),
    storeRegister("UInt32", "RDI", "EAX", afterRangeOffset),
    ins("Cld"),
    repeatedStringMove("Movsd", "MemoryESRDI", "MemorySegRSI", "UInt32")
  ]);

  expectKnownMemory(state, destination, firstValue, bitsOf("UInt32"));
  expectKnownMemory(state, destination + lastOffset, lastValue, bitsOf("UInt32"));
  expectKnownMemory(state, destination + afterRangeOffset, staleValue, bitsOf("UInt32"));
  assert.ok(BigInt(state.memory.size) < count);
  expectKnownRegister(state, "RSI", pointers.source + afterRangeOffset, bitsOf("UInt64"));
  expectKnownRegister(state, "RDI", destination + afterRangeOffset, bitsOf("UInt64"));
});
