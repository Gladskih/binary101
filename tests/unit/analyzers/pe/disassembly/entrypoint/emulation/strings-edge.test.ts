"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createEmulationState } from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/index.js";
import {
  UNKNOWN,
  joinEmulatedValues,
  known,
  type EmulationState
} from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/state.js";
import { executeStringInstruction } from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/strings.js";
import {
  fixtureIced,
  implicitMem,
  instruction as ins
} from "../../../../../../helpers/pe-entrypoint-emulation-fixture.js";
import {
  bitsOf,
  bytesOf,
  fixtureAddressPair,
  fixtureValue,
  repeatCountRequiringRcx,
} from "../../../../../../helpers/pe-entrypoint-emulation-values.js";

const movsd = () =>
  ins("Movsd", [
    implicitMem("MemoryESRDI", "UInt32"),
    implicitMem("MemorySegRSI", "UInt32")
  ]);

const repeatedMovsd = () =>
  ins("Movsd", [
    implicitMem("MemoryESRDI", "UInt32"),
    implicitMem("MemorySegRSI", "UInt32")
  ], { repeatPrefix: "rep" });

// 64-bit mode makes MOVS use RSI/RDI/RCX, which these tests assert directly.
const createX64State = (): EmulationState => createEmulationState(64);

const knownQword = (value: bigint) => known(value, bitsOf("UInt64"));

const setRegister = (
  state: EmulationState,
  register: "RSI" | "RDI" | "RCX",
  value: bigint
): void => {
  state.registers.set(register, knownQword(value));
};

const expectKnownQwordRegister = (
  state: EmulationState,
  register: "RSI" | "RDI" | "RCX",
  value: bigint
): void => {
  assert.deepEqual(state.registers.get(register), knownQword(value));
};

void test("executeStringInstruction requires a MOVS mnemonic and unsigned memory size", () => {
  const state = createX64State();

  assert.equal(executeStringInstruction(fixtureIced, state, ins("Movsd")), false);
  assert.equal(executeStringInstruction(
    fixtureIced,
    state,
    ins("Stosd", [
      implicitMem("MemoryESRDI", "UInt32"),
      implicitMem("MemorySegRSI", "UInt32")
    ])
  ), false);
  assert.equal(executeStringInstruction(
    fixtureIced,
    state,
    ins("Movsq", [
      implicitMem("MemoryESRDI", "Int64"),
      implicitMem("MemorySegRSI", "Int64")
    ])
  ), false);
});

void test("executeStringInstruction uses the full 64-bit repeat counter", () => {
  const state = createX64State();
  const pointers = fixtureAddressPair();
  const repeatCount = repeatCountRequiringRcx();
  const expectedAdvance = repeatCount * bytesOf("UInt32");

  state.flags.DF = false;
  setRegister(state, "RSI", pointers.source);
  setRegister(state, "RDI", pointers.destination);
  setRegister(state, "RCX", repeatCount);

  assert.equal(executeStringInstruction(fixtureIced, state, repeatedMovsd()), true);
  expectKnownQwordRegister(state, "RSI", pointers.source + expectedAdvance);
  expectKnownQwordRegister(state, "RDI", pointers.destination + expectedAdvance);
});

void test("executeStringInstruction invalidates ambiguous string pointers", () => {
  const state = createX64State();
  const pointers = fixtureAddressPair();

  state.flags.DF = false;
  state.registers.set("RSI", joinEmulatedValues(
    knownQword(pointers.source),
    knownQword(pointers.source + bytesOf("UInt32"))
  ));
  setRegister(state, "RDI", pointers.destination);
  setRegister(state, "RCX", 1n);

  assert.equal(executeStringInstruction(fixtureIced, state, repeatedMovsd()), true);
  assert.deepEqual(state.registers.get("RSI"), UNKNOWN);
  assert.deepEqual(state.registers.get("RDI"), UNKNOWN);
  assert.deepEqual(state.registers.get("RCX"), UNKNOWN);
});

void test("executeStringInstruction keeps the counter for non-repeated unknown DF", () => {
  const state = createX64State();
  const pointers = fixtureAddressPair();
  const nonRepeatedCounter = fixtureValue(1, bitsOf("UInt32"));

  setRegister(state, "RSI", pointers.source);
  setRegister(state, "RDI", pointers.destination);
  setRegister(state, "RCX", nonRepeatedCounter);

  assert.equal(executeStringInstruction(fixtureIced, state, movsd()), true);
  assert.deepEqual(state.registers.get("RSI"), UNKNOWN);
  assert.deepEqual(state.registers.get("RDI"), UNKNOWN);
  expectKnownQwordRegister(state, "RCX", nonRepeatedCounter);
});
