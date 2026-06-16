"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createEmulationState
} from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/index.js";
import {
  UNKNOWN,
  known
} from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/state.js";
import {
  executeRotate,
  isRotateInstruction
} from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/integer/rotates.js";
import {
  type FixtureMnemonic,
  fixtureIced,
  imm,
  instruction as ins,
  reg
} from "../../../../../../helpers/pe-entrypoint-emulation-fixture.js";

const mnemonic = (name: FixtureMnemonic): number => fixtureIced.Mnemonic?.[name] ?? 0;

void test("isRotateInstruction recognizes scalar rotate mnemonics", () => {
  assert.equal(isRotateInstruction(fixtureIced, mnemonic("Rol")), true);
  assert.equal(isRotateInstruction(fixtureIced, mnemonic("Rcr")), true);
  assert.equal(isRotateInstruction(fixtureIced, mnemonic("Shl")), false);
});

void test("executeRotate models rotate-through-carry with known carry", () => {
  const state = createEmulationState(64);
  state.registers.set("RAX", known(1n, 64));
  state.flags.CF = true;

  const handled = executeRotate(
    fixtureIced,
    state,
    ins("Rcl", [reg("EAX"), imm(1, "Immediate8")]),
    32,
    known(1n, 8)
  );

  assert.equal(handled, true);
  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 3n, bits: 64 });
  assert.equal(state.flags.CF, false);
  assert.equal(state.flags.OF, false);
});

void test("executeRotate keeps full-cycle carry rotates stable", () => {
  const state = createEmulationState(64);
  state.registers.set("RAX", known(0x81n, 64));
  state.flags.CF = true;

  executeRotate(
    fixtureIced,
    state,
    ins("Rcl", [reg("AL"), imm(9, "Immediate8")]),
    8,
    known(9n, 8)
  );

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 0x81n, bits: 64 });
  assert.equal(state.flags.CF, true);
  assert.equal(state.flags.OF, undefined);
});

void test("executeRotate marks unknown count results as unknown", () => {
  const state = createEmulationState(64);
  state.registers.set("RAX", known(1n, 64));
  state.flags.CF = true;
  state.flags.ZF = true;

  executeRotate(
    fixtureIced,
    state,
    ins("Rcr", [reg("EAX"), reg("CL")]),
    32,
    UNKNOWN
  );

  assert.deepEqual(state.registers.get("RAX"), UNKNOWN);
  assert.equal(state.flags.CF, undefined);
  assert.equal(state.flags.OF, undefined);
  assert.equal(state.flags.ZF, true);
});
