"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import type { IcedModule } from "../../../../../../../analyzers/pe/disassembly/entrypoint/iced.js";
import { resolveRegister } from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/registers.js";
import {
  collectKnownValues,
  createEmulationState,
  joinEmulatedValues,
  known,
  mapKnownValues,
  mergeEmulationStates,
  readRegister,
  writeRegister
} from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/state.js";

const icedModule = iced as unknown as IcedModule;

void test("writeRegister zero-extends 32-bit writes in 64-bit mode", () => {
  const state = createEmulationState(64);
  const rax = resolveRegister(icedModule, iced.Register.RAX);
  const eax = resolveRegister(icedModule, iced.Register.EAX);

  writeRegister(state, rax, known(0xffff_ffff_ffff_ffffn, 64));
  writeRegister(state, eax, known(1n, 32));

  assert.deepEqual(readRegister(state, rax), { kind: "known", value: 1n, bits: 64 });
});

void test("writeRegister truncates oversized values before 32-bit zero-extension", () => {
  const state = createEmulationState(64);
  const rax = resolveRegister(icedModule, iced.Register.RAX);
  const eax = resolveRegister(icedModule, iced.Register.EAX);

  writeRegister(state, rax, known(0n, 64));
  writeRegister(state, eax, known(0x1122_3344_5566_7788n, 64));

  assert.deepEqual(readRegister(state, rax), {
    kind: "known",
    value: 0x5566_7788n,
    bits: 64
  });
});

void test("writeRegister keeps 32-bit state width in 32-bit mode", () => {
  const state = createEmulationState(32);
  const eax = resolveRegister(icedModule, iced.Register.EAX);

  writeRegister(state, eax, known(0xffff_ffffn, 32));

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0xffff_ffffn,
    bits: 32
  });
  assert.deepEqual(readRegister(state, eax), {
    kind: "known",
    value: 0xffff_ffffn,
    bits: 32
  });
});

void test("readRegister extracts known partial register aliases", () => {
  const state = createEmulationState(64);
  const rax = resolveRegister(icedModule, iced.Register.RAX);
  const ax = resolveRegister(icedModule, iced.Register.AX);
  const al = resolveRegister(icedModule, iced.Register.AL);
  const ah = resolveRegister(icedModule, iced.Register.AH);

  writeRegister(state, rax, known(0x1122_3344_5566_7788n, 64));

  assert.deepEqual(readRegister(state, ax), { kind: "known", value: 0x7788n, bits: 16 });
  assert.deepEqual(readRegister(state, al), { kind: "known", value: 0x88n, bits: 8 });
  assert.deepEqual(readRegister(state, ah), { kind: "known", value: 0x77n, bits: 8 });
});

void test("writeRegister updates known partial register aliases", () => {
  const state = createEmulationState(64);
  const rax = resolveRegister(icedModule, iced.Register.RAX);
  const ax = resolveRegister(icedModule, iced.Register.AX);
  const ah = resolveRegister(icedModule, iced.Register.AH);
  const r8 = resolveRegister(icedModule, iced.Register.R8);
  const r8b = resolveRegister(icedModule, iced.Register.R8L);

  writeRegister(state, rax, known(0x1122_3344_5566_7788n, 64));
  writeRegister(state, ax, known(0xaabbn, 16));
  writeRegister(state, ah, known(0xccn, 8));
  writeRegister(state, r8, known(0x9999n, 64));
  writeRegister(state, r8b, known(0x11n, 8));

  assert.deepEqual(readRegister(state, rax), {
    kind: "known",
    value: 0x1122_3344_5566_ccbbn,
    bits: 64
  });
  assert.deepEqual(readRegister(state, r8), { kind: "known", value: 0x9911n, bits: 64 });
});

void test("writeRegister invalidates unknown partial register aliases", () => {
  const state = createEmulationState(64);
  const rax = resolveRegister(icedModule, iced.Register.RAX);
  const ax = resolveRegister(icedModule, iced.Register.AX);

  writeRegister(state, ax, known(1n, 16));

  assert.deepEqual(readRegister(state, rax), { kind: "unknown" });
});

void test("createEmulationState initializes abstract stack by bitness", () => {
  assert.deepEqual(createEmulationState(32).registers.get("RSP"), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.deepEqual(createEmulationState(64).registers.get("RSP"), {
    kind: "known",
    value: 0x100000000000n,
    bits: 64
  });
});

void test("mergeEmulationStates joins concrete register alternatives", () => {
  const left = createEmulationState(64);
  const right = createEmulationState(64);
  const r11 = resolveRegister(icedModule, iced.Register.R11);

  writeRegister(left, r11, known(0x140001010n, 64));
  writeRegister(right, r11, known(0x140002020n, 64));

  const merged = mergeEmulationStates(left, right);

  assert.deepEqual(
    collectKnownValues(readRegister(merged, r11)).map(value => value.value),
    [0x140001010n, 0x140002020n]
  );
});

void test("mapKnownValues transforms bounded value-set alternatives", () => {
  const mapped = mapKnownValues(
    joinEmulatedValues(known(1n, 8), known(2n, 8)),
    16,
    value => value + 1n
  );

  assert.deepEqual(collectKnownValues(mapped).map(value => value.value), [2n, 3n]);
  assert.deepEqual(collectKnownValues(mapped).map(value => value.bits), [16, 16]);
});

void test("mergeEmulationStates widens missing path-only values to unknown", () => {
  const left = createEmulationState(64);
  const right = createEmulationState(64);
  const r11 = resolveRegister(icedModule, iced.Register.R11);

  writeRegister(left, r11, known(0x140001010n, 64));

  assert.deepEqual(readRegister(mergeEmulationStates(left, right), r11), { kind: "unknown" });
});
