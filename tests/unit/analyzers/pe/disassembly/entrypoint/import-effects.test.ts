"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import {
  applyReturningImportEffects
} from "../../../../../../analyzers/pe/disassembly/entrypoint/import-effects.js";
import { pushStackValue } from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/stack.js";
import type { IcedModule } from "../../../../../../analyzers/pe/disassembly/entrypoint/iced.js";
import { resolveRegister } from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/registers.js";
import {
  createEmulationState,
  known,
  readRegister,
  writeRegister
} from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/state.js";

const icedModule = iced as unknown as IcedModule;
const X86_BITNESS = 32 as const;
const X86_STACK_SLOT_BYTES = BigInt(Uint32Array.BYTES_PER_ELEMENT);

void test("applyReturningImportEffects models ABI volatile registers and return value", () => {
  const state = createEmulationState(64);
  writeRegister(state, resolveRegister(icedModule, iced.Register.RCX), known(0xfffffff5n, 64));
  writeRegister(state, resolveRegister(icedModule, iced.Register.RBX), known(0x1234n, 64));

  applyReturningImportEffects(icedModule, state, { label: "KERNEL32.dll!GetStdHandle" });

  assert.deepEqual(readRegister(state, resolveRegister(icedModule, iced.Register.RAX)), {
    kind: "import-return",
    label: "KERNEL32.dll!GetStdHandle"
  });
  assert.deepEqual(readRegister(state, resolveRegister(icedModule, iced.Register.RCX)), {
    kind: "unknown"
  });
  assert.deepEqual(readRegister(state, resolveRegister(icedModule, iced.Register.RBX)), {
    kind: "known",
    value: 0x1234n,
    bits: 64
  });
});

void test("applyReturningImportEffects cleans known x86 stdcall import arguments", () => {
  const state = createEmulationState(X86_BITNESS);
  pushStackValue(icedModule, state, known(0x1234n, X86_BITNESS), X86_STACK_SLOT_BYTES);

  applyReturningImportEffects(icedModule, state, { label: "KERNEL32.dll!FreeLibrary" });

  assert.deepEqual(readRegister(state, resolveRegister(icedModule, iced.Register.ESP)), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.deepEqual(readRegister(state, resolveRegister(icedModule, iced.Register.EAX)), {
    kind: "import-return",
    label: "KERNEL32.dll!FreeLibrary"
  });
  assert.equal(state.memory.size, 0);
});

void test("applyReturningImportEffects cleans multiple x86 stdcall import arguments", () => {
  const state = createEmulationState(X86_BITNESS);
  pushStackValue(icedModule, state, known(0x2222n, X86_BITNESS), X86_STACK_SLOT_BYTES);
  pushStackValue(icedModule, state, known(0x1111n, X86_BITNESS), X86_STACK_SLOT_BYTES);

  applyReturningImportEffects(icedModule, state, { label: "KERNEL32.dll!TlsSetValue" });

  assert.deepEqual(readRegister(state, resolveRegister(icedModule, iced.Register.ESP)), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.equal(state.memory.size, 0);
});

void test("applyReturningImportEffects matches x86 stdcall imports regardless of DLL casing", () => {
  const state = createEmulationState(X86_BITNESS);
  const stackPointer = resolveRegister(icedModule, iced.Register.ESP);
  const initialStackPointer = readRegister(state, stackPointer);
  pushStackValue(icedModule, state, known(0n, X86_BITNESS), X86_STACK_SLOT_BYTES);
  pushStackValue(icedModule, state, known(0n, X86_BITNESS), X86_STACK_SLOT_BYTES);

  applyReturningImportEffects(icedModule, state, { label: "kernel32.dll!GetProcAddress" });

  assert.deepEqual(readRegister(state, stackPointer), initialStackPointer);
  assert.equal(state.memory.size, 0);
});

void test("applyReturningImportEffects preserves case-sensitive export matching", () => {
  const state = createEmulationState(X86_BITNESS);
  const stackPointer = resolveRegister(icedModule, iced.Register.ESP);
  const initialStackPointer = readRegister(state, stackPointer);
  pushStackValue(icedModule, state, known(0n, X86_BITNESS), X86_STACK_SLOT_BYTES);
  pushStackValue(icedModule, state, known(0n, X86_BITNESS), X86_STACK_SLOT_BYTES);

  applyReturningImportEffects(icedModule, state, { label: "kernel32.dll!getprocaddress" });

  assert.notDeepEqual(readRegister(state, stackPointer), initialStackPointer);
  assert.ok(state.memory.size > 0);
});

void test("applyReturningImportEffects cleans the x86 GetModuleHandleW argument", () => {
  const state = createEmulationState(X86_BITNESS);
  const stackPointer = resolveRegister(icedModule, iced.Register.ESP);
  const initialStackPointer = readRegister(state, stackPointer);
  pushStackValue(icedModule, state, known(0n, X86_BITNESS), X86_STACK_SLOT_BYTES);

  applyReturningImportEffects(icedModule, state, { label: "kernel32.dll!GetModuleHandleW" });

  assert.deepEqual(readRegister(state, stackPointer), initialStackPointer);
  assert.equal(state.memory.size, 0);
});
