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
import type { PeImportMetadataEntry } from "../../../../../../pe-import-metadata-schema.js";

const icedModule = iced as unknown as IcedModule;
const X86_BITNESS = 32 as const;
const X86_STACK_SLOT_BYTES = BigInt(Uint32Array.BYTES_PER_ELEMENT);

const metadata = (
  callingConvention: string,
  x86StackBytes: Array<number | null>
): PeImportMetadataEntry => ({
  sourceKind: "winapi",
  id: "test:metadata",
  module: "TEST.dll",
  entrypoint: "Imported",
  namespace: null,
  api: "Imported",
  signature: "int Imported()",
  returnType: "int",
  rawReturnType: "int",
  parameters: x86StackBytes.map((bytes, index) => ({
    name: `param${index + 1}`,
    type: "u4",
    rawType: "u4",
    direction: "in",
    x86StackBytes: bytes
  })),
  callingConvention,
  variadic: false,
  setLastError: false,
  characterSet: null,
  architecture: [],
  platform: []
});

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

void test("applyReturningImportEffects cleans x86 winapi import arguments from metadata", () => {
  const state = createEmulationState(X86_BITNESS);
  pushStackValue(icedModule, state, known(0x1234n, X86_BITNESS), X86_STACK_SLOT_BYTES);

  applyReturningImportEffects(icedModule, state, {
    label: "USER32.dll!ShowCursor",
    apiMetadata: metadata("winapi", [4])
  });

  assert.deepEqual(readRegister(state, resolveRegister(icedModule, iced.Register.ESP)), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.deepEqual(readRegister(state, resolveRegister(icedModule, iced.Register.EAX)), {
    kind: "import-return",
    label: "USER32.dll!ShowCursor"
  });
  assert.equal(state.memory.size, 0);
});

void test("applyReturningImportEffects cleans multiple x86 stdcall import arguments", () => {
  const state = createEmulationState(X86_BITNESS);
  pushStackValue(icedModule, state, known(0x2222n, X86_BITNESS), X86_STACK_SLOT_BYTES);
  pushStackValue(icedModule, state, known(0x1111n, X86_BITNESS), X86_STACK_SLOT_BYTES);

  applyReturningImportEffects(icedModule, state, {
    label: "TEST.dll!TwoArgs",
    apiMetadata: metadata("stdcall", [4, 4])
  });

  assert.deepEqual(readRegister(state, resolveRegister(icedModule, iced.Register.ESP)), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.equal(state.memory.size, 0);
});

void test("applyReturningImportEffects preserves x86 cdecl caller-cleaned arguments", () => {
  const state = createEmulationState(X86_BITNESS);
  const stackPointer = resolveRegister(icedModule, iced.Register.ESP);
  const initialStackPointer = readRegister(state, stackPointer);
  pushStackValue(icedModule, state, known(0n, X86_BITNESS), X86_STACK_SLOT_BYTES);
  pushStackValue(icedModule, state, known(0n, X86_BITNESS), X86_STACK_SLOT_BYTES);

  applyReturningImportEffects(icedModule, state, {
    label: "ucrtbase.dll!printf",
    apiMetadata: metadata("cdecl", [4, 4])
  });

  assert.notDeepEqual(readRegister(state, stackPointer), initialStackPointer);
  assert.equal(state.memory.size, 2);
});

void test("applyReturningImportEffects preserves arguments with unknown metadata sizes", () => {
  const state = createEmulationState(X86_BITNESS);
  const stackPointer = resolveRegister(icedModule, iced.Register.ESP);
  pushStackValue(icedModule, state, known(0n, X86_BITNESS), X86_STACK_SLOT_BYTES);
  const currentStackPointer = readRegister(state, stackPointer);

  applyReturningImportEffects(icedModule, state, {
    label: "TEST.dll!UnknownStruct",
    apiMetadata: metadata("winapi", [null])
  });

  assert.deepEqual(readRegister(state, stackPointer), currentStackPointer);
  assert.equal(state.memory.size, 1);
});
