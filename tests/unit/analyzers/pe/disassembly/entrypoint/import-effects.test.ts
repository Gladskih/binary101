"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86-disasm";
import {
  applyReturningImportEffects
} from "../../../../../../analyzers/pe/disassembly/entrypoint/import-effects.js";
import { pushStackValue } from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/stack.js";
import { resolveRegister } from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/registers.js";
import {
  createEmulationState,
  known,
  readRegister,
  writeRegister
} from "../../../../../../analyzers/pe/disassembly/entrypoint/emulation/state.js";
import type { PeImportMetadataEntry } from "../../../../../../pe-import-metadata-schema.js";

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
  noReturn: false,
  setLastError: false,
  characterSet: null,
  architecture: [],
  platform: []
});

void test("applyReturningImportEffects models ABI volatile registers and return value", () => {
  const state = createEmulationState(64);
  writeRegister(state, resolveRegister(iced, iced.Register.RCX), known(0xfffffff5n, 64));
  writeRegister(state, resolveRegister(iced, iced.Register.RBX), known(0x1234n, 64));

  applyReturningImportEffects(iced, state, { label: "KERNEL32.dll!GetStdHandle" });

  assert.deepEqual(readRegister(state, resolveRegister(iced, iced.Register.RAX)), {
    kind: "import-return",
    label: "KERNEL32.dll!GetStdHandle"
  });
  assert.deepEqual(readRegister(state, resolveRegister(iced, iced.Register.RCX)), {
    kind: "unknown"
  });
  assert.deepEqual(readRegister(state, resolveRegister(iced, iced.Register.RBX)), {
    kind: "known",
    value: 0x1234n,
    bits: 64
  });
});

void test("applyReturningImportEffects cleans x86 winapi import arguments from metadata", () => {
  const state = createEmulationState(X86_BITNESS);
  pushStackValue(iced, state, known(0x1234n, X86_BITNESS), X86_STACK_SLOT_BYTES);

  applyReturningImportEffects(iced, state, {
    label: "USER32.dll!ShowCursor",
    apiMetadata: metadata("winapi", [4])
  });

  assert.deepEqual(readRegister(state, resolveRegister(iced, iced.Register.ESP)), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.deepEqual(readRegister(state, resolveRegister(iced, iced.Register.EAX)), {
    kind: "import-return",
    label: "USER32.dll!ShowCursor"
  });
  assert.equal(state.memory.size, 0);
});

void test("applyReturningImportEffects cleans multiple x86 stdcall import arguments", () => {
  const state = createEmulationState(X86_BITNESS);
  pushStackValue(iced, state, known(0x2222n, X86_BITNESS), X86_STACK_SLOT_BYTES);
  pushStackValue(iced, state, known(0x1111n, X86_BITNESS), X86_STACK_SLOT_BYTES);

  applyReturningImportEffects(iced, state, {
    label: "TEST.dll!TwoArgs",
    apiMetadata: metadata("stdcall", [4, 4])
  });

  assert.deepEqual(readRegister(state, resolveRegister(iced, iced.Register.ESP)), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.equal(state.memory.size, 0);
});

void test("applyReturningImportEffects preserves x86 cdecl caller-cleaned arguments", () => {
  const state = createEmulationState(X86_BITNESS);
  const stackPointer = resolveRegister(iced, iced.Register.ESP);
  const initialStackPointer = readRegister(state, stackPointer);
  pushStackValue(iced, state, known(0n, X86_BITNESS), X86_STACK_SLOT_BYTES);
  pushStackValue(iced, state, known(0n, X86_BITNESS), X86_STACK_SLOT_BYTES);

  applyReturningImportEffects(iced, state, {
    label: "ucrtbase.dll!printf",
    apiMetadata: metadata("cdecl", [4, 4])
  });

  assert.notDeepEqual(readRegister(state, stackPointer), initialStackPointer);
  assert.equal(state.memory.size, 2);
});

void test("applyReturningImportEffects preserves arguments with unknown metadata sizes", () => {
  const state = createEmulationState(X86_BITNESS);
  const stackPointer = resolveRegister(iced, iced.Register.ESP);
  pushStackValue(iced, state, known(0n, X86_BITNESS), X86_STACK_SLOT_BYTES);
  const currentStackPointer = readRegister(state, stackPointer);

  applyReturningImportEffects(iced, state, {
    label: "TEST.dll!UnknownStruct",
    apiMetadata: metadata("winapi", [null])
  });

  assert.deepEqual(readRegister(state, stackPointer), currentStackPointer);
  assert.equal(state.memory.size, 1);
});
