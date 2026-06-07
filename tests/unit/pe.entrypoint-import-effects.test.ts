"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import {
  applyReturningImportEffects
} from "../../analyzers/pe/disassembly/entrypoint/import-effects.js";
import type { IcedModule } from "../../analyzers/pe/disassembly/entrypoint/iced.js";
import { resolveRegister } from "../../analyzers/pe/disassembly/entrypoint/emulation-registers.js";
import {
  createEmulationState,
  known,
  readRegister,
  writeRegister
} from "../../analyzers/pe/disassembly/entrypoint/emulation-state.js";

const icedModule = iced as unknown as IcedModule;

void test("applyReturningImportEffects models ABI volatile registers and return value", () => {
  const state = createEmulationState(64);
  writeRegister(state, resolveRegister(icedModule, iced.Register.RCX), known(0xfffffff5n, 64));
  writeRegister(state, resolveRegister(icedModule, iced.Register.RBX), known(0x1234n, 64));

  applyReturningImportEffects(icedModule, state, {
    label: "KERNEL32.dll!GetStdHandle",
    slotRva: 0x2060,
    importKind: "eager",
    guardIatEntry: false
  });

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
