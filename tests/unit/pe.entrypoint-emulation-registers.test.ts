"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import { resolveRegister } from "../../analyzers/pe/disassembly/entrypoint/emulation-registers.js";
import type { IcedModule } from "../../analyzers/pe/disassembly/entrypoint/iced.js";

const icedModule = iced as unknown as IcedModule;
const registers = iced.Register as unknown as Record<string, number>;

void test("resolveRegister maps supported x86 register aliases", () => {
  const expected: Array<[string, string, 8 | 16 | 32 | 64, 0 | 8]> = [
    ["RAX", "RAX", 64, 0], ["EAX", "RAX", 32, 0],
    ["AX", "RAX", 16, 0], ["AL", "RAX", 8, 0], ["AH", "RAX", 8, 8],
    ["RBX", "RBX", 64, 0], ["EBX", "RBX", 32, 0],
    ["BX", "RBX", 16, 0], ["BL", "RBX", 8, 0], ["BH", "RBX", 8, 8],
    ["RCX", "RCX", 64, 0], ["ECX", "RCX", 32, 0],
    ["CX", "RCX", 16, 0], ["CL", "RCX", 8, 0], ["CH", "RCX", 8, 8],
    ["RDX", "RDX", 64, 0], ["EDX", "RDX", 32, 0],
    ["DX", "RDX", 16, 0], ["DL", "RDX", 8, 0], ["DH", "RDX", 8, 8],
    ["RSI", "RSI", 64, 0], ["ESI", "RSI", 32, 0],
    ["SI", "RSI", 16, 0], ["SIL", "RSI", 8, 0],
    ["RDI", "RDI", 64, 0], ["EDI", "RDI", 32, 0],
    ["DI", "RDI", 16, 0], ["DIL", "RDI", 8, 0],
    ["RBP", "RBP", 64, 0], ["EBP", "RBP", 32, 0],
    ["BP", "RBP", 16, 0], ["BPL", "RBP", 8, 0],
    ["RSP", "RSP", 64, 0], ["ESP", "RSP", 32, 0],
    ["SP", "RSP", 16, 0], ["SPL", "RSP", 8, 0],
    ["R8", "R8", 64, 0], ["R8D", "R8", 32, 0],
    ["R8W", "R8", 16, 0], ["R8L", "R8", 8, 0],
    ["R9", "R9", 64, 0], ["R9D", "R9", 32, 0],
    ["R9W", "R9", 16, 0], ["R9L", "R9", 8, 0],
    ["R10", "R10", 64, 0], ["R10D", "R10", 32, 0],
    ["R10W", "R10", 16, 0], ["R10L", "R10", 8, 0],
    ["R11", "R11", 64, 0], ["R11D", "R11", 32, 0],
    ["R11W", "R11", 16, 0], ["R11L", "R11", 8, 0],
    ["R12", "R12", 64, 0], ["R12D", "R12", 32, 0],
    ["R12W", "R12", 16, 0], ["R12L", "R12", 8, 0],
    ["R13", "R13", 64, 0], ["R13D", "R13", 32, 0],
    ["R13W", "R13", 16, 0], ["R13L", "R13", 8, 0],
    ["R14", "R14", 64, 0], ["R14D", "R14", 32, 0],
    ["R14W", "R14", 16, 0], ["R14L", "R14", 8, 0],
    ["R15", "R15", 64, 0], ["R15D", "R15", 32, 0],
    ["R15W", "R15", 16, 0], ["R15L", "R15", 8, 0]
  ];

  for (const [name, canonical, accessBits, bitOffset] of expected) {
    assert.deepEqual(resolveRegister(icedModule, registers[name] ?? 0), {
      canonical,
      accessBits,
      bitOffset
    });
  }
});
