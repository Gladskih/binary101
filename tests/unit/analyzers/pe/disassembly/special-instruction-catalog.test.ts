import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import {
  SPECIAL_INSTRUCTION_CATALOG,
  SPECIAL_INSTRUCTION_CATEGORIES
} from "../../../../../analyzers/pe/disassembly/special-instruction-catalog.js";

void test("every educational entry names a decoded mnemonic or an intentional operand family", () => {
  const mnemonics = new Set(Object.keys(iced.Mnemonic).map(name => name.toUpperCase()));
  mnemonics.add("MOV CR").add("MOV DR").add("INT 0x2E");
  for (const [name, [category, explanation]] of Object.entries(SPECIAL_INSTRUCTION_CATALOG)) {
    assert.ok(mnemonics.has(name), `Unsupported mnemonic ${name}`);
    assert.ok(SPECIAL_INSTRUCTION_CATEGORIES[category], `Missing category for ${name}`);
    assert.ok(explanation.length > 40, `Missing useful explanation for ${name}`);
  }
});

void test("each category has a readable label and an educational explanation", () => {
  for (const [category, [label, explanation]] of Object.entries(SPECIAL_INSTRUCTION_CATEGORIES)) {
    assert.ok(label.length > 3, category);
    assert.ok(explanation.length > 40, category);
  }
});
