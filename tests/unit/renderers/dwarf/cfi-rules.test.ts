import assert from "node:assert/strict";
import { test } from "node:test";
import { dwarfCfaRuleText, dwarfRegisterRuleText } from "../../../../renderers/dwarf/cfi-rules.js";

void test("CFI rule text explains every register recovery rule without raw addresses", () => {
  assert.equal(dwarfCfaRuleText(null), "Unspecified frame address");
  assert.equal(dwarfCfaRuleText({ expression: [{ offset: 0, opcode: 0x54, operands: [] }] }), "DWARF register 4");
  assert.equal(dwarfCfaRuleText({ expression: "legacy bytes" }), "legacy bytes");
  assert.equal(dwarfRegisterRuleText({ kind: "register", register: 7n }), "value of register 7");
  assert.equal(dwarfRegisterRuleText({ kind: "undefined" }), "unavailable value");
  assert.equal(dwarfRegisterRuleText({ kind: "same_value" }), "unchanged value");
  assert.equal(dwarfRegisterRuleText({ kind: "val_offset", offset: -4n }), "value of frame address − 4 bytes");
  assert.equal(dwarfRegisterRuleText({ kind: "expression", expression: "test" }), "memory at test");
  assert.equal(dwarfRegisterRuleText({ kind: "val_expression", expression: "test" }), "value of test");
});
