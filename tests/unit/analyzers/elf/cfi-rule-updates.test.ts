import assert from "node:assert/strict";
import { test } from "node:test";
import { applyElfCfiRule } from "../../../../analyzers/elf/cfi-rule-updates.js";
import type { ElfCfiRules } from "../../../../analyzers/elf/cfi-state-types.js";

const state = (): ElfCfiRules => ({ cfa: { register: 7n, offset: 8n }, registers: {},
  returnAddressSigned: false, argumentSize: 0n });
const apply = (rules: ElfCfiRules, operation: string, operands: (bigint | string)[] = []) =>
  applyElfCfiRule(rules, { offset: 0, operation, operands }, -8n);

void test("applies all CFA definition forms with their distinct scaling", () => {
  const rules = state();
  assert.equal(apply(rules, "def_cfa_sf", [6n, -2n]), true);
  assert.deepEqual(rules.cfa, { register: 6n, offset: 16n });
  assert.equal(apply(rules, "def_cfa_register", [5n]), true);
  assert.deepEqual(rules.cfa, { register: 5n, offset: 16n });
  assert.equal(apply(rules, "def_cfa_offset_sf", [-3n]), true);
  assert.deepEqual(rules.cfa, { register: 5n, offset: 24n });
  assert.equal(apply(rules, "def_cfa_expression", ["abcd"]), true);
  assert.deepEqual(rules.cfa, { expression: "abcd" });
  assert.equal(apply(rules, "def_cfa_register", [7n]), false);
  assert.equal(apply(rules, "def_cfa_offset", [8n]), false);
});

for (const operation of ["offset", "offset_extended", "offset_extended_sf"]) {
  void test(`scales ${operation} register offsets`, () => {
    const rules = state();
    assert.equal(apply(rules, operation, [16n, 2n]), true);
    assert.deepEqual(rules.registers["16"], { kind: "offset", offset: -16n });
  });
}
for (const operation of ["val_offset", "val_offset_sf"]) {
  void test(`scales ${operation} register values`, () => {
    const rules = state();
    assert.equal(apply(rules, operation, [16n, 2n]), true);
    assert.deepEqual(rules.registers["16"], { kind: "val_offset", offset: -16n });
  });
}

void test("keeps register, expression and value-expression rules distinct", () => {
  const rules = state();
  assert.equal(apply(rules, "register", [1n, 2n]), true);
  assert.equal(apply(rules, "expression", [3n, "abcd"]), true);
  assert.equal(apply(rules, "val_expression", [4n, "ab"]), true);
  assert.equal(apply(rules, "same_value", [5n]), true);
  assert.equal(apply(rules, "undefined", [6n]), true);
  assert.deepEqual(rules.registers, { 1: { kind: "register", register: 2n },
    3: { kind: "expression", expression: "abcd" }, 4: { kind: "val_expression", expression: "ab" },
    5: { kind: "same_value" }, 6: { kind: "undefined" } });
});

void test("applies GNU and AArch64 rule extensions", () => {
  const rules = state();
  assert.equal(apply(rules, "GNU_negative_offset_extended", [1n, 2n]), true);
  assert.deepEqual(rules.registers["1"], { kind: "offset", offset: 16n });
  assert.equal(apply(rules, "GNU_args_size", [32n]), true);
  assert.equal(rules.argumentSize, 32n);
  assert.equal(apply(rules, "AARCH64_negate_ra_state"), true);
  assert.equal(rules.returnAddressSigned, true);
  assert.equal(apply(rules, "AARCH64_negate_ra_state"), true);
  assert.equal(rules.returnAddressSigned, false);
  assert.equal(apply(rules, "nop"), true);
});

for (const operation of ["def_cfa", "def_cfa_sf", "def_cfa_register", "def_cfa_offset",
  "def_cfa_offset_sf", "def_cfa_expression", "offset", "register", "expression", "GNU_args_size"]) {
  void test(`rejects missing operands for ${operation}`, () => {
    assert.equal(apply(state(), operation), false);
  });
}

void test("rejects invalid registers and unknown operations", () => {
  assert.equal(apply(state(), "offset", [-1n, 1n]), false);
  assert.equal(apply(state(), "offset", ["bad", 1n]), false);
  assert.equal(apply(state(), "unknown"), false);
  assert.equal(apply({ ...state(), cfa: null }, "def_cfa_offset", [8n]), false);
  assert.equal(apply({ ...state(), cfa: null }, "def_cfa_register", [8n]), false);
});
