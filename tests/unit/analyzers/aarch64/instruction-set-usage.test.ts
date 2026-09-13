import assert from "node:assert/strict";
import { test } from "node:test";
import type { FeatureRequirements } from "llvm-aarch64-disasm";
import {
  formatAarch64FeatureExpression, recordAarch64Requirements
} from "../../../../analyzers/aarch64/instruction-set-usage.js";
import type { ElfInstructionSetUsage } from "../../../../analyzers/elf/disassembly-types.js";

void test("AArch64 expressions preserve nesting, negation, constants and unknown feature names", () => {
  assert.equal(formatAarch64FeatureExpression({ all_of: [
    { any_of: [{ feature: "FeatureSVE" }, { feature: "FeatureSME" }] },
    { not: { feature: "unrecognized" } }, true, false
  ] }), "((FEAT_SVE or FEAT_SME) and not (unrecognized) and true and false)");
  assert.equal(formatAarch64FeatureExpression({ feature: "FeatureAES" }), "FEAT_AES, FEAT_PMULL");
});

void test("AArch64 usage distinguishes unknown metadata, empty gates and conjunctive predicates", () => {
  const usage = new Map<string, ElfInstructionSetUsage>();
  const base: FeatureRequirements = {
    source: "llvm-tablegen", scope: "opcode", known: true, predicates: [], nonAssemblerPredicates: []
  };
  recordAarch64Requirements(base, usage);
  recordAarch64Requirements(base, usage);
  recordAarch64Requirements({ ...base, known: false }, usage);
  recordAarch64Requirements({ ...base, predicates: [
    { name: "simd", expression: { feature: "FeatureNEON" } },
    { name: "fp", expression: { feature: "FeatureFPARMv8" } }
  ] }, usage);

  const values = [...usage.values()];
  assert.equal(values.length, 3);
  assert.equal(values[0]?.label, "No recorded LLVM feature gate");
  assert.equal(values[0]?.instructionCount, 2);
  assert.equal(values[1]?.label, "Unknown requirements");
  assert.equal(values[1]?.id, "unknown");
  assert.match(values[1]!.description, /no extracted feature record/);
  assert.equal(values[2]?.label, "FEAT_AdvSIMD and FEAT_FP");
  assert.match(values[2]!.description, /LLVM opcode assembler gates/);
});
