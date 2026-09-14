import assert from "node:assert/strict";
import { test } from "node:test";
import { describeAarch64Features } from "../../../../analyzers/aarch64/feature-descriptions.js";

void test("descriptions preserve unknown features and describe each nested feature once", () => {
  assert.equal(describeAarch64Features([{ all_of: [true, { feature: "missing" },
    { not: { any_of: [false, { feature: "missing" }] } }] }]), "No description available");
  assert.equal(describeAarch64Features([]),
    "LLVM opcode assembler gates; grouped Arm labels are preserved.");
  assert.equal(describeAarch64Features([{ feature: "FeatureNEON" }]), "Advanced SIMD instructions");
});
