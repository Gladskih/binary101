import assert from "node:assert/strict";
import { test } from "node:test";
import {
  classifyAarch64Privilege, createAarch64SpecialInstructionCollector
} from "../../../../analyzers/aarch64/special-instructions.js";

// QEMU's A64 encoding table and architectural CheckSystemAccess implementation:
// https://github.com/qemu/qemu/blob/master/target/arm/tcg/a64.decode
// https://github.com/qemu/qemu/blob/master/target/arm/helper.c
for (const [word, access] of [
  [0xd5381000, "EL1+"], // MRS SCTLR_EL1
  [0xd5181001, "EL1+"], // MSR SCTLR_EL1, X1
  [0xd5390000, "EL1+"], [0xd53a0000, "EL1+"], // op1 = 1, 2
  [0xd53c1100, "EL2+"], [0xd53d1000, "EL2+"], // HCR_EL2; op1 = 5
  [0xd53e1100, "EL3"], [0xd53f0000, "EL1+"], // SCR_EL3; secure op1 = 7
  [0xd508871f, "EL1+"], // TLBI VMALLE1
  [0xd5087800, "EL1+"], // AT S1E1R, X0
  [0xd5087620, "EL1+"], // DC IVAC, X0
  [0xd508751f, "EL1+"], // IC IALLU
  [0xd5280000, "EL1+"], // SYSL
  [0xd50041bf, "EL1+"], [0xd500409f, "EL1+"], // MSR SPSel/PAN
  [0xd500407f, "EL1+"], [0xd501411f, "EL1+"], // MSR UAO/ALLINT
  [0xd5034fdf, "configuration"], [0xd5034fff, "configuration"], // DAIFSet/Clr
  [0xd53b4220, "configuration"], [0xd51b4221, "configuration"], // MRS/MSR DAIF
  [0xd4000002, "EL1+"], [0xd41fffe3, "EL1+"], // HVC/SMC with imm16
  [0xd69f03e0, "EL1+"], [0xd69f0bff, "EL1+"], [0xd69f0fff, "EL1+"], // ERET/A/B
  [0xd6bf03e0, "debug"], // DRPS
  [0xd4a00001, "debug"], [0xd4a00002, "debug"], [0xd4bfffe3, "debug"] // DCPS1/2/3
] as const) {
  void test(`A64 privilege encoding 0x${word.toString(16)} requires ${access}`, () => {
    assert.equal(classifyAarch64Privilege(word), access);
  });
}

for (const word of [
  0xd53bd040, 0xd53be040, 0xd53b4400, 0xd51b4200, // TPIDR_EL0, CNTVCT_EL0, FPCR, NZCV
  0xd50b7b20, 0xd50b7520, 0xd50b7420, // DC CVAU, IC IVAU, DC ZVA: can execute at EL0
  0xd503201f, 0xd503207f, 0xd5033fdf, // NOP, WFI, ISB
  0xd503415f, 0xd503419f, 0xd503413f, // MSR DIT/TCO/SSBS: EL0 accessible
  0xd4000001, 0xd4200000, 0xd4400000, 0xd65f03c0, // SVC, BRK, HLT, RET
  0xd4000000, 0xd4a00000, 0xd5000000, // Reserved exception/system op0=0 encodings
  0xffffffff, 0, -1, 2 ** 32, 1.5, NaN, Infinity,
  // Values that would alias a privileged word if coerced to uint32 without validation.
  0xd5381000 - 2 ** 32, 0xd5381000 + 2 ** 32, 0xd5381000 + 0.5
]) {
  void test(`A64 does not claim an unconditional privilege for ${word}`, () => {
    assert.equal(classifyAarch64Privilege(word), null);
  });
}

void test("A64 findings count sites while bounding address examples and keeping access groups", () => {
  const collector = createAarch64SpecialInstructionCollector();

  collector.record({ instruction: "MRS SCTLR_EL1", access: "EL1+" }, 0n);
  collector.record({ instruction: "MRS SCTLR_EL1", access: "EL1+" }, 4n);
  collector.record({ instruction: "MRS SCTLR_EL1", access: "EL1+" }, 8n);
  collector.record({ instruction: "MRS SCTLR_EL1", access: "EL1+" }, 12n);
  collector.record({ instruction: "SYS", access: "EL2+" }, 1n << 63n);
  collector.record({ instruction: "SYS", access: "EL1+" }, 16n);

  assert.deepEqual(collector.findings(), [
    { instruction: "MRS SCTLR_EL1", access: "EL1+", count: 4, sampleAddresses: [0n, 4n, 8n] },
    { instruction: "SYS", access: "EL2+", count: 1, sampleAddresses: [1n << 63n] },
    { instruction: "SYS", access: "EL1+", count: 1, sampleAddresses: [16n] }
  ]);
  assert.deepEqual(createAarch64SpecialInstructionCollector().findings(), []);
});
