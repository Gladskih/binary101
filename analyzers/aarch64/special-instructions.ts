export type Aarch64InstructionAccess = "EL1+" | "EL2+" | "EL3" | "configuration" | "debug";

export interface Aarch64SpecialInstruction {
  instruction: string;
  access: Aarch64InstructionAccess;
}

export interface Aarch64SpecialInstructionFinding extends Aarch64SpecialInstruction {
  count: number;
  sampleAddresses: bigint[];
}

// A64 encodings: https://github.com/qemu/qemu/blob/master/target/arm/tcg/a64.decode
// MSR (immediate) PSTATE fields, with CRm (the immediate) masked out.
const ACCESS_BY_ENCODING: Readonly<Record<number, Aarch64InstructionAccess>> = {
  0xd500407f: "EL1+", // UAO
  0xd500409f: "EL1+", // PAN
  0xd50040bf: "EL1+", // SPSel
  0xd501401f: "EL1+", // ALLINT
  0xd50340df: "configuration", // DAIFSet: SCTLR_EL1.UMA controls EL0 access.
  0xd50340ff: "configuration", // DAIFClr
  0xd69f03e0: "EL1+", // ERET
  0xd69f0bff: "EL1+", // ERETAA
  0xd69f0fff: "EL1+", // ERETAB
  0xd6bf03e0: "debug", // DRPS: halting debug state, not an ordinary EL requirement.
  0xd4000002: "EL1+", // HVC: target EL2 does not mean caller must be at EL2.
  0xd4000003: "EL1+", // SMC: target EL3 does not mean caller must be at EL3.
  0xd4a00001: "debug", // DCPS1
  0xd4a00002: "debug", // DCPS2
  0xd4a00003: "debug" // DCPS3
};

const systemAccess = (word: number): Aarch64InstructionAccess | null => {
  // Bits [31:22] = 1101010100; op0 [20:19] != 0 selects MRS/MSR/SYS/SYSL.
  if (word >>> 22 !== 0x354 || ((word >>> 19) & 3) === 0) return null;
  // CheckSystemAccess: op1 [18:16] encodes the minimum EL, independent of the
  // printed register suffix. Even SP_EL0 has op1=0 and requires EL1.
  // https://github.com/qemu/qemu/blob/master/target/arm/helper.c (define_one_arm_cp_reg)
  switch ((word >>> 16) & 7) {
    case 3: return null; // May be accessible at EL0; no blanket privilege claim.
    case 4: case 5: return "EL2+";
    case 6: return "EL3";
    default: return "EL1+";
  }
};

// This classifies encoding restrictions, not whether the register/operation exists
// on a particular CPU. Only attach the result after LLVM accepts a complete word.
export const classifyAarch64Privilege = (word: number): Aarch64InstructionAccess | null => {
  if (!Number.isInteger(word) || word < 0 || word > 0xffffffff) return null;
  // Ignore direction L [21] and Rt [4:0] for MRS/MSR DAIF.
  if (((word & 0xffdfffe0) >>> 0) === 0xd51b4220) return "configuration";
  // Clear CRm [11:8] for PSTATE immediates, or imm16 [20:5] for exception instructions.
  return ACCESS_BY_ENCODING[word] ?? ACCESS_BY_ENCODING[(word & 0xfffff0ff) >>> 0] ??
    ACCESS_BY_ENCODING[(word & 0xffe0001f) >>> 0] ?? systemAccess(word);
};

export const createAarch64SpecialInstructionCollector = () => {
  const findings = new Map<string, Aarch64SpecialInstructionFinding>();
  const record = (instruction: Aarch64SpecialInstruction, address: bigint): void => {
    const key = `${instruction.access}:${instruction.instruction}`;
    const previous = findings.get(key);
    const examples = previous?.sampleAddresses ?? [];
    findings.set(key, { ...instruction, count: (previous?.count ?? 0) + 1,
      // Bound examples independently of the number of decoded sites.
      sampleAddresses: examples.length < 3 ? [...examples, address] : examples });
  };
  return { record, findings: (): Aarch64SpecialInstructionFinding[] => [...findings.values()] };
};
