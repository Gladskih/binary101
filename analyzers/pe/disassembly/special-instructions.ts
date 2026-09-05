import type { IcedInstructionObject, IcedX86Module } from "../../x86/disassembly-iced.js";

export type PeSpecialInstructionCategory = "syscall" | "privileged" | "io-privilege" | "trap";

export interface PeSpecialInstructionFinding {
  category: PeSpecialInstructionCategory;
  instruction: string;
  count: number;
}

// iced's privileged flag includes CPL=0 and these IOPL-sensitive instructions.
// https://docs.rs/iced-x86/1.21.0/iced_x86/struct.Instruction.html#method.is_privileged
const SPECIAL_MNEMONICS = {
  ioPrivilege: new Set(["Cli", "Sti", "In", "Insb", "Insw", "Insd",
    "Out", "Outsb", "Outsw", "Outsd"]),
  traps: new Set(["Int", "Int1", "Int3", "Into", "Ud0", "Ud1", "Ud2"])
};

const categoryOf = (
  instruction: IcedInstructionObject,
  mnemonic: string
): PeSpecialInstructionCategory | null => {
  if (mnemonic === "Syscall" || mnemonic === "Sysenter") return "syscall";
  // Windows' historical INT 2Eh gateway; other INT vectors are not Windows syscalls.
  // https://github.com/reactos/reactos/blob/master/ntoskrnl/ke/i386/traphdlr.c
  if (mnemonic === "Int" && instruction.immediate(0) === 0x2en) return "syscall";
  if (SPECIAL_MNEMONICS.ioPrivilege.has(mnemonic)) return "io-privilege";
  if (instruction.isPrivileged) return "privileged";
  return SPECIAL_MNEMONICS.traps.has(mnemonic) ? "trap" : null;
};

const instructionLabel = (instruction: IcedInstructionObject, mnemonic: string): string =>
  mnemonic === "Int"
    ? `INT 0x${instruction.immediate(0).toString(16).toUpperCase()}`
    : mnemonic.toUpperCase();

export const createPeSpecialInstructionCollector = (iced: IcedX86Module) => {
  const findings = new Map<string, PeSpecialInstructionFinding>();
  const record = (instruction: IcedInstructionObject): void => {
    if (instruction.code === iced.Code["INVALID"]) return;
    const mnemonic = iced.Mnemonic?.[instruction.mnemonic];
    if (!mnemonic) return;
    const category = categoryOf(instruction, mnemonic);
    if (!category) return;
    const label = instructionLabel(instruction, mnemonic);
    findings.set(label, {
      category,
      instruction: label,
      count: (findings.get(label)?.count ?? 0) + 1
    });
  };
  return { record, findings: (): PeSpecialInstructionFinding[] => [...findings.values()] };
};
