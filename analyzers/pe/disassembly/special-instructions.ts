import type { IcedInstructionObject, IcedX86Module } from "../../x86/disassembly-iced.js";
import {
  SPECIAL_INSTRUCTION_CATALOG,
  type PeSpecialInstructionCategory
} from "./special-instruction-catalog.js";

export interface PeSpecialInstructionFinding {
  categories: PeSpecialInstructionCategory[];
  instruction: string;
  count: number;
  sampleRvas: number[];
}

// iced's privileged flag includes CPL=0 and these IOPL-sensitive instructions.
// https://docs.rs/iced-x86/1.21.0/iced_x86/struct.Instruction.html#method.is_privileged
const categoriesOf = (
  instruction: IcedInstructionObject,
  label: string
): PeSpecialInstructionCategory[] => {
  const purpose = SPECIAL_INSTRUCTION_CATALOG[label]?.[0] ??
    (label.startsWith("INT ") ? "trap" : null);
  const categories = purpose ? [purpose] : [];
  if (instruction.isPrivileged && purpose !== "io-privilege" && purpose !== "privileged") {
    categories.push("privileged");
  }
  return categories;
};

const instructionLabel = (
  iced: IcedX86Module, instruction: IcedInstructionObject, mnemonic: string
): string => {
  if (mnemonic === "Int") return `INT 0x${instruction.immediate(0).toString(16).toUpperCase()}`;
  if (mnemonic !== "Mov") return mnemonic.toUpperCase();
  for (let operand = 0; operand < instruction.opCount; operand++) {
    if (instruction.opKind(operand) !== iced.OpKind["Register"]) continue;
    const register = iced.Register?.[instruction.opRegister(operand)] ?? "";
    if (/^(CR|DR)\d+$/.test(register)) return `MOV ${register.slice(0, 2)}`;
  }
  return "MOV";
};

const sampleRvas = (previous: number[], address: bigint): number[] => {
  // Keep three navigation examples per mnemonic, independent of its total count.
  // PE RVAs are DWORDs: Microsoft PE/COFF specification, "General Concepts".
  if (previous.length >= 3 || address < 0n || address > 0xffffffffn) return previous;
  return [...previous, Number(address)];
};

export const createPeSpecialInstructionCollector = (iced: IcedX86Module, imageBase = 0n) => {
  const findings = new Map<string, PeSpecialInstructionFinding>();
  const record = (instruction: IcedInstructionObject): void => {
    if (instruction.code === iced.Code["INVALID"]) return;
    const mnemonic = iced.Mnemonic?.[instruction.mnemonic];
    if (!mnemonic) return;
    const label = instructionLabel(iced, instruction, mnemonic);
    const categories = categoriesOf(instruction, label);
    if (!categories.length) return;
    findings.set(label, {
      categories,
      instruction: label,
      count: (findings.get(label)?.count ?? 0) + 1,
      sampleRvas: sampleRvas(findings.get(label)?.sampleRvas ?? [], instruction.ip - imageBase)
    });
  };
  return { record, findings: (): PeSpecialInstructionFinding[] => [...findings.values()] };
};
