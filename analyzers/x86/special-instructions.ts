import type { IcedInstructionObject, IcedX86Module } from "./disassembly-iced.js";
import {
  SPECIAL_INSTRUCTION_CATALOG,
  type X86SpecialInstructionCategory
} from "./special-instruction-catalog.js";

export interface X86SpecialInstructionFinding<Address = bigint> {
  categories: X86SpecialInstructionCategory[];
  instruction: string;
  count: number;
  sampleAddresses: Address[];
}

// iced's privileged flag includes CPL=0 and these IOPL-sensitive instructions.
// https://docs.rs/iced-x86/1.21.0/iced_x86/struct.Instruction.html#method.is_privileged
const categoriesOf = (
  instruction: IcedInstructionObject,
  label: string
): X86SpecialInstructionCategory[] => {
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

export const createX86SpecialInstructionCollector = <Address>(
  iced: IcedX86Module, sampleAddress: (address: bigint) => Address | null
) => {
  const findings = new Map<string, X86SpecialInstructionFinding<Address>>();
  const record = (instruction: IcedInstructionObject): void => {
    if (instruction.code === iced.Code["INVALID"]) return;
    const mnemonic = iced.Mnemonic?.[instruction.mnemonic];
    if (!mnemonic) return;
    const label = instructionLabel(iced, instruction, mnemonic);
    const categories = categoriesOf(instruction, label);
    if (!categories.length) return;
    const previous = findings.get(label);
    const address = sampleAddress(instruction.ip);
    const examples = previous?.sampleAddresses ?? [];
    findings.set(label, {
      categories,
      instruction: label,
      count: (previous?.count ?? 0) + 1,
      // Keep at most three examples per mnemonic, independent of the site count.
      sampleAddresses: examples.length < 3 && address !== null ? [...examples, address] : examples
    });
  };
  return { record, findings: (): X86SpecialInstructionFinding<Address>[] => [...findings.values()] };
};
