import type { IcedX86Module } from "../../x86/disassembly-iced.js";
import {
  createX86SpecialInstructionCollector, type X86SpecialInstructionFinding
} from "../../x86/special-instructions.js";

export interface PeSpecialInstructionFinding extends
  Omit<X86SpecialInstructionFinding<number>, "sampleAddresses"> {
  sampleRvas: number[];
}

export const createPeSpecialInstructionCollector = (iced: IcedX86Module, imageBase = 0n) => {
  const collector = createX86SpecialInstructionCollector(iced, address => {
    const rva = address - imageBase;
    // PE RVAs are DWORDs: Microsoft PE/COFF specification, "General Concepts".
    return rva < 0n || rva > 0xffffffffn ? null : Number(rva);
  });
  return {
    record: collector.record,
    findings: (): PeSpecialInstructionFinding[] => collector.findings().map(
      ({ sampleAddresses, ...finding }) => ({ ...finding, sampleRvas: sampleAddresses })
    )
  };
};
