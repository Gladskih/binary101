import type { DwarfLineHeader } from "./line-header.js";
import type { DwarfLineRow } from "./types.js";

// DWARF 5 Tables 6.3/6.4 and section 6.2.5 (including VLIW operation pointers).
// https://dwarfstd.org/doc/DWARF5.pdf
export const createDwarfLineRegisters = (header: DwarfLineHeader): DwarfLineRow => ({
  address: 0n, operationIndex: 0n, file: 1n, line: 1n, column: 0n,
  isStatement: header.defaultIsStatement, basicBlock: false, endSequence: false,
  prologueEnd: false, epilogueBegin: false, isa: 0n, discriminator: 0n
});

export const emitDwarfLineRow = (rows: DwarfLineRow[], state: DwarfLineRow): void => {
  rows.push({ ...state });
  state.basicBlock = false;
  state.prologueEnd = false;
  state.epilogueBegin = false;
  state.discriminator = 0n;
};

export const advanceDwarfLineAddress = (
  state: DwarfLineRow,
  header: DwarfLineHeader,
  operationAdvance: bigint
): void => {
  const maximumOperations = BigInt(header.maximumOperationsPerInstruction);
  const totalOperations = state.operationIndex + operationAdvance;
  state.address += BigInt(header.minimumInstructionLength) *
    (totalOperations / maximumOperations);
  state.operationIndex = totalOperations % maximumOperations;
};
