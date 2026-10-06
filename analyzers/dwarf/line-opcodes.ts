import { DWARF_LINE_STANDARD_OPCODE as opcode } from "./constants.js";
import type { DwarfCursor } from "./cursor.js";
import type { DwarfLineHeader } from "./line-header.js";
import { advanceDwarfLineAddress, emitDwarfLineRow } from "./line-registers.js";
import type { DwarfLineRow } from "./types.js";

const unsignedRegisters = new Map<number, "file" | "column" | "isa">([
  [opcode.setFile, "file"], [opcode.setColumn, "column"], [opcode.setIsa, "isa"]
]);
const flagRegisters = new Map<number, "basicBlock" | "prologueEnd" | "epilogueBegin">([
  [opcode.setBasicBlock, "basicBlock"],
  [opcode.setPrologueEnd, "prologueEnd"], [opcode.setEpilogueBegin, "epilogueBegin"]
]);

const skipDeclaredOperands = async (
  cursor: DwarfCursor, header: DwarfLineHeader, code: number
): Promise<boolean> => {
  cursor.notice(`Unknown standard line opcode ${code}; skipping its declared operands`);
  for (let index = 0; index < (header.standardOperandCounts[code - 1] ?? 0); index += 1) {
    if (await cursor.uleb() == null) return false;
  }
  return true;
};

const executeAddressOpcode = async (
  cursor: DwarfCursor, header: DwarfLineHeader, state: DwarfLineRow, code: number
): Promise<boolean> => {
  if (code === opcode.advancePc) {
    const advance = await cursor.uleb();
    if (advance == null) return false;
    advanceDwarfLineAddress(state, header, advance);
  } else if (code === opcode.fixedAdvancePc) {
    const advance = await cursor.uint16();
    if (advance == null) return false;
    state.address += BigInt(advance);
    state.operationIndex = 0n;
  } else if (code === opcode.constantAddPc) {
    // DWARF 5 6.2.5.2: the address advance of special opcode 255.
    advanceDwarfLineAddress(state, header, BigInt(Math.floor(
      (0xff - header.opcodeBase) / header.lineRange
    )));
  } else return skipDeclaredOperands(cursor, header, code);
  return true;
};

export const executeDwarfStandardLineOpcode = async (
  cursor: DwarfCursor, header: DwarfLineHeader, state: DwarfLineRow,
  rows: DwarfLineRow[], code: number
): Promise<boolean> => {
  const unsignedRegister = unsignedRegisters.get(code);
  const flagRegister = flagRegisters.get(code);
  if (unsignedRegister != null) {
    const value = await cursor.uleb();
    if (value == null) return false;
    state[unsignedRegister] = value;
  } else if (flagRegister != null) state[flagRegister] = true;
  else if (code === opcode.copy) emitDwarfLineRow(rows, state);
  else if (code === opcode.negateStatement) state.isStatement = !state.isStatement;
  else if (code === opcode.advanceLine) {
    const advance = await cursor.sleb();
    if (advance == null) return false;
    state.line += advance;
  } else return executeAddressOpcode(cursor, header, state, code);
  return true;
};
