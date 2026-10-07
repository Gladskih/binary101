import type { DwarfCursor } from "../dwarf/cursor.js";
import { readDwarfCfiInstructions } from "../dwarf/cfi-instructions.js";
import type { ElfCfiInstruction } from "./unwind-types.js";

const expression = async (cursor: DwarfCursor): Promise<string | null> => {
  const size = await cursor.uleb();
  if (size == null) return null;
  // Retain expression bytes for inspection; expression execution needs register/memory state.
  if (size > BigInt(cursor.end - cursor.position)) {
    cursor.fail("CFI expression is truncated");
    return null;
  }
  const bytes: string[] = [];
  for (let index = 0n; index < size; index += 1n) {
    const byte = await cursor.uint8();
    if (byte == null) return null;
    bytes.push(byte.toString(16).padStart(2, "0"));
  }
  return bytes.join("");
};

export const readElfCfiInstructions = async (
  cursor: DwarfCursor, addressSize: number, machine: number
): Promise<ElfCfiInstruction[]> => readDwarfCfiInstructions(cursor, addressSize, machine, expression);
