import type { DwarfCursor } from "./cursor.js";
import type { DwarfMacroHeader } from "./macro-types.js";

// DWARF 5 6.3.1: flags 1/2/4 select offset width, line offset and operand descriptors.
// https://dwarfstd.org/doc/DWARF5.pdf
const allowedForms = new Set([
  0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
  0x0e, 0x0f, 0x17, 0x1a, 0x1d, 0x1e, 0x1f, 0x25, 0x26, 0x27, 0x28
]);

const readOperandForms = async (cursor: DwarfCursor): Promise<number[] | null> => {
  const count = await cursor.uleb();
  if (count == null) return null;
  if (count > BigInt(cursor.end - cursor.position)) {
    cursor.fail("Macro operand descriptor count exceeds remaining bytes");
    return null;
  }
  const forms: number[] = [];
  for (let index = 0n; index < count; index += 1n) {
    const form = await cursor.uint8();
    if (form == null) return null;
    if (!allowedForms.has(form)) { cursor.fail(`Invalid macro operand form ${form}`); return null; }
    forms.push(form);
  }
  return forms;
};

const readDescriptors = async (cursor: DwarfCursor): Promise<Map<number, number[]> | null> => {
  const count = await cursor.uint8();
  if (count == null) return null;
  const descriptors = new Map<number, number[]>();
  for (let index = 0; index < count; index += 1) {
    const opcode = await cursor.uint8();
    if (opcode == null) return null;
    if (!opcode || descriptors.has(opcode)) {
      cursor.fail("Zero or duplicate macro opcode descriptor");
      return null;
    }
    const forms = await readOperandForms(cursor);
    if (!forms) return null;
    descriptors.set(opcode, forms);
  }
  return descriptors;
};

const validHeader = (cursor: DwarfCursor, version: number, flags: number): boolean => {
  if ([4, 5].includes(version) && !(flags & ~7)) return true;
  cursor.fail("Unsupported macro version or reserved header flags");
  return false;
};

const readModernHeader = async (cursor: DwarfCursor): Promise<DwarfMacroHeader | null> => {
  const version = await cursor.uint16();
  const flags = await cursor.uint8();
  if (version == null || flags == null) return null;
  // GNU .debug_macro version 4 uses the DWARF 5 opcode encoding (LLVM DWARFDebugMacro.cpp).
  if (!validHeader(cursor, version, flags)) return null;
  const format = flags & 1 ? 64 : 32;
  const lineOffset = flags & 2 ? await cursor.unsigned(format / 8) : null;
  const operandForms = flags & 4 ? await readDescriptors(cursor) : new Map<number, number[]>();
  if (cursor.failed) return null;
  return operandForms ? { version, format, lineOffset, operandForms } : null;
};

export const readDwarfMacroHeader = async (
  cursor: DwarfCursor, sectionName: string
): Promise<DwarfMacroHeader | null> => sectionName === ".debug_macinfo"
  ? { version: null, format: 32, lineOffset: null, operandForms: new Map() }
  : readModernHeader(cursor);
