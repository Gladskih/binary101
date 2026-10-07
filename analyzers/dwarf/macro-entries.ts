import type { DwarfCursor } from "./cursor.js";
import { readDwarfForm } from "./forms.js";
import type { DwarfMacroEntry, DwarfMacroHeader } from "./macro-types.js";
import type { DwarfStringReader } from "./strings.js";
import type { DwarfFormValue, DwarfUnitContext } from "./types.js";

// DWARF 5 Table 7.27: udata+string, udata+strp/sup/strx, and import section offsets.
const standardForms = new Map<number, number[]>([
  [1, [0x0f, 0x08]], [2, [0x0f, 0x08]], [3, [0x0f, 0x0f]], [4, []],
  [5, [0x0f, 0x0e]], [6, [0x0f, 0x0e]], [7, [0x17]],
  [8, [0x0f, 0x1d]], [9, [0x0f, 0x1d]], [10, [0x17]],
  [11, [0x0f, 0x1a]], [12, [0x0f, 0x1a]]
]);

const legacyLayout = (cursor: DwarfCursor, opcode: number): number[] | null => {
  if (opcode === 255) return [0x0f, 0x08];
  if (opcode <= 4) return standardForms.get(opcode)!;
  cursor.fail(`Unknown legacy macro opcode ${opcode}`);
  return null;
};

const operandLayout = (cursor: DwarfCursor, header: DwarfMacroHeader, opcode: number): number[] | null => {
  if (header.version == null) return legacyLayout(cursor, opcode);
  const standard = standardForms.get(opcode);
  const declared = header.operandForms.get(opcode);
  if (standard && declared && standard.join() !== declared.join()) {
    cursor.fail(`Macro opcode ${opcode} descriptor disagrees with its standard encoding`);
    return null;
  }
  const forms = standard ?? declared;
  if (!forms) cursor.fail(`Unknown macro opcode ${opcode} without an operand descriptor`);
  return forms ?? null;
};

const readOperands = async (cursor: DwarfCursor, forms: number[], context: DwarfUnitContext,
  strings: DwarfStringReader): Promise<DwarfFormValue[] | null> => {
  const operands: DwarfFormValue[] = [];
  for (const form of forms) {
    const value = await readDwarfForm(cursor, { name: 0, form, implicitConstant: null }, context);
    if (!value) return null;
    // String indices depend on the importing compilation unit; resolve them after linking imports.
    const text = value.kind === "string-offset" ? await strings.resolve(value, context) : null;
    operands.push(text == null ? value : { kind: "string", value: text });
  }
  return operands;
};

export const readDwarfMacroEntry = async (cursor: DwarfCursor, header: DwarfMacroHeader,
  strings: DwarfStringReader): Promise<DwarfMacroEntry | "end" | null> => {
  const offset = cursor.position;
  const opcode = await cursor.uint8();
  if (opcode == null) return null;
  if (!opcode) return "end";
  const forms = operandLayout(cursor, header, opcode);
  if (!forms) return null;
  const operands = await readOperands(cursor, forms, {
    version: header.version ?? 4, format: header.format, addressSize: 0, stringOffsetsBase: null
  }, strings);
  return operands ? { offset, opcode, operands } : null;
};
