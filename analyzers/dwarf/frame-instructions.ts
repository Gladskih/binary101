import type { DwarfCursor } from "./cursor.js";
import { readDwarfCfiInstructions } from "./cfi-instructions.js";
import { decodeDwarfExpression } from "./expressions.js";
import type { DwarfCfiInstruction } from "./frame-types.js";
import type { DwarfExpressionOperation } from "./types.js";

// DWARF 5 6.4.2 prohibits cross-section and circular CFA dependencies in CFI expressions.
// https://dwarfstd.org/doc/DWARF5.pdf
const forbidden = new Set([0x98, 0x99, 0x9a, 0x97, 0x9c, 0xa1, 0xa2, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9]);

const validateExpression = (operations: DwarfExpressionOperation[], cursor: DwarfCursor): void => {
  const pending = [...operations];
  while (pending.length) {
    const operation = pending.pop()!;
    if (forbidden.has(operation.opcode)) cursor.notice("CFI expression uses a forbidden context-dependent operation");
    for (const operand of operation.operands) if (Array.isArray(operand)) pending.push(...operand);
  }
};

export const readDwarfFrameInstructions = async (cursor: DwarfCursor, addressSize: number,
  format: 32 | 64, byteOrder: "little" | "big", machine: number,
  issues: string[]): Promise<DwarfCfiInstruction[]> => readDwarfCfiInstructions(cursor,
  addressSize, machine, async expressionCursor => {
    const size = await expressionCursor.uleb();
    if (size == null) return null;
    const bytes = await expressionCursor.bytes(size);
    if (!bytes) return null;
    const operations = await decodeDwarfExpression(bytes,
      { version: 5, format, addressSize, stringOffsetsBase: null }, byteOrder, issues);
    validateExpression(operations, expressionCursor);
    return operations;
  });
