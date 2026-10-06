import type { FileRangeReader } from "../file-range-reader.js";
import { DwarfCursor } from "./cursor.js";
import { readDwarfExpressionOperands } from "./expression-operands.js";
import type { DwarfExpressionOperation, DwarfUnitContext } from "./types.js";

type ExpressionFrame = {
  cursor: DwarfCursor;
  base: number;
  operations: DwarfExpressionOperation[];
  instructionEnds: Map<number, number>;
};

const expressionReader = (bytes: Uint8Array): FileRangeReader => {
  const read = async (offset: number, size: number): Promise<DataView> =>
    new DataView(bytes.buffer, bytes.byteOffset + offset, size);
  return { size: bytes.length, read,
    readBytes: async (offset, size) => bytes.subarray(offset, offset + size) };
};

const validateBranches = (frame: ExpressionFrame): void => {
  const boundaries = new Set([...frame.instructionEnds.keys(), frame.cursor.end - frame.base]);
  for (const operation of frame.operations) {
    // DW_OP_bra / DW_OP_skip: displacement from the byte after the instruction (2.5.1.6).
    if (operation.opcode !== 0x28 && operation.opcode !== 0x2f) continue;
    const displacement = operation.operands[0];
    if (typeof displacement !== "bigint") continue;
    const target = BigInt(frame.instructionEnds.get(operation.offset)!) + displacement;
    if (!boundaries.has(Number(target))) frame.cursor.notice(`Invalid expression branch target ${target}`);
  }
};

const expressionOperation = (offset: number, opcode: number,
  operands: Awaited<ReturnType<typeof readDwarfExpressionOperands>>): DwarfExpressionOperation =>
  operands == null ? { offset, opcode, operands: [], incomplete: true } : { offset, opcode, operands: [] };

export const decodeDwarfExpression = async (
  bytes: Uint8Array, context: DwarfUnitContext,
  byteOrder: "little" | "big", issues: string[]
): Promise<DwarfExpressionOperation[]> => {
  const reader = expressionReader(bytes);
  const section = { name: "DWARF expression", offset: 0, size: bytes.length, compressed: false };
  const operations: DwarfExpressionOperation[] = [];
  const frames: ExpressionFrame[] = [{ base: 0, operations, instructionEnds: new Map(),
    cursor: new DwarfCursor(reader, section, 0, bytes.length, byteOrder === "little", issues) }];
  while (frames.length) {
    const frame = frames.at(-1)!;
    if (frame.cursor.failed || frame.cursor.position >= frame.cursor.end) {
      validateBranches(frame);
      frames.pop();
      continue;
    }
    const offset = frame.cursor.position - frame.base;
    const opcode = await frame.cursor.uint8();
    if (opcode == null) continue;
    const operands = await readDwarfExpressionOperands(frame.cursor, opcode, context);
    const operation = expressionOperation(offset, opcode, operands);
    frame.operations.push(operation);
    frame.instructionEnds.set(offset, frame.cursor.position - frame.base);
    for (const operand of operands ?? []) {
      if (typeof operand === "bigint" || operand instanceof Uint8Array) {
        operation.operands.push(operand);
      } else {
        const nested: DwarfExpressionOperation[] = [];
        operation.operands.push(nested);
        frames.push({ base: operand.offset, operations: nested, instructionEnds: new Map(),
          cursor: new DwarfCursor(reader, section, operand.offset, operand.offset + operand.size,
            byteOrder === "little", issues) });
      }
    }
  }
  return operations;
};
