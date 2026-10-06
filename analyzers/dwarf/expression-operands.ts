import type { DwarfCursor } from "./cursor.js";
import type { DwarfUnitContext } from "./types.js";

export type NestedDwarfExpression = { offset: number; size: number };
export type DwarfExpressionOperand = bigint | Uint8Array | NestedDwarfExpression;
type OperandEncoding = "uleb" | "sleb" | "u1" | "s1" | "u2" | "s2" |
  "u4" | "s4" | "u8" | "s8" | "address" | "offset" | "block" | "nested" | "byte-block";

// DWARF 5 7.7.1, with GNU extensions from LLVM Dwarf.def.
// https://dwarfstd.org/doc/DWARF5.pdf
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/Dwarf.def
const encodings = new Map<number, OperandEncoding[]>([
  [0x03, ["address"]], [0x08, ["u1"]], [0x09, ["s1"]],
  [0x0a, ["u2"]], [0x0b, ["s2"]], [0x0c, ["u4"]], [0x0d, ["s4"]],
  [0x0e, ["u8"]], [0x0f, ["s8"]], [0x10, ["uleb"]], [0x11, ["sleb"]],
  [0x15, ["u1"]], [0x23, ["uleb"]], [0x28, ["s2"]], [0x2f, ["s2"]],
  [0x90, ["uleb"]], [0x91, ["sleb"]], [0x92, ["uleb", "sleb"]], [0x93, ["uleb"]],
  [0x94, ["u1"]], [0x95, ["u1"]], [0x98, ["u2"]], [0x99, ["u4"]], [0x9a, ["offset"]],
  [0x9d, ["uleb", "uleb"]], [0x9e, ["block"]], [0xa0, ["offset", "sleb"]],
  [0xa1, ["uleb"]], [0xa2, ["uleb"]], [0xa3, ["nested"]], [0xa4, ["uleb", "byte-block"]],
  [0xa5, ["uleb", "uleb"]], [0xa6, ["u1", "uleb"]], [0xa7, ["u1", "uleb"]],
  [0xa8, ["uleb"]], [0xa9, ["uleb"]], [0xf2, ["offset", "sleb"]], [0xf3, ["nested"]],
  [0xf4, ["uleb", "byte-block"]], [0xf5, ["uleb", "uleb"]], [0xf6, ["u1", "uleb"]],
  [0xf7, ["uleb"]], [0xf9, ["uleb"]], [0xfa, ["u4"]], [0xfb, ["uleb"]], [0xfc, ["uleb"]]
]);
const noOperands = new Set([
  0x06, 0x12, 0x13, 0x14, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
  0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x24, 0x25, 0x26, 0x27,
  0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x96, 0x97, 0x9b, 0x9c, 0x9f, 0xe0, 0xf0
]);

const readBlockOperand = async (
  cursor: DwarfCursor, encoding: "block" | "nested" | "byte-block"
): Promise<Uint8Array | NestedDwarfExpression | null> => {
  const size = encoding === "byte-block" ? await cursor.uint8() : await cursor.uleb();
  if (size == null) return null;
  if (encoding !== "nested") return cursor.bytes(size);
  const offset = cursor.position;
  return cursor.skip(size) ? { offset, size: Number(size) } : null;
};

const readOperand = async (
  cursor: DwarfCursor, encoding: OperandEncoding, context: DwarfUnitContext
): Promise<DwarfExpressionOperand | null> => {
  if (encoding === "uleb") return cursor.uleb();
  if (encoding === "sleb") return cursor.sleb();
  if (encoding === "address") return cursor.unsigned(context.addressSize);
  if (encoding === "offset") return cursor.unsigned(context.format / 8);
  if (encoding === "block" || encoding === "nested" || encoding === "byte-block") {
    return readBlockOperand(cursor, encoding);
  }
  const width = Number(encoding.slice(1));
  return readFixedOperand(cursor, width, encoding);
};

const readFixedOperand = async (cursor: DwarfCursor, width: number, encoding: string): Promise<bigint | null> => {
  const value = await cursor.unsigned(width);
  return value == null ? null : encoding.startsWith("s") ? BigInt.asIntN(width * 8, value) : value;
};

export const readDwarfExpressionOperands = async (
  cursor: DwarfCursor, opcode: number, context: DwarfUnitContext
): Promise<DwarfExpressionOperand[] | null> => {
  if ((opcode >= 0x30 && opcode <= 0x6f) || noOperands.has(opcode)) return [];
  const layout = opcode >= 0x70 && opcode <= 0x8f ? ["sleb" as const] : encodings.get(opcode);
  if (!layout) {
    cursor.fail(`Unsupported DWARF expression opcode 0x${opcode.toString(16)}`);
    return null;
  }
  const operands: DwarfExpressionOperand[] = [];
  for (const encoding of layout) {
    const value = await readOperand(cursor, encoding, context);
    if (value == null) return null;
    operands.push(value);
  }
  return operands;
};
