import type { DwarfCursor } from "./cursor.js";
import type { DwarfCfiInstruction } from "./frame-types.js";

// DWARF 5 section 6.4.2; GNU extensions from LLVM Dwarf.def.
// https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/include/llvm/BinaryFormat/Dwarf.def
const instructions: Record<number, [string, string[]]> = {
  0: ["nop", []], 1: ["set_loc", ["address"]], 2: ["advance_loc1", ["1"]],
  3: ["advance_loc2", ["2"]], 4: ["advance_loc4", ["4"]],
  5: ["offset_extended", ["uleb", "uleb"]], 6: ["restore_extended", ["uleb"]],
  7: ["undefined", ["uleb"]], 8: ["same_value", ["uleb"]], 9: ["register", ["uleb", "uleb"]],
  10: ["remember_state", []], 11: ["restore_state", []], 12: ["def_cfa", ["uleb", "uleb"]],
  13: ["def_cfa_register", ["uleb"]], 14: ["def_cfa_offset", ["uleb"]],
  15: ["def_cfa_expression", ["expression"]], 16: ["expression", ["uleb", "expression"]],
  17: ["offset_extended_sf", ["uleb", "sleb"]], 18: ["def_cfa_sf", ["uleb", "sleb"]],
  19: ["def_cfa_offset_sf", ["sleb"]], 20: ["val_offset", ["uleb", "uleb"]],
  21: ["val_offset_sf", ["uleb", "sleb"]], 22: ["val_expression", ["uleb", "expression"]],
  0x2e: ["GNU_args_size", ["uleb"]], 0x2f: ["GNU_negative_offset_extended", ["uleb", "uleb"]]
};

const operand = async <Value>(
  cursor: DwarfCursor, kind: string, addressSize: number, expression: (cursor: DwarfCursor) => Promise<Value | null>
): Promise<bigint | Value | null> => {
  if (kind === "uleb") return cursor.uleb();
  if (kind === "sleb") return cursor.sleb();
  if (kind === "expression") return expression(cursor);
  return cursor.unsigned(kind === "address" ? addressSize : Number(kind));
};

const instruction = async <Value>(
  cursor: DwarfCursor, addressSize: number, machine: number,
  expression: (cursor: DwarfCursor) => Promise<Value | null>
): Promise<DwarfCfiInstruction<Value> | null> => {
  const offset = cursor.position;
  const opcode = await cursor.uint8();
  if (opcode == null) return null;
  const primary = opcode & 0xc0;
  const descriptor = instructionDescriptor(opcode, machine);
  if (!descriptor) {
    cursor.fail(`Unknown CFI opcode 0x${opcode.toString(16)}`);
    return null;
  }
  const operands: Array<bigint | Value> = primary ? [BigInt(opcode & 63)] : [];
  for (const kind of descriptor[1]) {
    const value = await operand(cursor, kind, addressSize, expression);
    if (value == null) return null;
    operands.push(value);
  }
  return { offset, operation: descriptor[0], operands };
};

const instructionDescriptor = (opcode: number, machine: number): [string, string[]] | undefined => {
  const primary = opcode & 0xc0;
  if (primary) {
    return [({ 64: "advance_loc", 128: "offset", 192: "restore" } as Record<number, string>)[primary]!,
      primary === 128 ? ["uleb"] : []];
  }
  if (opcode === 0x2d) return architectureInstruction(machine);
  if (opcode === 0x1d && machine === 8) return ["MIPS_advance_loc8", ["8"]];
  return instructions[opcode];
};

const architectureInstruction = (machine: number): [string, string[]] | undefined => {
  if (machine === 183) return ["AARCH64_negate_ra_state", []];
  return [2, 18, 43].includes(machine) ? ["GNU_window_save", []] : undefined;
};

export const readDwarfCfiInstructions = async <Value>(
  cursor: DwarfCursor, addressSize: number, machine: number,
  expression: (cursor: DwarfCursor) => Promise<Value | null>
): Promise<DwarfCfiInstruction<Value>[]> => {
  const result: DwarfCfiInstruction<Value>[] = [];
  while (cursor.position < cursor.end && !cursor.failed) {
    const next = await instruction(cursor, addressSize, machine, expression);
    if (!next) break;
    result.push(next);
  }
  return result;
};
