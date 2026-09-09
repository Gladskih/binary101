import type { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfCfiInstruction } from "./unwind-types.js";

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

const expression = async (cursor: DwarfCursor): Promise<string | null> => {
  const size = await cursor.uleb();
  if (size == null) return null;
  // Retain expression bytes for inspection; expression execution needs register/memory state.
  if (size > 65536n || size > BigInt(cursor.end - cursor.position)) {
    cursor.fail("CFI expression is truncated or exceeds the 64 KiB expression limit");
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

const operand = async (
  cursor: DwarfCursor, kind: string, addressSize: number
): Promise<bigint | string | null> => {
  if (kind === "uleb") return cursor.uleb();
  if (kind === "sleb") return cursor.sleb();
  if (kind === "expression") return expression(cursor);
  return cursor.unsigned(kind === "address" ? addressSize : Number(kind));
};

const instruction = async (
  cursor: DwarfCursor, addressSize: number, machine: number
): Promise<ElfCfiInstruction | null> => {
  const offset = cursor.position;
  const opcode = await cursor.uint8();
  if (opcode == null) return null;
  const primary = opcode & 0xc0;
  const descriptor = instructionDescriptor(opcode, machine);
  if (!descriptor) {
    cursor.fail(`Unknown CFI opcode 0x${opcode.toString(16)}`);
    return null;
  }
  const operands: Array<bigint | string> = primary ? [BigInt(opcode & 63)] : [];
  for (const kind of descriptor[1]) {
    const value = await operand(cursor, kind, addressSize);
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
  return opcode === 0x2d ? [machine === 183 ? "AARCH64_negate_ra_state" : "GNU_window_save", []]
    : instructions[opcode];
};

export const readElfCfiInstructions = async (
  cursor: DwarfCursor, addressSize: number, machine: number
): Promise<ElfCfiInstruction[]> => {
  const result: ElfCfiInstruction[] = [];
  // Resource policy: limit expanded instruction objects per CIE/FDE.
  while (cursor.position < cursor.end && !cursor.failed && result.length < 4096) {
    const next = await instruction(cursor, addressSize, machine);
    if (!next) break;
    result.push(next);
  }
  if (result.length === 4096 && cursor.position < cursor.end) cursor.fail("CFI instruction limit reached");
  return result;
};
