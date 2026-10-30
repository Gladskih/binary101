import type { WasmReader } from "./reader.js";
import type { WasmInstruction } from "./types.js";
import { CORE_OPCODES } from "./core-opcodes.js";
import { BULK_OPCODES } from "./bulk-opcodes.js";
import { SIMD_OPCODES } from "./simd-opcodes.js";
import { ATOMIC_OPCODES } from "./atomic-opcodes.js";
import {
  readBulkOperands, readCoreOperands, readMemoryArgument, readSimdOperands
} from "./instruction-operands.js";

const readPrefixed = async (reader: WasmReader, prefix: number): Promise<WasmInstruction> => {
  const offset = reader.offset - 1;
  const opcode = await reader.u32();
  const catalog = prefix === 0xfc ? BULK_OPCODES : prefix === 0xfd ? SIMD_OPCODES : ATOMIC_OPCODES;
  const mnemonic = catalog[opcode];
  if (!mnemonic) throw new Error(`Unsupported opcode 0x${prefix.toString(16)}:${opcode} at ${offset}`);
  if (prefix === 0xfc) return { offset, mnemonic, operands: await readBulkOperands(reader, opcode) };
  if (prefix === 0xfd) return { offset, mnemonic, operands: await readSimdOperands(reader, opcode) };
  if (opcode === 3) {
    if (await reader.byte() !== 0) throw new Error("Invalid atomic.fence reserved byte");
    return { offset, mnemonic, operands: "" };
  }
  return { offset, mnemonic, operands: await readMemoryArgument(reader) };
};

export const readInstruction = async (reader: WasmReader): Promise<WasmInstruction> => {
  const offset = reader.offset;
  const opcode = await reader.byte();
  if (opcode === 0xfc || opcode === 0xfd || opcode === 0xfe) return readPrefixed(reader, opcode);
  const mnemonic = CORE_OPCODES[opcode];
  if (!mnemonic) throw new Error(`Unsupported opcode 0x${opcode.toString(16)} at ${offset}`);
  return { offset, mnemonic, operands: await readCoreOperands(reader, opcode) };
};

const advanceFrames = (frames: Array<string | undefined>, mnemonic: string): void => {
  if (["block", "loop", "if", "try", "try_table"].includes(mnemonic)) frames.push(mnemonic);
  if (mnemonic === "else") {
    if (frames.at(-1) !== "if") throw new Error("Unexpected else instruction");
    // Clearing the mnemonic prevents a second else from matching the same if.
    frames[frames.length - 1] = undefined;
  }
  if (mnemonic === "end") frames.pop();
  if (mnemonic === "delegate") {
    if (frames.pop() !== "try") throw new Error("Unexpected delegate instruction");
  }
};

export const readExpression = async (reader: WasmReader,
  instructions: WasmInstruction[] = []): Promise<WasmInstruction[]> => {
  // The outer expression has no opening instruction mnemonic.
  const frames: Array<string | undefined> = [undefined];
  while (frames.length) {
    const instruction = await readInstruction(reader);
    instructions.push(instruction);
    advanceFrames(frames, instruction.mnemonic);
  }
  return instructions;
};
