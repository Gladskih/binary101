import type { DwarfCursor } from "../dwarf/cursor.js";
import { decodeArmEhabiInstructions } from "./arm-ehabi-opcodes.js";
import type { ArmEhabiEntry } from "./arm-ehabi-types.js";

// Arm EHABI32, exception-handling table entries and compact model, sections 6 and 9.
// https://github.com/ARM-software/abi-aa/blob/main/ehabi32/ehabi32.rst
export const armPrel31 = (word: number, place: bigint): bigint =>
  BigInt.asUintN(32, place + BigInt((word << 1) >> 1));

const instructionBytes = (word: number, count: number): number[] =>
  Array.from({ length: count }, (_, index) => (word >>> ((count - index - 1) * 8)) & 255);

const readInstructionBytes = async (word: number, personality: number,
  continuation: DwarfCursor | null): Promise<number[] | null> => {
  const bytes = instructionBytes(word, personality === 0 ? 3 : 2);
  const extraWords = personality === 0 ? 0 : (word >>> 16) & 255;
  for (let index = 0; index < extraWords; index++) {
    const next = await continuation!.uint32();
    if (next == null) return null;
    bytes.push(...instructionBytes(next, 4));
  }
  return bytes;
};

export const readArmEhabiProgram = async (
  word: number, continuation: DwarfCursor | null, entry: ArmEhabiEntry
): Promise<void> => {
  if (!(word & 0x80000000)) {
    entry.personality = armPrel31(word, entry.tableAddress!);
    entry.issues.push("Generic EHABI personality: its language-specific payload is not decoded.");
    return;
  }
  const personality = (word >>> 24) & 15;
  if ((word & 0x70000000) || personality > 2) {
    entry.issues.push("Reserved EHABI compact personality or header bits.");
    return;
  }
  entry.personality = personality;
  if (!continuation && personality !== 0) {
    entry.issues.push("Inline EHABI entries require compact personality 0.");
    return;
  }
  const bytes = await readInstructionBytes(word, personality, continuation);
  if (!bytes) return;
  const decoded = decodeArmEhabiInstructions(bytes);
  entry.instructions = decoded.instructions;
  entry.issues.push(...decoded.issues);
};
