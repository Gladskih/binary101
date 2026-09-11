import { ArmEhabiBytecode, ehabiRegisterMask, ehabiRegisterRange } from "./arm-ehabi-bytecode.js";
import type { ArmEhabiProgram } from "./arm-ehabi-types.js";

type Opcode = (code: ArmEhabiBytecode, byte: number) => string | null;
const popMask: Opcode = (code, byte) => {
  const low = code.byte();
  if (low == null) return null;
  const mask = ((byte & 15) << 8) | low;
  return mask ? `pop {${ehabiRegisterMask("r", 4, mask)}}` : "refuse to unwind";
};
const lowMask = (prefix: string): Opcode => code => {
  const mask = code.byte();
  if (mask == null) return null;
  return mask > 0 && mask < 16 ? `pop {${ehabiRegisterMask(prefix, 0, mask)}}` : null;
};
const vectorRange = (prefix: string, base: number, format: string): Opcode => code => {
  const byte = code.byte();
  if (byte == null) return null;
  const start = base + (byte >> 4);
  const count = (byte & 15) + 1;
  const limit = prefix === "wR" || format === "FSTMFDX" ? 16 : 32;
  if (start + count > limit) return null;
  return `pop {${ehabiRegisterRange(prefix, start, count)}}${format ? ` (${format})` : ""}`;
};

// Arm EHABI32, table 4: https://github.com/ARM-software/abi-aa/blob/main/ehabi32/ehabi32.rst
const extended: Readonly<Record<number, Opcode>> = {
  0xb0: () => "finish", 0xb1: lowMask("r"),
  0xb2: code => { const value = code.uleb(); return value == null ? null : `vsp += ${0x204n + (value << 2n)}`; },
  0xb3: vectorRange("d", 0, "FSTMFDX"),
  0xb4: () => "pop return address authentication code", 0xb5: () => "use vsp as authentication modifier",
  0xc6: vectorRange("wR", 0, ""), 0xc7: lowMask("wCGR"),
  0xc8: vectorRange("d", 16, "VPUSH"), 0xc9: vectorRange("d", 0, "VPUSH")
};
const ranges: { mask: number; value: number; decode: Opcode }[] = [
  { mask: 0xc0, value: 0, decode: (_, byte) => `vsp += ${(byte & 63) * 4 + 4}` },
  { mask: 0xc0, value: 0x40, decode: (_, byte) => `vsp -= ${(byte & 63) * 4 + 4}` },
  { mask: 0xf0, value: 0x80, decode: popMask },
  { mask: 0xf0, value: 0x90, decode: (_, byte) => [13, 15].includes(byte & 15) ? null : `vsp = r${byte & 15}` },
  { mask: 0xf0, value: 0xa0, decode: (_, byte) =>
    `pop {${ehabiRegisterRange("r", 4, (byte & 7) + 1)}${byte & 8 ? ", r14" : ""}}` },
  { mask: 0xf8, value: 0xb8, decode: (_, byte) => `pop {${ehabiRegisterRange("d", 8, (byte & 7) + 1)}} (FSTMFDX)` },
  { mask: 0xf8, value: 0xc0, decode: (_, byte) => `pop {${ehabiRegisterRange("wR", 10, (byte & 7) + 1)}}` },
  { mask: 0xf8, value: 0xd0, decode: (_, byte) => `pop {${ehabiRegisterRange("d", 8, (byte & 7) + 1)}} (VPUSH)` }
];

const decodeOpcode = (code: ArmEhabiBytecode, byte: number): string | null => {
  const decode = extended[byte] ?? ranges.find(range => (byte & range.mask) === range.value)?.decode;
  return decode?.(code, byte) ?? null;
};

export const decodeArmEhabiInstructions = (bytes: number[]): ArmEhabiProgram => {
  const code = new ArmEhabiBytecode(bytes);
  const result: ArmEhabiProgram = { instructions: [], issues: code.issues };
  while (code.position < bytes.length && result.instructions.length < 4096) {
    const offset = code.position;
    const byte = code.byte()!;
    const text = decodeOpcode(code, byte);
    if (!text) {
      if (!code.issues.length) code.issues.push(`Reserved EHABI opcode 0x${byte.toString(16)}.`);
      return result;
    }
    result.instructions.push({ offset, text });
    if (text === "finish" || text === "refuse to unwind") return result;
  }
  if (code.position < bytes.length) code.issues.push("EHABI instruction limit reached.");
  else result.instructions.push({ offset: code.position, text: "finish (implicit)" });
  return result;
};
