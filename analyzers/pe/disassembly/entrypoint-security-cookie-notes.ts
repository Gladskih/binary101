"use strict";

import type { EntrypointIcedModule, IcedInstruction } from "./entrypoint-iced.js";

type SecurityCookieImmediate = {
  value: bigint;
  note: string;
};

// Microsoft documents that an uninitialized __security_cookie falls back to a
// default value and weakens /GS protection:
// https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/security-init-cookie
// The exact values and 0x4711 repair constant are from Visual Studio VCRuntime
// crt/src/vcruntime/gs_support.c and gs_cookie.c.
const KNOWN_SECURITY_COOKIE_IMMEDIATES: readonly SecurityCookieImmediate[] = [
  {
    value: 0xbb40e64en,
    note: "MSVC-compatible x86 /GS default security cookie (0xBB40E64E)."
  },
  {
    value: 0x44bf19b1n,
    note: "Bitwise complement of the MSVC-compatible x86 /GS default security cookie."
  },
  {
    value: 0xbb40e64fn,
    note: "MSVC-compatible x86 /GS default-cookie collision fallback (0xBB40E64F)."
  },
  {
    value: 0x2b992ddfa232n,
    note: "MSVC-compatible x64 /GS default security cookie (0x00002B992DDFA232)."
  },
  {
    value: 0xffffd466d2205dcdn,
    note: "Bitwise complement of the MSVC-compatible x64 /GS default security cookie."
  },
  {
    value: 0x2b992ddfa233n,
    note: "MSVC-compatible x64 /GS default-cookie collision fallback (0x00002B992DDFA233)."
  },
  {
    value: 0x4711n,
    note: "MSVC x86 /GS high-word repair constant for cookies with upper 16 bits zero."
  }
];

const isImmediateOperand = (
  opKinds: EntrypointIcedModule["OpKind"],
  kind: number
): boolean =>
  kind === opKinds["Immediate8"] ||
  kind === opKinds["Immediate8_2nd"] ||
  kind === opKinds["Immediate16"] ||
  kind === opKinds["Immediate32"] ||
  kind === opKinds["Immediate64"] ||
  kind === opKinds["Immediate8to16"] ||
  kind === opKinds["Immediate8to32"] ||
  kind === opKinds["Immediate8to64"] ||
  kind === opKinds["Immediate32to64"];

const readImmediateOperand = (
  instruction: IcedInstruction,
  operand: number
): bigint | null => {
  try {
    return BigInt.asUintN(64, instruction.immediate(operand));
  } catch {
    return null;
  }
};

const describeSecurityCookieImmediate = (value: bigint): string | null =>
  KNOWN_SECURITY_COOKIE_IMMEDIATES.find(known => known.value === value)?.note ?? null;

export const collectSecurityCookieOperandNotes = (
  iced: EntrypointIcedModule,
  instruction: IcedInstruction
): string[] => {
  const notes: string[] = [];
  const seenValues = new Set<bigint>();
  for (let operand = 0; operand < instruction.opCount; operand += 1) {
    if (!isImmediateOperand(iced.OpKind, instruction.opKind(operand))) continue;
    const immediate = readImmediateOperand(instruction, operand);
    if (immediate == null || seenValues.has(immediate)) continue;
    const note = describeSecurityCookieImmediate(immediate);
    if (note) notes.push(note);
    seenValues.add(immediate);
  }
  return notes;
};
