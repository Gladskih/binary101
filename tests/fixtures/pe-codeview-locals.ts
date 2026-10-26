import { legacyU16, legacyU32 } from "./pe-legacy-codeview.js";

export const localRecord = (type: number, body: readonly number[]): number[] =>
  [...legacyU16(body.length + 2), ...legacyU16(type), ...body];
export const localName = (name: string): number[] => [...new TextEncoder().encode(name), 0];
export const frameRecord = (flags = 0): number[] => localRecord(0x1012,
  [...[64, 8, 24, 16, 0x1234].flatMap(legacyU32), ...legacyU16(3), ...legacyU32(flags)]);
export const localVariableRecord = (name = "value", flags = 1): number[] =>
  localRecord(0x113e, [...legacyU32(0x1001), ...legacyU16(flags), ...localName(name)]);
export const localRangeBytes = (offset = 0x20, length = 32): number[] =>
  [...legacyU32(offset), ...legacyU16(1), ...legacyU16(length)];
