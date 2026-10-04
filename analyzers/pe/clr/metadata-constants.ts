"use strict";

import type { PeClrConstantValue } from "./metadata-value-types.js";
import { AttributeCursor } from "./metadata-attribute-cursor.js";
import { readAttributePrimitive } from "./metadata-attribute-primitives.js";
import { decodeMetadataUtf16 } from "./metadata-utf16.js";

// ECMA-335 II.22.9 and II.23.1.16: Constant.Type selects the binary encoding of Value.
const CONSTANT_TYPES: Readonly<Record<number, string>> = {
  2: "bool", 3: "char", 4: "i1", 5: "u1", 6: "i2", 7: "u2", 8: "i4", 9: "u4",
  10: "i8", 11: "u8", 12: "r4", 13: "r8"
};

const readConstantValue = (bytes: Uint8Array, type: number, context: string, issues: string[]) => {
  if (type === 0x0e) {
    return decodeMetadataUtf16(bytes, issues, `${context} constant string`);
  }
  if (type === 0x12) {
    if (bytes.length !== 4 || bytes.some(byte => byte !== 0)) {
      issues.push(`${context} CLASS constant must encode null using four zero bytes.`);
    }
    return null;
  }
  if (!CONSTANT_TYPES[type]) {
    issues.push(`${context} constant type 0x${type.toString(16)} is unsupported.`);
    return Array.from(bytes);
  }
  const cursor = new AttributeCursor(bytes, issues, context);
  const value = readAttributePrimitive(cursor, CONSTANT_TYPES[type]!);
  if (cursor.remaining) issues.push(`${context} constant has ${cursor.remaining} trailing byte(s).`);
  return value?.value ?? null;
};

export const parseConstant = (
  bytes: Uint8Array,
  type: number,
  context: string
): PeClrConstantValue => {
  const issues: string[] = [];
  if (type & 0xff00) issues.push(`${context} constant Type padding byte is not zero.`);
  const value = readConstantValue(bytes, type & 0xff, context, issues);
  return { kind: "constant", value, ...(issues.length ? { issues } : {}) };
};
