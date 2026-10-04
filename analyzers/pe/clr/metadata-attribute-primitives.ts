"use strict";

import type { AttributeCursor } from "./metadata-attribute-cursor.js";

export interface AttributeReadValue {
  value: string | number | boolean | null;
  complete: boolean;
}

const signedValue = (value: number | null, bits: number): number | null =>
  value == null ? null : value >= 2 ** (bits - 1) ? value - 2 ** bits : value;

const readInt64 = (cursor: AttributeCursor): string | null => {
  const low = cursor.readU32();
  const high = cursor.readU32();
  if (low == null || high == null) return null;
  // ECMA-335 II.23.3: I8 is a signed 64-bit integer. Preserve precision using decimal text.
  return BigInt.asIntN(64, BigInt(high) * 0x100000000n + BigInt(low)).toString();
};

const readUInt64 = (cursor: AttributeCursor): string | null => {
  const low = cursor.readU32();
  const high = cursor.readU32();
  return low == null || high == null
    ? null : `0x${high.toString(16).padStart(8, "0")}${low.toString(16).padStart(8, "0")}`;
};

const readBoolean = (cursor: AttributeCursor): boolean | null => {
  const value = cursor.readU8();
  return value == null ? null : value !== 0;
};

const readChar = (cursor: AttributeCursor): string | null => {
  const value = cursor.readU16();
  return value == null ? null : String.fromCharCode(value);
};

// ECMA-335 II.23.3: primitive fixed arguments use little-endian values and SerString.
const READERS: Record<string, (cursor: AttributeCursor) => AttributeReadValue["value"]> = {
  string: cursor => cursor.readSerString(), "System.Type": cursor => cursor.readSerString(),
  bool: readBoolean, char: readChar,
  i1: cursor => signedValue(cursor.readU8(), 8), u1: cursor => cursor.readU8(),
  i2: cursor => signedValue(cursor.readU16(), 16), u2: cursor => cursor.readU16(),
  i4: cursor => signedValue(cursor.readU32(), 32), u4: cursor => cursor.readU32(),
  i8: readInt64, u8: readUInt64, r4: cursor => cursor.readF32(), r8: cursor => cursor.readF64()
};

export const isPrimitiveAttributeType = (type: string): boolean =>
  type === "object" || Object.hasOwn(READERS, type);

export const readAttributePrimitive = (
  cursor: AttributeCursor,
  type: string | null
): AttributeReadValue | undefined => {
  if (!type || !Object.hasOwn(READERS, type)) return undefined;
  return primitiveResult(cursor, cursor.issueCount, READERS[type]!(cursor));
};

const primitiveResult = (
  cursor: AttributeCursor,
  issueCount: number,
  value: AttributeReadValue["value"]
): AttributeReadValue => ({ value, complete: cursor.issueCount === issueCount });
