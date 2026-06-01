"use strict";

import type { AttributeCursor } from "./metadata-attribute-cursor.js";

export const TYPE_BOOL = "bool";
export const TYPE_CHAR = "char";
export const TYPE_I1 = "i1";
export const TYPE_U1 = "u1";
export const TYPE_I2 = "i2";
export const TYPE_U2 = "u2";
export const TYPE_I4 = "i4";
export const TYPE_U4 = "u4";
export const TYPE_I8 = "i8";
export const TYPE_U8 = "u8";
export const TYPE_R4 = "r4";
export const TYPE_R8 = "r8";
export const TYPE_STRING = "string";
export const TYPE_SYSTEM_TYPE = "System.Type";
export const TYPE_OBJECT = "object";
export const TYPE_ENUM_PREFIX = "enum ";
export const TYPE_ARRAY_SUFFIX = "[]";

const elementTypeName = (elementType: number): string | null => {
  // ECMA-335 II.23.1.16 names the ELEMENT_TYPE values; these short labels are the
  // analyzer's stable internal representation for CustomAttrib decoding.
  const names: Record<number, string> = {
    0x02: TYPE_BOOL,
    0x03: TYPE_CHAR,
    0x04: TYPE_I1,
    0x05: TYPE_U1,
    0x06: TYPE_I2,
    0x07: TYPE_U2,
    0x08: TYPE_I4,
    0x09: TYPE_U4,
    0x0a: TYPE_I8,
    0x0b: TYPE_U8,
    0x0c: TYPE_R4,
    0x0d: TYPE_R8,
    0x0e: TYPE_STRING,
    0x50: TYPE_SYSTEM_TYPE,
    0x51: TYPE_OBJECT
  };
  return names[elementType] || null;
};

export const readFieldOrPropType = (cursor: AttributeCursor): string | null => {
  const elementType = cursor.readU8();
  if (elementType == null) return null;
  // ECMA-335 II.23.3: FieldOrPropType 0x55 is enum followed by a TypeName.
  if (elementType === 0x55) return `${TYPE_ENUM_PREFIX}${cursor.readSerString() || "?"}`;
  // ECMA-335 II.23.3: FieldOrPropType 0x1d is SZARRAY followed by an element type.
  if (elementType === 0x1d) return `${readFieldOrPropType(cursor) || "?"}${TYPE_ARRAY_SUFFIX}`;
  return elementTypeName(elementType) || `ELEMENT_TYPE_${elementType.toString(16).padStart(2, "0")}`;
};
