"use strict";

import type { PeClrMarshallingDescriptor } from "./metadata-value-types.js";
import { MetadataBlobCursor } from "./metadata-blob-cursor.js";

// ECMA-335 II.23.4 plus the runtime's CorNativeType extensions:
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/corhdr.h
const NATIVE_TYPES: Readonly<Record<number, string>> = {
  0: "END", 1: "VOID", 2: "BOOLEAN", 3: "I1", 4: "U1", 5: "I2", 6: "U2", 7: "I4", 8: "U4",
  9: "I8", 10: "U8", 11: "R4", 12: "R8", 13: "SYSCHAR", 14: "VARIANT", 15: "CURRENCY",
  16: "PTR", 17: "DECIMAL", 18: "DATE", 19: "BSTR", 20: "LPSTR", 21: "LPWSTR", 22: "LPTSTR",
  23: "FIXEDSYSSTRING", 24: "OBJECTREF", 25: "IUNKNOWN", 26: "IDISPATCH", 27: "STRUCT",
  28: "INTERFACE", 29: "SAFEARRAY", 30: "FIXEDARRAY", 31: "INT", 32: "UINT", 33: "NESTEDSTRUCT",
  34: "BYVALSTR", 35: "ANSIBSTR", 36: "TBSTR", 37: "VARIANTBOOL", 38: "FUNC", 40: "ASANY",
  42: "ARRAY", 43: "LPSTRUCT", 44: "CUSTOMMARSHALER", 45: "ERROR", 46: "IINSPECTABLE",
  47: "HSTRING", 48: "LPUTF8STR"
};

const optionalIntegers = (cursor: MetadataBlobCursor, keys: string[]): Record<string, number | null> => {
  const parameters: Record<string, number | null> = {};
  for (const key of keys) {
    if (!cursor.remaining) break;
    parameters[key] = cursor.readCompressedUInt();
  }
  return parameters;
};

const customMarshaler = (cursor: MetadataBlobCursor): PeClrMarshallingDescriptor["parameters"] => ({
  guid: cursor.readUtf8(), nativeTypeName: cursor.readUtf8(),
  marshalerType: cursor.readUtf8(), cookie: cursor.readUtf8()
});

const safeArray = (cursor: MetadataBlobCursor): PeClrMarshallingDescriptor["parameters"] => ({
  ...optionalIntegers(cursor, ["variantType"]),
  ...(cursor.remaining ? { userDefinedType: cursor.readUtf8() } : {})
});

// dnlib MarshalBlobReader documents optional runtime fields and CustomMarshaler string order.
// https://github.com/0xd4d/dnlib/blob/master/src/DotNet/MarshalBlobReader.cs
type ParameterReader = (cursor: MetadataBlobCursor) => PeClrMarshallingDescriptor["parameters"];
const parameterReaders: Readonly<Record<number, ParameterReader>> = {
  0x17: cursor => optionalIntegers(cursor, ["size"]),
  0x19: cursor => optionalIntegers(cursor, ["iidParameterIndex"]),
  0x1a: cursor => optionalIntegers(cursor, ["iidParameterIndex"]),
  0x1c: cursor => optionalIntegers(cursor, ["iidParameterIndex"]),
  0x1d: safeArray,
  0x1e: cursor => optionalIntegers(cursor, ["size", "elementType"]),
  0x2a: cursor => optionalIntegers(cursor, ["elementType", "sizeParameterIndex", "size", "flags"]),
  0x2c: customMarshaler
};

export const parseMarshallingDescriptor = (
  bytes: Uint8Array,
  context: string
): PeClrMarshallingDescriptor => {
  const cursor = new MetadataBlobCursor(bytes, [], context);
  const code = cursor.readU8();
  const nativeType = code == null ? "unknown" : NATIVE_TYPES[code] ?? `0x${code.toString(16)}`;
  if (code != null && !NATIVE_TYPES[code]) cursor.issues.push(`${context}: unsupported native type ${nativeType}.`);
  const parameters = code == null ? {} : parameterReaders[code]?.(cursor) ?? {};
  cursor.finish();
  return { kind: "marshal", nativeType, parameters, ...(cursor.issues.length ? { issues: cursor.issues } : {}) };
};
