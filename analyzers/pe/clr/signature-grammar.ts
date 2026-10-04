"use strict";

import type { PeClrMethodSignature } from "./types.js";
import type { SignatureCursor } from "./signature-cursor.js";
import { parseArrayShape } from "./signature-array.js";

// ECMA-335 II.23.1.16, II.23.2; CoreCLR corhdr.h also defines UNMANAGED/NATIVEVARARG.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/corhdr.h
const ELEMENT_TYPE_NAMES: Record<number, string> = {
  0x01: "void", 0x02: "bool", 0x03: "char", 0x04: "i1", 0x05: "u1", 0x06: "i2",
  0x07: "u2", 0x08: "i4", 0x09: "u4", 0x0a: "i8", 0x0b: "u8", 0x0c: "r4",
  0x0d: "r8", 0x0e: "string", 0x16: "typedref", 0x18: "native int",
  0x19: "native uint", 0x1c: "object"
};

const parseTypeDefOrRefEncoded = (cursor: SignatureCursor): string | null => {
  const encoded = cursor.readCompressedUInt();
  if (encoded == null) return null;
  const name = ["TypeDef", "TypeRef", "TypeSpec"][encoded & 3];
  if (!name || (encoded >>> 2) === 0) return cursor.fail("has an invalid TypeDefOrRefEncoded token");
  return `${name}#${encoded >>> 2}`;
};

const parseModifiedType = (cursor: SignatureCursor, element: number): string | null => {
  const modifier = parseTypeDefOrRefEncoded(cursor);
  if (!modifier) return null;
  const type = parseSignatureType(cursor);
  return type ? `${type} ${element === 0x1f ? "modreq" : "modopt"} ${modifier}` : null;
};

const parseGenericInstance = (cursor: SignatureCursor): string | null => {
  const kind = cursor.peekU8();
  if (kind !== 0x11 && kind !== 0x12) return cursor.fail("generic instance requires class or valuetype");
  const base = parseSignatureType(cursor);
  if (!base) return null;
  const count = cursor.readCount();
  if (count == null) return null;
  if (!count) return cursor.fail("generic instance has no type arguments");
  const types = parseTypeSequence(cursor, count);
  return types.length === count ? `${base}<${types.join(", ")}>` : null;
};

const parseCompoundType = (cursor: SignatureCursor, element: number): string | null => {
  const type = parseSignatureType(cursor);
  if (type == null) return null;
  if (element === 0x14) {
    const shape = parseArrayShape(cursor);
    return shape ? `${type}${shape}` : null;
  }
  return `${type}${({ 0x0f: "*", 0x10: "&", 0x1d: "[]", 0x45: " pinned" })[element]}`;
};

const parseTypeElement = (cursor: SignatureCursor, element: number): string | null => {
  if (ELEMENT_TYPE_NAMES[element]) return ELEMENT_TYPE_NAMES[element];
  if ([0x0f, 0x10, 0x14, 0x1d, 0x45].includes(element)) return parseCompoundType(cursor, element);
  if ([0x1f, 0x20].includes(element)) return parseModifiedType(cursor, element);
  if (element === 0x15) return parseGenericInstance(cursor);
  if (element === 0x1b) {
    const method = parseMethodSignatureCore(cursor);
    return method ? `fnptr (${method.parameterTypes.join(", ")}) -> ${method.returnType}` : null;
  }
  if ([0x11, 0x12, 0x13, 0x1e].includes(element)) return parseIndexedType(cursor, element);
  return cursor.fail(`has unsupported element type 0x${element.toString(16).padStart(2, "0")}`);
};

const parseIndexedType = (cursor: SignatureCursor, element: number): string | null => {
  if (element === 0x11 || element === 0x12) {
    const token = parseTypeDefOrRefEncoded(cursor);
    return token ? `${element === 0x11 ? "valuetype" : "class"} ${token}` : null;
  }
  const index = cursor.readCompressedUInt();
  return index == null ? null : `${element === 0x13 ? "var" : "mvar"} ${index}`;
};

export const parseSignatureType = (cursor: SignatureCursor): string | null => {
  if (!cursor.enterType()) return null;
  const element = cursor.readU8();
  return finishType(cursor, element == null ? null : parseTypeElement(cursor, element));
};

const finishType = (cursor: SignatureCursor, type: string | null): string | null => {
  cursor.leaveType();
  return type;
};

export const parseTypeSequence = (cursor: SignatureCursor, count: number): string[] => {
  const types: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const type = parseSignatureType(cursor);
    if (type == null) break;
    types.push(type);
  }
  return types;
};

const parseParameters = (
  cursor: SignatureCursor,
  count: number,
  convention: number
): Pick<PeClrMethodSignature, "parameterTypes" | "sentinelIndex"> => {
  const parameterTypes: string[] = [];
  let sentinelIndex: number | undefined;
  for (let index = 0; index < count; index += 1) {
    if (cursor.peekU8() === 0x41) {
      if (sentinelIndex != null || (convention !== 0x05 && convention !== 0x0b)) {
        cursor.fail("has a duplicate sentinel or a sentinel outside a vararg signature");
        break;
      }
      cursor.readU8();
      sentinelIndex = index;
    }
    const type = parseSignatureType(cursor);
    if (type == null) break;
    parameterTypes.push(type);
  }
  return { parameterTypes, ...(sentinelIndex == null ? {} : { sentinelIndex }) };
};

export const parseMethodSignatureCore = (cursor: SignatureCursor): PeClrMethodSignature | null => {
  // ECMA-335 II.23.2.1-3: header, optional generic arity, parameter count, return type, parameters.
  const callingConvention = cursor.readU8();
  if (callingConvention == null) return null;
  if (!validateMethodHeader(cursor, callingConvention)) return null;
  const genericParameterCount = (callingConvention & 0x10) ? cursor.readCompressedUInt() : undefined;
  if (genericParameterCount === null) return null;
  const parameterCount = cursor.readCount();
  if (parameterCount == null) return null;
  const returnType = parseSignatureType(cursor);
  return {
    callingConvention,
    ...(genericParameterCount == null ? {} : { genericParameterCount }),
    parameterCount,
    returnType,
    ...parseParameters(cursor, parameterCount, callingConvention & 0x0f)
  };
};

const validateMethodHeader = (cursor: SignatureCursor, header: number): boolean => {
  if (![0, 1, 2, 3, 4, 5, 8, 9, 0x0b].includes(header & 0x0f) || (header & 0x80)) {
    cursor.fail("has an invalid method/property calling convention");
    return false;
  }
  if ((header & 0x40) && !(header & 0x20)) {
    cursor.fail("uses EXPLICITTHIS without HASTHIS");
    return false;
  }
  return true;
};

export const parseFieldSignatureCore = (cursor: SignatureCursor): PeClrMethodSignature | null => {
  // ECMA-335 II.23.2.4: FIELD, then exactly one type.
  if (cursor.readU8() !== 0x06) return cursor.fail("does not start with FIELD");
  return {
    callingConvention: 0x06,
    parameterCount: 0,
    returnType: parseSignatureType(cursor),
    parameterTypes: []
  };
};
