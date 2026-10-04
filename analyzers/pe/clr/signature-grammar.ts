"use strict";

import type { PeClrMethodSignature } from "./types.js";
import type { SignatureCursor } from "./signature-cursor.js";
import { parseArrayShape } from "./signature-array.js";
import { runMetadataDecoding, type MetadataDecodingTask } from "./metadata-decoding-stack.js";
import { parseMethodSignatureTask } from "./signature-method.js";

// ECMA-335 II.23.1.16 and II.23.2 define these primitive signature element codes.
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

function* parseModifiedType(cursor: SignatureCursor, element: number): MetadataDecodingTask<string | null> {
  const modifier = parseTypeDefOrRefEncoded(cursor);
  if (!modifier) return null;
  const type = (yield parseSignatureTypeTask(cursor)) as string | null;
  return type ? `${type} ${element === 0x1f ? "modreq" : "modopt"} ${modifier}` : null;
}

function* parseGenericInstance(cursor: SignatureCursor): MetadataDecodingTask<string | null> {
  const kind = cursor.peekU8();
  if (kind !== 0x11 && kind !== 0x12) return cursor.fail("generic instance requires class or valuetype");
  const base = (yield parseSignatureTypeTask(cursor)) as string | null;
  if (!base) return null;
  const count = cursor.readCount();
  if (count == null) return null;
  if (!count) return cursor.fail("generic instance has no type arguments");
  const types: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const type = (yield parseSignatureTypeTask(cursor)) as string | null;
    if (type == null) return null;
    types.push(type);
  }
  return `${base}<${types.join(", ")}>`;
}

function* parseCompoundType(cursor: SignatureCursor, element: number): MetadataDecodingTask<string | null> {
  const type = (yield parseSignatureTypeTask(cursor)) as string | null;
  if (type == null) return null;
  if (element === 0x14) {
    const shape = parseArrayShape(cursor);
    return shape ? `${type}${shape}` : null;
  }
  return `${type}${({ 0x0f: "*", 0x10: "&", 0x1d: "[]", 0x45: " pinned" })[element]}`;
}

const functionPointerText = (method: PeClrMethodSignature): string => {
  const parameters = [...method.parameterTypes];
  if (method.sentinelIndex != null) parameters.splice(method.sentinelIndex, 0, "...");
  return `fnptr${method.callingConvention ? ` [cc=0x${method.callingConvention.toString(16)}` +
    `${method.genericParameterCount == null ? "" : `; generic=${method.genericParameterCount}`}]` : ""}` +
    ` (${parameters.join(", ")}) -> ${method.returnType}`;
};

export function* parseSignatureTypeTask(cursor: SignatureCursor): MetadataDecodingTask<string | null> {
  const element = cursor.readU8();
  if (element == null) return null;
  if (ELEMENT_TYPE_NAMES[element]) return ELEMENT_TYPE_NAMES[element]!;
  if ([0x0f, 0x10, 0x14, 0x1d, 0x45].includes(element)) {
    return (yield parseCompoundType(cursor, element)) as string | null;
  }
  if ([0x1f, 0x20].includes(element)) return (yield parseModifiedType(cursor, element)) as string | null;
  if (element === 0x15) return (yield parseGenericInstance(cursor)) as string | null;
  if (element === 0x1b) {
    const method = (yield parseMethodSignatureTask(cursor)) as PeClrMethodSignature | null;
    return method ? functionPointerText(method) : null;
  }
  return parseIndexedType(cursor, element);
}

const parseIndexedType = (cursor: SignatureCursor, element: number): string | null => {
  if (element === 0x11 || element === 0x12) {
    const token = parseTypeDefOrRefEncoded(cursor);
    return token ? `${element === 0x11 ? "valuetype" : "class"} ${token}` : null;
  }
  if (element === 0x13 || element === 0x1e) {
    const index = cursor.readCompressedUInt();
    return index == null ? null : `${element === 0x13 ? "var" : "mvar"} ${index}`;
  }
  return cursor.fail(`has unsupported element type 0x${element.toString(16).padStart(2, "0")}`);
};

export const parseSignatureType = (cursor: SignatureCursor): string | null =>
  runMetadataDecoding(parseSignatureTypeTask(cursor));

export const parseTypeSequence = (cursor: SignatureCursor, count: number): string[] => {
  const types: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const type = parseSignatureType(cursor);
    if (type == null) break;
    types.push(type);
  }
  return types;
};
