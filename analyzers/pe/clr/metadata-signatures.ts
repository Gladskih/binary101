"use strict";

import type { PeClrMethodSignature } from "./types.js";
import { readCompressedUInt } from "./metadata-heaps.js";

// ECMA-335 II.23.1.16 defines ELEMENT_TYPE values used inside signatures.
// Spec: https://docs.ecma-international.org/ecma-335/Ecma-335-part-i-iv.pdf
const ELEMENT_TYPE_NAMES: Record<number, string> = {
  0x01: "void",
  0x02: "bool",
  0x03: "char",
  0x04: "i1",
  0x05: "u1",
  0x06: "i2",
  0x07: "u2",
  0x08: "i4",
  0x09: "u4",
  0x0a: "i8",
  0x0b: "u8",
  0x0c: "r4",
  0x0d: "r8",
  0x0e: "string",
  0x16: "typedref",
  0x18: "native int",
  0x19: "native uint",
  0x1c: "object"
};

class SignatureCursor {
  offset = 0;

  constructor(
    private readonly bytes: Uint8Array,
    private readonly issues: string[],
    private readonly context: string
  ) {}

  readU8(): number | null {
    const value = this.bytes[this.offset];
    if (value == null) {
      this.issues.push(`${this.context} signature is truncated.`);
      return null;
    }
    this.offset += 1;
    return value;
  }

  readCompressedUInt(): number | null {
    const value = readCompressedUInt(this.bytes, this.offset);
    if (!value) {
      this.issues.push(`${this.context} signature has a malformed compressed integer.`);
      return null;
    }
    this.offset += value.size;
    return value.value;
  }

  peekU8(): number | null {
    return this.bytes[this.offset] ?? null;
  }
}

const parseTypeDefOrRefEncoded = (cursor: SignatureCursor): string | null => {
  const encoded = cursor.readCompressedUInt();
  if (encoded == null) return null;
  const tags = ["TypeDef", "TypeRef", "TypeSpec"];
  return `${tags[encoded & 3] || "InvalidType"}#${encoded >>> 2}`;
};

const parseArrayShape = (cursor: SignatureCursor): void => {
  const rank = cursor.readCompressedUInt();
  if (rank == null) return;
  const sizes = cursor.readCompressedUInt();
  if (sizes == null) return;
  for (let index = 0; index < sizes; index += 1) cursor.readCompressedUInt();
  const bounds = cursor.readCompressedUInt();
  if (bounds == null) return;
  for (let index = 0; index < bounds; index += 1) cursor.readCompressedUInt();
};

const parseCustomMod = (cursor: SignatureCursor, prefix: string): string | null => {
  const typeName = parseTypeDefOrRefEncoded(cursor);
  const next = parseSignatureType(cursor);
  return next ? `${next} ${prefix} ${typeName || "?"}` : null;
};

const parseSignatureType = (cursor: SignatureCursor): string | null => {
  const elementType = cursor.readU8();
  if (elementType == null) return null;
  const simple = ELEMENT_TYPE_NAMES[elementType];
  if (simple) return simple;
  if (elementType === 0x0f) return `${parseSignatureType(cursor) || "?"}*`;
  if (elementType === 0x10) return `${parseSignatureType(cursor) || "?"}&`;
  if (elementType === 0x11 || elementType === 0x12) {
    const kind = elementType === 0x11 ? "valuetype" : "class";
    return `${kind} ${parseTypeDefOrRefEncoded(cursor) || "?"}`;
  }
  if (elementType === 0x13 || elementType === 0x1e) {
    const index = cursor.readCompressedUInt();
    return `${elementType === 0x13 ? "var" : "mvar"} ${index ?? "?"}`;
  }
  if (elementType === 0x14) {
    const arrayType = parseSignatureType(cursor);
    parseArrayShape(cursor);
    return `${arrayType || "?"}[]`;
  }
  if (elementType === 0x15) {
    const baseType = parseSignatureType(cursor);
    const count = cursor.readCompressedUInt() ?? 0;
    const args = Array.from({ length: count }, () => parseSignatureType(cursor) || "?");
    return `${baseType || "?"}<${args.join(", ")}>`;
  }
  if (elementType === 0x1b) return `fnptr ${parseMethodSignatureFromCursor(cursor) || "?"}`;
  if (elementType === 0x1d) return `${parseSignatureType(cursor) || "?"}[]`;
  if (elementType === 0x20) return parseCustomMod(cursor, "modreq");
  if (elementType === 0x21) return parseCustomMod(cursor, "modopt");
  if (elementType === 0x45) return `${parseSignatureType(cursor) || "?"} pinned`;
  cursor.readCompressedUInt();
  return `ELEMENT_TYPE_${elementType.toString(16).padStart(2, "0")}`;
};

const parseMethodSignatureFromCursor = (cursor: SignatureCursor): string | null => {
  const signature = parseMethodSignatureCore(cursor);
  if (!signature) return null;
  return `(${signature.parameterTypes.map(type => type || "?").join(", ")}) -> ` +
    `${signature.returnType || "?"}`;
};

const parseMethodSignatureCore = (cursor: SignatureCursor): PeClrMethodSignature | null => {
  // ECMA-335 II.23.2.1: MethodDefSig/MethodRefSig start with calling convention and ParamCount.
  const callingConvention = cursor.readU8();
  if (callingConvention == null) return null;
  const genericParameterCount = (callingConvention & 0x10) !== 0
    ? cursor.readCompressedUInt()
    : null;
  const parameterCount = cursor.readCompressedUInt();
  if (parameterCount == null) return null;
  const returnType = parseSignatureType(cursor);
  const parameterTypes: Array<string | null> = [];
  for (let index = 0; index < parameterCount; index += 1) {
    if (cursor.peekU8() === 0x41) cursor.offset += 1;
    parameterTypes.push(parseSignatureType(cursor));
  }
  return {
    callingConvention,
    ...(genericParameterCount != null ? { genericParameterCount } : {}),
    parameterCount,
    returnType,
    parameterTypes
  };
};

export const parseMethodSignature = (
  blob: Uint8Array | null,
  context: string
): PeClrMethodSignature | undefined => {
  if (!blob) return undefined;
  const issues: string[] = [];
  const parsed = parseMethodSignatureCore(new SignatureCursor(blob, issues, context));
  if (!parsed) return { callingConvention: 0, parameterCount: 0, returnType: null, parameterTypes: [], issues };
  return issues.length ? { ...parsed, issues } : parsed;
};
