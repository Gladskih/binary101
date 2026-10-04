"use strict";

import type { PeClrMethodSignature } from "./types.js";
import type { SignatureCursor } from "./signature-cursor.js";
import { parseSignatureType, parseSignatureTypeTask } from "./signature-grammar.js";
import { runMetadataDecoding, type MetadataDecodingTask } from "./metadata-decoding-stack.js";

const validateMethodHeader = (cursor: SignatureCursor, header: number): boolean => {
  // ECMA-335 II.23.2.1-3; CoreCLR corhdr.h additionally defines UNMANAGED and NATIVEVARARG.
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

const readMethodHeader = (
  cursor: SignatureCursor
): Pick<PeClrMethodSignature, "callingConvention" | "genericParameterCount" | "parameterCount"> | null => {
  const callingConvention = cursor.readU8();
  if (callingConvention == null || !validateMethodHeader(cursor, callingConvention)) return null;
  const genericParameterCount = (callingConvention & 0x10) ? cursor.readCompressedUInt() : undefined;
  if (genericParameterCount === null) return null;
  const parameterCount = cursor.readCount();
  return parameterCount == null ? null : { callingConvention, parameterCount,
    ...(genericParameterCount == null ? {} : { genericParameterCount }) };
};

type MethodParameters = Pick<PeClrMethodSignature, "parameterTypes" | "sentinelIndex">;

function* parseParameters(
  cursor: SignatureCursor,
  count: number,
  convention: number
): MetadataDecodingTask<MethodParameters> {
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
    const type = (yield parseSignatureTypeTask(cursor)) as string | null;
    if (type == null) break;
    parameterTypes.push(type);
  }
  return { parameterTypes, ...(sentinelIndex == null ? {} : { sentinelIndex }) };
}

export function* parseMethodSignatureTask(
  cursor: SignatureCursor
): MetadataDecodingTask<PeClrMethodSignature | null> {
  const header = readMethodHeader(cursor);
  if (!header) return null;
  const returnType = (yield parseSignatureTypeTask(cursor)) as string | null;
  return { ...header, returnType,
    ...(yield parseParameters(cursor, header.parameterCount, header.callingConvention & 0x0f)) as MethodParameters };
}

export const parseMethodSignatureCore = (cursor: SignatureCursor): PeClrMethodSignature | null =>
  runMetadataDecoding(parseMethodSignatureTask(cursor));

export const parseFieldSignatureCore = (cursor: SignatureCursor): PeClrMethodSignature | null => {
  // ECMA-335 II.23.2.4: FIELD, then exactly one type.
  if (cursor.readU8() !== 0x06) return cursor.fail("does not start with FIELD");
  return { callingConvention: 0x06, parameterCount: 0,
    returnType: parseSignatureType(cursor), parameterTypes: [] };
};
