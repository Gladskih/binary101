"use strict";

import { addHeuristicResourcePreview } from "../resources/preview/sniff.js";
import type { ResourcePreviewData } from "../resources/preview/types.js";
import type { PeClrManagedResourceValue } from "./managed-resource-types.js";

const utf8Decoder = new TextDecoder("utf-8", { fatal: false });

const valuePreviewFields = (preview: ResourcePreviewData): Partial<PeClrManagedResourceValue> => ({
  previewKind: preview.previewKind,
  ...(preview.previewMime ? { previewMime: preview.previewMime } : {}),
  ...(preview.previewDataUrl ? { previewDataUrl: preview.previewDataUrl } : {}),
  ...(preview.textPreview ? { textPreview: preview.textPreview } : {}),
  ...(preview.textEncoding !== undefined ? { textEncoding: preview.textEncoding } : {}),
  ...(preview.previewFields ? { previewFields: preview.previewFields } : {})
});

const readBinaryString = (
  bytes: Uint8Array,
  offset: number,
  readSevenBitEncodedInt: (bytes: Uint8Array, offset: number) => { value: number; next: number } | null
): { value: string; next: number } | null => {
  const length = readSevenBitEncodedInt(bytes, offset);
  if (!length || length.value < 0 || length.next + length.value > bytes.length) return null;
  return {
    value: utf8Decoder.decode(bytes.subarray(length.next, length.next + length.value)),
    next: length.next + length.value
  };
};

const readIntegerPrimitive = (
  bytes: Uint8Array,
  offset: number,
  typeCode: number
): { value: number | null; next: number } | null => {
  const width = typeCode <= 5 ? 1 : typeCode <= 7 ? 2 : 4;
  if (offset + width > bytes.length) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const readers = [
    () => view.getUint8(offset),
    () => view.getInt8(offset),
    () => view.getInt16(offset, true),
    () => view.getUint16(offset, true),
    () => view.getInt32(offset, true)
  ];
  return { value: readers[typeCode - 4]?.() ?? null, next: offset + width };
};

const readDecimalPrimitive = (
  view: DataView,
  offset: number
): { value: string; next: number } => ({
  value: [
    view.getUint32(offset, true),
    view.getUint32(offset + 4, true),
    view.getUint32(offset + 8, true),
    view.getUint32(offset + 12, true)
  ].map(part => part.toString(16).padStart(8, "0")).join(":"),
  next: offset + 16
});

const readPrimitive = async (
  bytes: Uint8Array,
  offset: number,
  typeCode: number,
  readSevenBitEncodedInt: (bytes: Uint8Array, offset: number) => { value: number; next: number } | null
): Promise<{ value: string | number | boolean | null; next: number; raw?: Uint8Array } | null> => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (typeCode === 0) return { value: null, next: offset };
  if (typeCode === 1) {
    const text = readBinaryString(bytes, offset, readSevenBitEncodedInt);
    return text ? { value: text.value, next: text.next } : null;
  }
  if (typeCode === 2 && offset + 1 <= bytes.length) return { value: bytes[offset] !== 0, next: offset + 1 };
  if (typeCode === 3 && offset + 2 <= bytes.length) {
    return { value: String.fromCharCode(view.getUint16(offset, true)), next: offset + 2 };
  }
  if (typeCode >= 4 && typeCode <= 8) return readIntegerPrimitive(bytes, offset, typeCode);
  if (typeCode === 9 && offset + 4 <= bytes.length) return { value: view.getUint32(offset, true), next: offset + 4 };
  if (typeCode >= 10 && typeCode <= 11 && offset + 8 <= bytes.length) {
    const value = typeCode === 10 ? view.getBigInt64(offset, true) : view.getBigUint64(offset, true);
    return { value: String(value), next: offset + 8 };
  }
  if (typeCode === 12 && offset + 4 <= bytes.length) return { value: view.getFloat32(offset, true), next: offset + 4 };
  if (typeCode === 13 && offset + 8 <= bytes.length) return { value: view.getFloat64(offset, true), next: offset + 8 };
  if (typeCode === 14 && offset + 16 <= bytes.length) return readDecimalPrimitive(view, offset);
  if ((typeCode === 15 || typeCode === 16) && offset + 8 <= bytes.length) {
    return { value: String(view.getBigInt64(offset, true)), next: offset + 8 };
  }
  if ((typeCode === 32 || typeCode === 33) && offset + 4 <= bytes.length) {
    const length = view.getInt32(offset, true);
    if (length < 0 || offset + 4 + length > bytes.length) return null;
    return { value: `${length} bytes`, next: offset + 4 + length, raw: bytes.subarray(offset + 4, offset + 4 + length) };
  }
  return null;
};

const typeCodeFromV1TypeName = (type: string | undefined): number | null => {
  if (!type) return null;
  const name = type.split(",", 1)[0]?.trim();
  const typeCodes: Record<string, number> = {
    "System.String": 1,
    "System.Boolean": 2,
    "System.Char": 3,
    "System.Byte": 4,
    "System.SByte": 5,
    "System.Int16": 6,
    "System.UInt16": 7,
    "System.Int32": 8,
    "System.UInt32": 9,
    "System.Int64": 10,
    "System.UInt64": 11,
    "System.Single": 12,
    "System.Double": 13,
    "System.Decimal": 14,
    "System.DateTime": 15,
    "System.TimeSpan": 16
  };
  return name ? typeCodes[name] ?? null : null;
};

const typeName = (typeCode: number, userTypes: string[]): { name: string; opaque: boolean } => {
  // ResourceTypeCode values match System.Resources.ResourceTypeCode in ResourceReader.cs:
  // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceReader.cs
  const primitiveNames: Record<number, string> = {
    0: "Null",
    1: "String",
    2: "Boolean",
    3: "Char",
    4: "Byte",
    5: "SByte",
    6: "Int16",
    7: "UInt16",
    8: "Int32",
    9: "UInt32",
    10: "Int64",
    11: "UInt64",
    12: "Single",
    13: "Double",
    14: "Decimal",
    15: "DateTime",
    16: "TimeSpan",
    32: "ByteArray",
    33: "Stream"
  };
  if (primitiveNames[typeCode]) return { name: primitiveNames[typeCode], opaque: false };
  return { name: userTypes[typeCode - 64] ?? `UserType(${typeCode})`, opaque: true };
};

export const decodeDotNetResourceValue = async (
  payload: Uint8Array,
  type: { value: number; next: number },
  name: string,
  version: number,
  userTypes: string[],
  readSevenBitEncodedInt: (bytes: Uint8Array, offset: number) => { value: number; next: number } | null
): Promise<PeClrManagedResourceValue> => {
  const v1TypeCode = version === 1 ? typeCodeFromV1TypeName(userTypes[type.value]) : null;
  const typeInfo = version === 1 && type.value === -1
    ? { name: "Null", opaque: false }
    : version === 1
      ? { name: userTypes[type.value] ?? `UserType(${type.value})`, opaque: v1TypeCode == null }
      : typeName(type.value, userTypes);
  const primitiveTypeCode = version === 1 ? v1TypeCode : type.value;
  const decoded = typeInfo.opaque || primitiveTypeCode == null
    ? null
    : await readPrimitive(payload, type.next, primitiveTypeCode, readSevenBitEncodedInt);
  const preview = decoded?.raw ? (await addHeuristicResourcePreview(decoded.raw, undefined))?.preview : null;
  return {
    name,
    type: typeInfo.name,
    value: decoded?.value ?? null,
    opaque: typeInfo.opaque,
    ...(preview ? valuePreviewFields(preview) : {}),
    ...(decoded || typeInfo.opaque ? {} : { issues: ["Resource primitive value is truncated or unsupported."] })
  };
};
