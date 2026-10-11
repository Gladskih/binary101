"use strict";

import { previewManagedResourceBytes, previewManagedResourceText } from "./managed-resource-preview.js";
import type { PeClrManagedResourceValue } from "./managed-resource-types.js";
import { formatResourceDateTime, formatResourceTimeSpan } from "./dotnet-resource-time.js";
import { readBinaryString } from "./dotnet-resource-encoding.js";
import type { ResourcePreviewResult } from "../resources/preview/types.js";

const previewStringValue = (text: string): ResourcePreviewResult => {
  const result = previewManagedResourceText(text);
  // The decoded value is the string's source of truth; only byte/stream previews store textPreview.
  const { textPreview: _source, ...preview } = result.preview!;
  return { ...result, preview };
};

type PrimitiveValue = { value: string | number | boolean | null; next: number; raw?: Uint8Array };

const numericEncodings: Record<number, {
  width: number; read: (view: DataView, offset: number) => PrimitiveValue["value"];
}> = {
  2: { width: 1, read: (view, offset) => view.getUint8(offset) !== 0 },
  3: { width: 2, read: (view, offset) => String.fromCharCode(view.getUint16(offset, true)) },
  4: { width: 1, read: (view, offset) => view.getUint8(offset) },
  5: { width: 1, read: (view, offset) => view.getInt8(offset) },
  6: { width: 2, read: (view, offset) => view.getInt16(offset, true) },
  7: { width: 2, read: (view, offset) => view.getUint16(offset, true) },
  8: { width: 4, read: (view, offset) => view.getInt32(offset, true) },
  9: { width: 4, read: (view, offset) => view.getUint32(offset, true) },
  10: { width: 8, read: (view, offset) => String(view.getBigInt64(offset, true)) },
  11: { width: 8, read: (view, offset) => String(view.getBigUint64(offset, true)) },
  12: { width: 4, read: (view, offset) => view.getFloat32(offset, true) },
  13: { width: 8, read: (view, offset) => view.getFloat64(offset, true) }
};

const readDecimalPrimitive = (
  view: DataView,
  offset: number
): { value: string; next: number } | null => {
  // Decimal.GetBits: lo, mid, hi, flags; reserved bits must be zero and scale <= 28.
  // https://learn.microsoft.com/en-us/dotnet/api/system.decimal.getbits
  const flags = view.getUint32(offset + 12, true);
  const scale = (flags >>> 16) & 0xff;
  if ((flags & 0x7f00ffff) !== 0 || scale > 28) return null;
  const magnitude = BigInt(view.getUint32(offset, true)) |
    (BigInt(view.getUint32(offset + 4, true)) << 32n) |
    (BigInt(view.getUint32(offset + 8, true)) << 64n);
  const digits = magnitude.toString().padStart(scale + 1, "0");
  const value = scale ? `${digits.slice(0, -scale)}.${digits.slice(-scale)}` : digits;
  return { value: `${flags >>> 31 ? "-" : ""}${value}`, next: offset + 16 };
};

const readByteArray = (bytes: Uint8Array, offset: number): PrimitiveValue | null => {
  if (offset + 4 > bytes.length) return null;
  const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getInt32(offset, true);
  if (length < 0 || offset + 4 + length > bytes.length) return null;
  return { value: `${length} bytes`, next: offset + 4 + length,
    raw: bytes.subarray(offset + 4, offset + 4 + length) };
};

const readTimePrimitive = (
  view: DataView, offset: number, typeCode: number, version: number
): PrimitiveValue | null => {
  if (offset + 8 > view.byteLength) return null;
  const ticks = view.getBigInt64(offset, true);
  const value = typeCode === 15 ? formatResourceDateTime(ticks, version) : formatResourceTimeSpan(ticks);
  return value == null ? null : { value, next: offset + 8 };
};

const readFixedPrimitive = (
  bytes: Uint8Array, offset: number, typeCode: number, version: number
): PrimitiveValue | null => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (typeCode === 15 || typeCode === 16) return readTimePrimitive(view, offset, typeCode, version);
  if (typeCode === 14) return offset + 16 <= bytes.length ? readDecimalPrimitive(view, offset) : null;
  const encoding = numericEncodings[typeCode];
  if (!encoding || offset + encoding.width > bytes.length) return null;
  return { value: encoding.read(view, offset), next: offset + encoding.width };
};

const readPrimitive = (
  bytes: Uint8Array, offset: number, typeCode: number, version: number
): PrimitiveValue | null => {
  if (typeCode === 0) return { value: null, next: offset };
  if (typeCode === 1) return readBinaryString(bytes, offset);
  if (typeCode === 32 || typeCode === 33) return readByteArray(bytes, offset);
  return readFixedPrimitive(bytes, offset, typeCode, version);
};

const typeCodeFromV1TypeName = (type: string | undefined): number | null => {
  if (!type) return null;
  const name = type.split(",", 1)[0]!.trim();
  const typeCodes: Record<string, number> = {
    "System.String": 1,
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
  return typeCodes[name] ?? null;
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

const resolveValueType = (code: number, version: number, userTypes: string[]): {
  name: string; opaque: boolean; primitiveCode: number | null;
} => {
  if (version !== 1) return { ...typeName(code, userTypes), primitiveCode: code };
  if (code === -1) return { name: "Null", opaque: false, primitiveCode: 0 };
  const primitiveCode = typeCodeFromV1TypeName(userTypes[code]);
  return { name: userTypes[code] ?? `UserType(${code})`, opaque: primitiveCode == null, primitiveCode };
};

const previewDecodedValue = async (
  decoded: PrimitiveValue | null, primitiveCode: number | null
): Promise<ResourcePreviewResult | null> => {
  if (decoded?.raw) return previewManagedResourceBytes(decoded.raw);
  if (primitiveCode !== 1 || typeof decoded?.value !== "string") return null;
  return decoded.value.trimStart().startsWith("<")
    ? previewStringValue(decoded.value) : null;
};

const isValueOffsetValid = (offset: number, length: number): boolean =>
  Number.isSafeInteger(offset) && offset >= 0 && offset <= length;

const decodePrimitive = (
  payload: Uint8Array, offset: number,
  typeInfo: ReturnType<typeof resolveValueType>, version: number
): PrimitiveValue | null => typeInfo.opaque || typeInfo.primitiveCode == null
  ? null : readPrimitive(payload, offset, typeInfo.primitiveCode, version);

const primitiveIssues = (decoded: PrimitiveValue | null, opaque: boolean): string[] =>
  decoded || opaque ? [] : ["Resource primitive value is truncated or unsupported."];

export const decodeDotNetResourceValue = async (
  payload: Uint8Array,
  type: { value: number; next: number },
  name: string,
  version: number,
  userTypes: string[]
): Promise<PeClrManagedResourceValue> => {
  if (!isValueOffsetValid(type.next, payload.length)) {
    return { name, type: "Unknown", value: null, opaque: true,
      issues: ["Resource value offset is outside its data record."] };
  }
  const typeInfo = resolveValueType(type.value, version, userTypes);
  const decoded = decodePrimitive(payload, type.next, typeInfo, version);
  const preview = await previewDecodedValue(decoded, typeInfo.primitiveCode);
  const issues = [...preview?.issues ?? [], ...primitiveIssues(decoded, typeInfo.opaque)];
  return {
    name,
    type: typeInfo.name,
    value: decoded?.value ?? null,
    opaque: typeInfo.opaque,
    ...preview?.preview,
    ...(issues.length ? { issues } : {})
  };
};
