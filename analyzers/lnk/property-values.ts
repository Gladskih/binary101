"use strict";

import { readFiletime, readGuid } from "./utils.js";
import type { LnkPropertyScalar, LnkPropertyValue } from "./types.js";

const PROPERTY_KEY_LABELS: Record<string, string> = {
  "f29f85e0-4ff9-1068-ab91-08002b27b3d9:2": "System.Link.TargetParsingPath",
  "f29f85e0-4ff9-1068-ab91-08002b27b3d9:3": "System.Link.WorkingDirectory",
  "f29f85e0-4ff9-1068-ab91-08002b27b3d9:5": "System.Link.Arguments",
  "446d16b1-8dad-4870-a748-402ea43d788c:104": "System.VolumeId"
};

const PROPERTY_TYPE_NAMES: Record<number, string> = {
  0x0000: "Empty",
  0x0001: "Null",
  0x0002: "Signed 16-bit",
  0x0003: "Signed 32-bit",
  0x0004: "Float",
  0x0005: "Double",
  0x0006: "Currency",
  0x0007: "Date",
  0x0008: "BSTR",
  0x000b: "Boolean",
  0x0010: "Signed 8-bit",
  0x0011: "Unsigned 8-bit",
  0x0012: "Unsigned 16-bit",
  0x0013: "Unsigned 32-bit",
  0x0014: "Signed 64-bit",
  0x0015: "Unsigned 64-bit",
  0x001e: "ANSI string",
  0x001f: "Unicode string",
  0x0040: "Filetime",
  0x0041: "Blob",
  0x0048: "CLSID"
};

const ansiFromBytes = (bytes: Uint8Array): string => {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const code = bytes[i] ?? 0;
    if (code === 0) break;
    out += String.fromCharCode(code);
  }
  return out;
};

const propertyKeyLabel = (formatId: string | null, propertyId: number): string | null =>
  PROPERTY_KEY_LABELS[`${formatId}:${propertyId}`] || null;

const propertyTypeName = (type: number): string | null => PROPERTY_TYPE_NAMES[type] || null;

const parsePropertyString = (
  dv: DataView,
  offset: number,
  available: number,
  isUnicode: boolean
): string | null => {
  if (available < 4) return null;
  const count = dv.getUint32(offset, true);
  if (count <= 0) return "";
  const maxBytes = available - 4;
  const byteLength = isUnicode ? Math.min(maxBytes, count * 2) : Math.min(maxBytes, count);
  const bytes = new Uint8Array(dv.buffer, dv.byteOffset + offset + 4, Math.max(0, byteLength));
  if (!bytes.length) return "";
  if (isUnicode) {
    let result = "";
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const low = bytes[i] ?? 0;
      const high = bytes[i + 1] ?? 0;
      const code = low | (high << 8);
      if (code === 0) break;
      result += String.fromCharCode(code);
    }
    return result.replace(/\0+$/, "");
  }
  return ansiFromBytes(bytes).replace(/\0+$/, "");
};

const decodeVector = (
  dv: DataView,
  offset: number,
  available: number,
  baseType: number
): { value: LnkPropertyScalar[]; truncated: boolean } => {
  if (available < 4) return { value: [], truncated: true };
  const count = dv.getUint32(offset, true);
  const values: LnkPropertyScalar[] = [];
  let cursor = offset + 4;
  for (let i = 0; i < count && cursor < offset + available; i += 1) {
    const remaining = offset + available - cursor;
    let element: LnkPropertyScalar | null = null;
    switch (baseType) {
      case 0x0011:
        element = dv.getUint8(cursor);
        cursor += 1;
        break;
      case 0x0010:
        element = dv.getInt8(cursor);
        cursor += 1;
        break;
      case 0x0002:
        if (remaining < 2) return { value: values, truncated: true };
        element = dv.getInt16(cursor, true);
        cursor += 2;
        break;
      case 0x0012:
        if (remaining < 2) return { value: values, truncated: true };
        element = dv.getUint16(cursor, true);
        cursor += 2;
        break;
      case 0x0003:
        if (remaining < 4) return { value: values, truncated: true };
        element = dv.getInt32(cursor, true);
        cursor += 4;
        break;
      case 0x0013:
        if (remaining < 4) return { value: values, truncated: true };
        element = dv.getUint32(cursor, true);
        cursor += 4;
        break;
      case 0x0014:
        if (remaining < 8 || typeof dv.getBigInt64 !== "function") {
          return { value: values, truncated: true };
        }
        element = dv.getBigInt64(cursor, true);
        cursor += 8;
        break;
      case 0x0015:
        if (remaining < 8 || typeof dv.getBigUint64 !== "function") {
          return { value: values, truncated: true };
        }
        element = dv.getBigUint64(cursor, true);
        cursor += 8;
        break;
      case 0x0048:
        if (remaining < 16) return { value: values, truncated: true };
        element = readGuid(dv, cursor);
        cursor += 16;
        break;
      default:
        return { value: values, truncated: true };
    }
    values.push(element);
  }
  return { value: values, truncated: cursor > offset + available };
};

const parsePropertyValue = (
  dv: DataView,
  offset: number,
  declaredSize: number,
  warnings: string[],
  label: string
): {
    type: number | null;
    typeName: string | null;
    value: LnkPropertyValue;
    truncated: boolean;
    valueSize: number;
    isVector: boolean;
  } => {
  if (declaredSize < 4 || offset + 4 > dv.byteLength) {
    return {
      type: null,
      typeName: null,
      value: null,
      truncated: true,
      valueSize: declaredSize,
      isVector: false
    };
  }
  let type = dv.getUint16(offset, true);
  const rawType = type;
  const lowByte = rawType & 0xff;
  const highByte = (rawType >> 8) & 0xff;
  if (lowByte === 0 && highByte !== 0 && propertyTypeName(highByte)) {
    type = highByte;
  }
  dv.getUint16(offset + 2, true);
  const isVector = (type & 0x1000) !== 0;
  const baseType = isVector ? type & ~0x1000 : type;
  const dataStart = offset + 4;
  const declaredEnd = offset + declaredSize;
  const clampedEnd = Math.min(declaredEnd, dv.byteLength);
  const available = Math.max(0, clampedEnd - dataStart);
  const typeName = propertyTypeName(baseType);
  let value: LnkPropertyValue = null;
  let truncated = declaredEnd > dv.byteLength;

  const parseScalar = (): LnkPropertyValue => {
    switch (baseType) {
      case 0x001f:
        return parsePropertyString(dv, dataStart, available, true);
      case 0x001e:
        return parsePropertyString(dv, dataStart, available, false);
      case 0x0013:
        return available >= 4 ? dv.getUint32(dataStart, true) : null;
      case 0x0003:
        return available >= 4 ? dv.getInt32(dataStart, true) : null;
      case 0x000b:
        return available >= 2 ? dv.getInt16(dataStart, true) !== 0 : null;
      case 0x0014:
        return available >= 8 && typeof dv.getBigInt64 === "function"
          ? dv.getBigInt64(dataStart, true)
          : null;
      case 0x0015:
        return available >= 8 && typeof dv.getBigUint64 === "function"
          ? dv.getBigUint64(dataStart, true)
          : null;
      case 0x0040: {
        if (available >= 8) {
          const ftView = new DataView(dv.buffer, dv.byteOffset + dataStart, Math.min(8, available));
          return readFiletime(ftView, 0).iso;
        }
        return null;
      }
      case 0x0048: {
        if (available >= 16) {
          const guidView = new DataView(dv.buffer, dv.byteOffset + dataStart, Math.min(16, available));
          return readGuid(guidView, 0);
        }
        return null;
      }
      case 0x0041: {
        const bytes = new Uint8Array(
          dv.buffer,
          dv.byteOffset + dataStart,
          Math.max(0, Math.min(available, Math.max(0, declaredSize - 4)))
        );
        return { length: bytes.length };
      }
      default:
        return null;
    }
  };

  if (isVector) {
    const { value: vec, truncated: vecTrunc } = decodeVector(dv, dataStart, available, baseType);
    value = vec;
    truncated = truncated || vecTrunc;
  } else {
    value = parseScalar();
  }

  if (declaredEnd > dv.byteLength) {
    const labelText = label || "property store entry";
    warnings.push(`${labelText} value is truncated.`);
  }
  return { type, typeName, value, truncated, valueSize: declaredSize, isVector };
};

export { parsePropertyValue, propertyKeyLabel, propertyTypeName };
