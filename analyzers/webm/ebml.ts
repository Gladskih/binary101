"use strict";

import {
  EBML_DATE_EPOCH_MS,
  MAX_ELEMENT_HEADER
} from "./constants.js";
import type { Issues } from "./types.js";

export interface Vint {
  length: number;
  value: bigint;
  data: bigint;
  unknown: boolean;
}

export interface EbmlElementHeader {
  id: number;
  size: number | null;
  headerSize: number;
  dataOffset: number;
  offset: number;
  sizeUnknown: boolean;
}

const utf8Decoder = new TextDecoder("utf-8", { fatal: false });

export const readVint = (dv: DataView, offset: number): Vint | null => {
  if (offset >= dv.byteLength) return null;
  const first = dv.getUint8(offset);
  if (first === 0) return null;
  let length = 1;
  let mask = 0x80;
  while (length <= 8 && (first & mask) === 0) {
    length += 1;
    mask >>= 1;
  }
  if (length > 8) return null;
  if (offset + length > dv.byteLength) return null;
  let value = 0n;
  for (let i = 0; i < length; i += 1) {
    value = (value << 8n) | BigInt(dv.getUint8(offset + i));
  }
  const marker = 1n << BigInt(length * 7);
  const data = value & (marker - 1n);
  const unknown = data === marker - 1n;
  return { length, value, data, unknown };
};

export const readElementHeader = (
  dv: DataView,
  cursor: number,
  absoluteOffset: number,
  issues: Issues | null
): EbmlElementHeader | null => {
  const idVint = readVint(dv, cursor);
  if (!idVint) {
    if (issues) issues.push("Unexpected end of data while reading element ID.");
    return null;
  }
  const sizeVint = readVint(dv, cursor + idVint.length);
  if (!sizeVint) {
    if (issues) issues.push(`Unable to read size for element at ${absoluteOffset}.`);
    return null;
  }
  const headerSize = idVint.length + sizeVint.length;
  if (cursor + headerSize > dv.byteLength) {
    if (issues) issues.push(`Element header at ${absoluteOffset} is truncated.`);
    return null;
  }
  const rawSize = sizeVint.data;
  let size: number | null = null;
  if (!sizeVint.unknown) {
    if (rawSize > BigInt(Number.MAX_SAFE_INTEGER)) {
      size = null;
      if (issues) issues.push(`Element at ${absoluteOffset} declares an oversized length.`);
    } else {
      size = Number(rawSize);
    }
  }
  return {
    id: Number(idVint.value),
    size,
    headerSize,
    dataOffset: absoluteOffset + headerSize,
    offset: absoluteOffset,
    sizeUnknown: sizeVint.unknown
  };
};

export const clampReadLength = (
  fileSize: number,
  offset: number,
  declaredSize: number | null,
  cap: number
): { length: number; truncated: boolean } => {
  const maxAvailable = Math.max(0, fileSize - offset);
  const desired = declaredSize == null ? cap : Math.min(declaredSize, cap);
  const length = Math.min(desired, maxAvailable);
  const truncated = declaredSize != null && declaredSize > length;
  return { length, truncated };
};

export const toSafeNumber = (value: bigint, issues: Issues, label: string): number | null => {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    issues.push(`${label} is too large to represent precisely.`);
    return null;
  }
  return Number(value);
};

export const readUnsigned = (
  dv: DataView,
  offset: number,
  length: number,
  issues: Issues,
  label: string
): bigint | null => {
  if (length <= 0 || offset + length > dv.byteLength) {
    issues.push(`${label} is truncated or missing.`);
    return null;
  }
  let value = 0n;
  for (let i = 0; i < length; i += 1) {
    value = (value << 8n) | BigInt(dv.getUint8(offset + i));
  }
  return value;
};

export const readFloat = (
  dv: DataView,
  offset: number,
  length: number,
  issues: Issues,
  label: string
): number | null => {
  if (offset + length > dv.byteLength) {
    issues.push(`${label} is truncated or missing.`);
    return null;
  }
  if (length === 4) return dv.getFloat32(offset, false);
  if (length === 8) return dv.getFloat64(offset, false);
  issues.push(`${label} uses unsupported float size ${length}.`);
  return null;
};

export const readUtf8 = (dv: DataView, offset: number, length: number): string => {
  const slice = new Uint8Array(
    dv.buffer,
    dv.byteOffset + offset,
    Math.max(0, Math.min(length, dv.byteLength - offset))
  );
  return utf8Decoder.decode(slice);
};

export const readDate = (
  dv: DataView,
  offset: number,
  length: number,
  issues: Issues
): string | null => {
  if (length !== 8 || offset + length > dv.byteLength) {
    issues.push("DateUTC field is truncated or uses unsupported size.");
    return null;
  }
  const value = dv.getBigInt64(offset, false);
  const msOffset = value / 1000000n;
  if (msOffset > BigInt(Number.MAX_SAFE_INTEGER) || msOffset < BigInt(-Number.MAX_SAFE_INTEGER)) {
    issues.push("DateUTC is outside representable range.");
    return null;
  }
  const date = new Date(EBML_DATE_EPOCH_MS + Number(msOffset));
  return date.toISOString();
};

export const readElementAt = async (
  file: File,
  offset: number,
  issues: Issues
): Promise<EbmlElementHeader | null> => {
  if (offset >= file.size) {
    issues.push(`Element offset ${offset} is beyond file size.`);
    return null;
  }
  const length = Math.min(MAX_ELEMENT_HEADER, file.size - offset);
  const dv = new DataView(await file.slice(offset, offset + length).arrayBuffer());
  return readElementHeader(dv, 0, offset, issues);
};
