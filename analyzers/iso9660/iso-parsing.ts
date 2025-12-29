"use strict";

import { toHex32 } from "../../binary-utils.js";
import type { Iso9660StringEncoding } from "./types.js";

export const ISO9660_DESCRIPTOR_BLOCK_SIZE = 2048;
export const ISO9660_SYSTEM_AREA_BLOCKS = 16;

const formatOffsetHex = (offset: number): string => toHex32(offset >>> 0, 8);
const ECMA119_SPEC_URL = "https://ecma-international.org/publications-and-standards/standards/ecma-119/";

export const readUint16Le = (bytes: Uint8Array, offset: number): number | null => {
  if (offset < 0 || offset + 2 > bytes.length) return null;
  return (bytes[offset] ?? 0) | ((bytes[offset + 1] ?? 0) << 8);
};

export const readUint16Be = (bytes: Uint8Array, offset: number): number | null => {
  if (offset < 0 || offset + 2 > bytes.length) return null;
  return ((bytes[offset] ?? 0) << 8) | (bytes[offset + 1] ?? 0);
};

export const readUint32Le = (bytes: Uint8Array, offset: number): number | null => {
  if (offset < 0 || offset + 4 > bytes.length) return null;
  return (
    (bytes[offset] ?? 0) |
    ((bytes[offset + 1] ?? 0) << 8) |
    ((bytes[offset + 2] ?? 0) << 16) |
    ((bytes[offset + 3] ?? 0) << 24)
  ) >>> 0;
};

export const readUint32Be = (bytes: Uint8Array, offset: number): number | null => {
  if (offset < 0 || offset + 4 > bytes.length) return null;
  return (
    ((bytes[offset] ?? 0) << 24) |
    ((bytes[offset + 1] ?? 0) << 16) |
    ((bytes[offset + 2] ?? 0) << 8) |
    (bytes[offset + 3] ?? 0)
  ) >>> 0;
};

export const readBothEndianUint16 = (
  bytes: Uint8Array,
  offset: number,
  absoluteBaseOffset: number,
  fieldName: string,
  pushIssue: (message: string) => void
): number | null => {
  const le = readUint16Le(bytes, offset);
  const be = readUint16Be(bytes, offset + 2);
  if (le == null || be == null) return null;
  if (le !== be) {
    pushIssue(
      `${fieldName} stores mismatched LE (${le}) and BE (${be}) values at ${formatOffsetHex(absoluteBaseOffset + offset)}. ` +
        `Per ECMA-119 (ISO 9660) §8.2.4 (Both-byte orders), both halves should match; using LE. ` +
        `Spec: ${ECMA119_SPEC_URL}`
    );
  }
  return le;
};

export const readBothEndianUint32 = (
  bytes: Uint8Array,
  offset: number,
  absoluteBaseOffset: number,
  fieldName: string,
  pushIssue: (message: string) => void
): number | null => {
  const le = readUint32Le(bytes, offset);
  const be = readUint32Be(bytes, offset + 4);
  if (le == null || be == null) return null;
  if (le !== be) {
    pushIssue(
      `${fieldName} stores mismatched LE (${le}) and BE (${be}) values at ${formatOffsetHex(absoluteBaseOffset + offset)}. ` +
        `Per ECMA-119 (ISO 9660) §8.3.4 (Both-byte orders), both halves should match; using LE. ` +
        `Spec: ${ECMA119_SPEC_URL}`
    );
  }
  return le;
};

export const decodeAsciiField = (bytes: Uint8Array, offset: number, length: number): string | null => {
  if (offset < 0 || length <= 0 || offset + 1 > bytes.length) return null;
  const end = Math.min(bytes.length, offset + length);
  let trimmedEnd = end;
  while (trimmedEnd > offset) {
    const value = bytes[trimmedEnd - 1] ?? 0;
    if (value === 0x00 || value === 0x20) {
      trimmedEnd -= 1;
    } else {
      break;
    }
  }
  let out = "";
  for (let index = offset; index < trimmedEnd; index += 1) {
    const byteValue = bytes[index] ?? 0;
    if (byteValue === 0) break;
    out += String.fromCharCode(byteValue);
  }
  const result = out.trimEnd();
  return result.length ? result : null;
};

export const decodeUcs2BeField = (bytes: Uint8Array, offset: number, length: number): string | null => {
  if (offset < 0 || length <= 0 || offset + 1 > bytes.length) return null;
  const end = Math.min(bytes.length, offset + length);
  let out = "";
  for (let index = offset; index + 1 < end; index += 2) {
    const hi = bytes[index] ?? 0;
    const lo = bytes[index + 1] ?? 0;
    const codeUnit = (hi << 8) | lo;
    if (codeUnit === 0) break;
    out += String.fromCharCode(codeUnit);
  }
  const result = out.trimEnd();
  return result.length ? result : null;
};

export const decodeStringField = (
  bytes: Uint8Array,
  offset: number,
  length: number,
  encoding: Iso9660StringEncoding
): string | null => (encoding === "ucs2be" ? decodeUcs2BeField(bytes, offset, length) : decodeAsciiField(bytes, offset, length));

const parseSignedInt8 = (value: number): number => (value & 0x80 ? value - 0x100 : value);

const pad2 = (value: number): string => value.toString().padStart(2, "0");

export const parseRecordingDateTime = (
  bytes: Uint8Array,
  offset: number
): { text: string | null; utcOffsetMinutes: number | null } => {
  if (offset < 0 || offset + 7 > bytes.length) return { text: null, utcOffsetMinutes: null };
  const year = (bytes[offset] ?? 0) + 1900;
  const month = bytes[offset + 1] ?? 0;
  const day = bytes[offset + 2] ?? 0;
  const hour = bytes[offset + 3] ?? 0;
  const minute = bytes[offset + 4] ?? 0;
  const second = bytes[offset + 5] ?? 0;
  const tzQuarterHours = parseSignedInt8(bytes[offset + 6] ?? 0);
  const utcOffsetMinutes = tzQuarterHours * 15;

  if (!month || !day) return { text: null, utcOffsetMinutes: null };
  const tzLabel = utcOffsetMinutes ? ` UTC${utcOffsetMinutes >= 0 ? "+" : ""}${utcOffsetMinutes / 60}` : "";
  const text = `${year}-${pad2(month)}-${pad2(day)} ${pad2(hour)}:${pad2(minute)}:${pad2(second)}${tzLabel}`;
  return { text, utcOffsetMinutes };
};

export const parseVolumeDateTime17 = (bytes: Uint8Array, offset: number): string | null => {
  if (offset < 0 || offset + 17 > bytes.length) return null;
  let digits = "";
  for (let index = 0; index < 16; index += 1) {
    const byteValue = bytes[offset + index] ?? 0;
    if (byteValue === 0) break;
    digits += String.fromCharCode(byteValue);
  }
  if (!digits.trim().length || /^0+$/.test(digits.trim())) return null;
  if (!/^[0-9]{16}$/.test(digits)) return digits.trim();

  const year = digits.slice(0, 4);
  const month = digits.slice(4, 6);
  const day = digits.slice(6, 8);
  const hour = digits.slice(8, 10);
  const minute = digits.slice(10, 12);
  const second = digits.slice(12, 14);
  const hundredths = digits.slice(14, 16);

  const tzQuarterHours = parseSignedInt8(bytes[offset + 16] ?? 0);
  const utcOffsetMinutes = tzQuarterHours * 15;
  const tzLabel = utcOffsetMinutes ? ` UTC${utcOffsetMinutes >= 0 ? "+" : ""}${utcOffsetMinutes / 60}` : "";
  return `${year}-${month}-${day} ${hour}:${minute}:${second}.${hundredths}${tzLabel}`;
};

export const describeVolumeDescriptorType = (typeCode: number): string => {
  switch (typeCode) {
    case 0:
      return "Boot Record";
    case 1:
      return "Primary Volume Descriptor";
    case 2:
      return "Supplementary Volume Descriptor";
    case 3:
      return "Volume Partition Descriptor";
    case 255:
      return "Volume Descriptor Set Terminator";
    default:
      return `Unknown (${typeCode})`;
  }
};
