"use strict";

import { formatUnixSecondsOrDash } from "../../binary-utils.js";
import { SIGNATURE_V4, SIGNATURE_V5 } from "./constants.js";

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: false });
const LATIN1_DECODER = new TextDecoder("latin1", { fatal: false });

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let j = 0; j < 8; j += 1) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

export const crc32 = (bytes: Uint8Array): number => {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes.at(i) ?? 0;
    const tableValue = CRC32_TABLE.at((crc ^ byte) & 0xff) ?? 0;
    crc = (crc >>> 8) ^ tableValue;
  }
  return (crc ^ 0xffffffff) >>> 0;
};

export const toSafeNumber = (value: number | bigint | null | undefined): number | null => {
  if (typeof value === "number") return value;
  if (typeof value === "bigint") {
    if (value <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
    return null;
  }
  return null;
};

export const readDataView = async (
  file: File,
  offset: number,
  length: number
): Promise<DataView | null> => {
  if (offset >= (file.size || 0)) return null;
  const clampedLength = Math.max(0, Math.min(length, (file.size || 0) - offset));
  const buffer = await file.slice(offset, offset + clampedLength).arrayBuffer();
  return new DataView(buffer);
};

export const readVint = (
  dv: DataView,
  offset: number
): { value: bigint | null; length: number } => {
  let value = 0n;
  let shift = 0n;
  let length = 0;
  while (offset + length < dv.byteLength) {
    const byte = dv.getUint8(offset + length);
    length += 1;
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return { value, length };
    }
    shift += 7n;
    if (length >= 10) break;
  }
  return { value: null, length: 0 };
};

export const combineToBigInt = (high: number, low: number): bigint => {
  const hi = BigInt(high >>> 0);
  const lo = BigInt(low >>> 0);
  return (hi << 32n) + lo;
};

export const formatDosDateTime = (dosValue: number): string => {
  const seconds = (dosValue & 0x1f) * 2;
  const minutes = (dosValue >> 5) & 0x3f;
  const hours = (dosValue >> 11) & 0x1f;
  const day = (dosValue >> 16) & 0x1f;
  const month = (dosValue >> 21) & 0x0f;
  const year = ((dosValue >> 25) & 0x7f) + 1980;
  if (!year || !month || !day) return "-";
  const unixSeconds = Date.UTC(year, month - 1, day, hours, minutes, seconds) / 1000;
  return formatUnixSecondsOrDash(unixSeconds);
};

export const mapHostV4 = (value: number): string =>
  value === 0
    ? "MS-DOS"
    : value === 1
      ? "OS/2"
      : value === 2
        ? "Windows"
        : value === 3
          ? "Unix"
          : value === 4
            ? "Mac OS"
            : value === 5
            ? "BeOS"
            : `Host ${value}`;

export const mapHostV5 = (value: number): string =>
  value === 0 ? "Windows" : value === 1 ? "Unix" : `Host ${value}`;

export const decodeNameBytes = (bytes: Uint8Array, preferUtf8 = true): string => {
  if (!bytes || bytes.length === 0) return "";
  if (preferUtf8) {
    try {
      return UTF8_DECODER.decode(bytes);
    } catch {
      // fall through to latin1
    }
  }
  return LATIN1_DECODER.decode(bytes);
};

export const detectRarVersionBytes = (bytes: Uint8Array): number | null => {
  const matches = (sig: readonly number[]) =>
    sig.every((b, idx) => idx < bytes.length && bytes[idx] === b);
  if (bytes.length >= SIGNATURE_V5.length && matches(SIGNATURE_V5)) return 5;
  if (bytes.length >= SIGNATURE_V4.length && matches(SIGNATURE_V4)) return 4;
  return null;
};

export const hasRarSignature = (dv: DataView): boolean => {
  const bytes = new Uint8Array(dv.buffer, dv.byteOffset, Math.min(dv.byteLength, SIGNATURE_V5.length));
  return detectRarVersionBytes(bytes) != null;
};
