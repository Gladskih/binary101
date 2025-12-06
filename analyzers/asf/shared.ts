"use strict";

import {
  AUDIO_FORMAT_NAMES,
  FILETIME_EPOCH_DIFF,
  GUID_NAMES,
  HUNDRED_NS_PER_SECOND,
  MAX_OBJECTS,
  OBJECT_HEADER_SIZE
} from "./constants.js";
import type { AsfObjectSummary, NumericField } from "./types.js";

const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
const utf16Decoder = new TextDecoder("utf-16le");

export const guidToString = (dv: DataView, offset: number): string | null => {
  if (offset + 16 > dv.byteLength) return null;
  const d1 = dv.getUint32(offset, true).toString(16).padStart(8, "0");
  const d2 = dv.getUint16(offset + 4, true).toString(16).padStart(4, "0");
  const d3 = dv.getUint16(offset + 6, true).toString(16).padStart(4, "0");
  const b: string[] = [];
  for (let i = 0; i < 8; i += 1) {
    b.push(dv.getUint8(offset + 8 + i).toString(16).padStart(2, "0"));
  }
  return `${d1}-${d2}-${d3}-${b.slice(0, 2).join("")}-${b.slice(2).join("")}`;
};

export const nameForGuid = (guid: string | null): string =>
  guid && GUID_NAMES[guid] ? GUID_NAMES[guid] : guid || "Unknown object";

export const readUint64 = (dv: DataView, offset: number): bigint | null => {
  if (offset + 8 > dv.byteLength || typeof dv.getBigUint64 !== "function") return null;
  return dv.getBigUint64(offset, true);
};

export const numberOrString = (value: bigint | null): NumericField => {
  if (value == null) return null;
  return value <= maxSafe ? Number(value) : value.toString();
};

export const hundredNsToSeconds = (value: NumericField): number | null =>
  typeof value === "number" ? Math.round((value / HUNDRED_NS_PER_SECOND) * 1000) / 1000 : null;

export const filetimeToIso = (value: bigint | null): string | null => {
  if (value == null) return null;
  const unixTicks = value - FILETIME_EPOCH_DIFF;
  const millis = unixTicks / 10000n;
  if (millis < 0n || millis > maxSafe) return null;
  const date = new Date(Number(millis));
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
};

export const readUnicodeString = (dv: DataView, offset: number, byteLength: number): string => {
  const end = Math.min(dv.byteLength, offset + Math.max(0, byteLength));
  const bytes = new Uint8Array(dv.buffer, dv.byteOffset + offset, Math.max(0, end - offset));
  return utf16Decoder.decode(bytes).replace(/\0+$/u, "");
};

export const fourCcFromNumber = (value: number): string => {
  const bytes = [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff];
  const text = String.fromCharCode(...bytes);
  return /[ -~]{4}/u.test(text) ? text : `0x${value.toString(16)}`;
};

export const parseObjectList = (
  dv: DataView,
  start: number,
  end: number,
  issues: string[],
  context: string
): { objects: AsfObjectSummary[]; parsedBytes: number; truncatedCount: number } => {
  const objects: AsfObjectSummary[] = [];
  let cursor = start;
  let truncatedCount = 0;
  while (cursor + OBJECT_HEADER_SIZE <= end && objects.length < MAX_OBJECTS) {
    const guid = guidToString(dv, cursor);
    const sizeBig = readUint64(dv, cursor + 16);
    const size =
      sizeBig && sizeBig > 0n && sizeBig <= maxSafe ? Number(sizeBig) : null;
    if (size == null || size < OBJECT_HEADER_SIZE) {
      issues.push(`${context} object at ${cursor} has an invalid size.`);
      break;
    }
    const next = cursor + size;
    const truncated = next > end || next > dv.byteLength;
    if (truncated) truncatedCount += 1;
    objects.push({ guid, name: nameForGuid(guid), offset: cursor, size, truncated });
    if (next <= cursor) {
      issues.push(`${context} object at ${cursor} does not advance; stopping parse.`);
      break;
    }
    cursor = next;
  }
  return { objects, parsedBytes: cursor - start, truncatedCount };
};

export { AUDIO_FORMAT_NAMES };
