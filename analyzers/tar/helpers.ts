"use strict";

import { formatUnixSecondsOrDash } from "../../binary-utils.js";
import type { TarEntry, TarFormatInfo } from "./types.js";

const TAR_BLOCK_SIZE = 512;
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: false });

export const toSafeNumber = (value: unknown): number | null => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "bigint") {
    const max = BigInt(Number.MAX_SAFE_INTEGER);
    if (value <= max && value >= BigInt(Number.MIN_SAFE_INTEGER)) {
      return Number(value);
    }
  }
  return null;
};

export const align512 = (value: number): number => {
  if (value <= 0) return 0;
  return Math.ceil(value / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
};

export const isZeroBlock = (bytes: Uint8Array): boolean => {
  for (let i = 0; i < bytes.length; i += 1) {
    if (bytes[i] !== 0) return false;
  }
  return true;
};

export const readTarString = (
  bytes: Uint8Array,
  offset: number,
  length: number,
  options: { trimSpaces?: boolean } = {}
): string => {
  const { trimSpaces = true } = options;
  const slice = bytes.subarray(offset, offset + length);
  let end = slice.length;
  while (end > 0 && slice[end - 1] === 0) {
    end -= 1;
  }
  if (end <= 0) return "";
  let text = TEXT_DECODER.decode(slice.subarray(0, end));
  if (trimSpaces) text = text.replace(/\s+$/, "");
  return text;
};

export const combineNameParts = (prefix: string, baseName: string): string => {
  const cleanPrefix = prefix ? prefix.replace(/\/+$/, "") : "";
  if (cleanPrefix && baseName) return `${cleanPrefix}/${baseName}`;
  if (cleanPrefix) return cleanPrefix;
  return baseName || "";
};

export const parseBase256Number = (field: ArrayLike<number>): number | null => {
  const bytes = new Uint8Array(field);
  if (!bytes.length) return null;
  bytes[0] = (bytes[0] ?? 0) & 0x7f; // clear the indicator bit
  let value = 0n;
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes[i];
    if (byte === undefined) continue;
    value = (value << 8n) | BigInt(byte);
  }
  const safeNumber = toSafeNumber(value);
  return safeNumber;
};

export const parseOctalNumber = (field: Uint8Array): number | null => {
  let text = "";
  for (let i = 0; i < field.length; i += 1) {
    const byte = field[i];
    if (byte === undefined) break;
    if (byte === 0) break;
    if (byte === 0x20) {
      if (text.length === 0) continue;
      break;
    }
    text += String.fromCharCode(byte);
  }
  if (!text) return null;
  const parsed = parseInt(text.trim(), 8);
  return Number.isFinite(parsed) ? parsed : null;
};

export const parseTarNumber = (
  bytes: Uint8Array,
  offset: number,
  length: number
): number | null => {
  const field = bytes.subarray(offset, offset + length);
  if (!field.length) return null;
  const first = field[0];
  if (first === undefined) return null;
  if ((first & 0x80) !== 0) {
    return parseBase256Number(field);
  }
  return parseOctalNumber(field);
};

export const computeChecksum = (headerBytes: Uint8Array): number => {
  let sum = 0;
  for (let i = 0; i < TAR_BLOCK_SIZE; i += 1) {
    if (i >= 148 && i < 156) {
      sum += 0x20;
    } else {
      const byte = headerBytes[i];
      sum += byte ?? 0;
    }
  }
  return sum;
};

export const describeFormat = (
  magic: string | null | undefined,
  version: string | null | undefined
): TarFormatInfo => {
  const normalizedMagic = magic || "";
  const normalizedVersion = version || "";
  if (normalizedMagic === "ustar" && normalizedVersion === "00") {
    return {
      magic: "ustar",
      version: "00",
      label: "POSIX ustar (1988)",
      kind: "posix"
    };
  }
  if (normalizedMagic === "ustar" && !normalizedVersion) {
    return {
      magic: "ustar",
      version: "",
      label: "POSIX ustar",
      kind: "posix"
    };
  }
  if (normalizedMagic === "ustar" || normalizedMagic === "ustar ") {
    return {
      magic: normalizedMagic,
      version: normalizedVersion,
      label: normalizedMagic === "ustar " ? "GNU tar (ustar)" : "ustar variant",
      kind: normalizedMagic === "ustar " ? "gnu" : "posix"
    };
  }
  return {
    magic: normalizedMagic,
    version: normalizedVersion,
    label: "Legacy V7 header (no magic)",
    kind: "legacy"
  };
};

export const formatModeSymbolic = (mode: number | null): string | null => {
  if (mode == null) return null;
  const owner = [
    (mode & 0o400) ? "r" : "-",
    (mode & 0o200) ? "w" : "-",
    (mode & 0o100) ? "x" : "-"
  ];
  const group = [
    (mode & 0o40) ? "r" : "-",
    (mode & 0o20) ? "w" : "-",
    (mode & 0o10) ? "x" : "-"
  ];
  const other = [
    (mode & 0o4) ? "r" : "-",
    (mode & 0o2) ? "w" : "-",
    (mode & 0o1) ? "x" : "-"
  ];
  if (mode & 0o4000) {
    owner[2] = owner[2] === "x" ? "s" : "S";
  }
  if (mode & 0o2000) {
    group[2] = group[2] === "x" ? "s" : "S";
  }
  if (mode & 0o1000) {
    other[2] = other[2] === "x" ? "t" : "T";
  }
  return owner.join("") + group.join("") + other.join("");
};

export const formatModeOctal = (mode: number | null): string | null => {
  if (mode == null) return null;
  return mode.toString(8).padStart(6, "0");
};

export const decodeNullTerminated = (bytes: Uint8Array): string => {
  const text = TEXT_DECODER.decode(bytes);
  const zeroIndex = text.indexOf("\0");
  return zeroIndex === -1 ? text : text.slice(0, zeroIndex);
};

export const parsePaxHeaders = (
  bytes: Uint8Array,
  issues: string[],
  label: string | null | undefined
): Record<string, string> => {
  const text = TEXT_DECODER.decode(bytes);
  const values: Record<string, string> = {};
  let cursor = 0;
  while (cursor < text.length) {
    const spaceIndex = text.indexOf(" ", cursor);
    if (spaceIndex === -1) break;
    const lengthText = text.slice(cursor, spaceIndex);
    const recordLength = parseInt(lengthText, 10);
    if (!Number.isFinite(recordLength) || recordLength <= 0) break;
    const recordEnd = cursor + recordLength;
    const record = text.slice(spaceIndex + 1, recordEnd - 1);
    const equalsIndex = record.indexOf("=");
    if (equalsIndex !== -1) {
      const key = record.slice(0, equalsIndex);
      const value = record.slice(equalsIndex + 1);
      values[key] = value;
    }
    cursor = recordEnd;
    if (cursor > text.length) break;
  }
  if (!Object.keys(values).length && label) {
    issues.push(`PAX header (${label}) is present but empty or invalid.`);
  }
  return values;
};

export const applyPaxValues = (
  entry: TarEntry,
  paxValues: Record<string, string> | null | undefined
): void => {
  if (!paxValues) return;
  const keys = Object.keys(paxValues);
  if (!keys.length) return;
  entry.pax = paxValues;
  entry.hasPax = true;
  entry.paxKeys = keys;
  if (paxValues["path"]) {
    entry.name = paxValues["path"];
    entry.usedPaxPath = true;
  }
  if (paxValues["linkpath"]) {
    entry.linkName = paxValues["linkpath"];
  }
  if (paxValues["size"]) {
    const sizeValue = Number.parseFloat(paxValues["size"]);
    if (Number.isFinite(sizeValue)) {
      entry.size = Math.max(0, Math.floor(sizeValue));
    }
  }
  if (paxValues["uid"]) {
    const uid = Number.parseInt(paxValues["uid"], 10);
    if (Number.isFinite(uid)) entry.uid = uid;
  }
  if (paxValues["gid"]) {
    const gid = Number.parseInt(paxValues["gid"], 10);
    if (Number.isFinite(gid)) entry.gid = gid;
  }
  if (paxValues["uname"]) {
    entry.uname = paxValues["uname"];
  }
  if (paxValues["gname"]) {
    entry.gname = paxValues["gname"];
  }
  if (paxValues["mtime"]) {
    const mtime = Number.parseFloat(paxValues["mtime"]);
    if (Number.isFinite(mtime)) {
      entry.mtime = Math.floor(mtime);
      entry.mtimeIso = formatUnixSecondsOrDash(entry.mtime);
    }
  }
};
