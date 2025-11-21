"use strict";

// This file is a collection of helper functions from analyzers/tar/index.js
// It is used to test these functions in isolation.

const TAR_BLOCK_SIZE = 512;
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: false });

export const toSafeNumber = value => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "bigint") {
    const max = BigInt(Number.MAX_SAFE_INTEGER);
    if (value <= max && value >= BigInt(Number.MIN_SAFE_INTEGER)) {
      return Number(value);
    }
  }
  return null;
};

export const align512 = value => {
  if (value <= 0) return 0;
  return Math.ceil(value / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
};

export const isZeroBlock = bytes => {
  for (let i = 0; i < bytes.length; i += 1) {
    if (bytes[i] !== 0) return false;
  }
  return true;
};

export const readTarString = (bytes, offset, length, options = {}) => {
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

export const combineNameParts = (prefix, baseName) => {
  const cleanPrefix = prefix ? prefix.replace(/\/+$/, "") : "";
  if (cleanPrefix && baseName) return `${cleanPrefix}/${baseName}`;
  if (cleanPrefix) return cleanPrefix;
  return baseName || "";
};

export const parseBase256Number = field => {
  const bytes = new Uint8Array(field);
  if (!bytes.length) return null;
  bytes[0] &= 0x7f; // clear the indicator bit
  let value = 0n;
  for (let i = 0; i < bytes.length; i += 1) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  const safeNumber = toSafeNumber(value);
  return safeNumber;
};

export const parseOctalNumber = field => {
  let text = "";
  for (let i = 0; i < field.length; i += 1) {
    const byte = field[i];
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

export const parseTarNumber = (bytes, offset, length) => {
  const field = bytes.subarray(offset, offset + length);
  if (!field.length) return null;
  const first = field[0];
  if ((first & 0x80) !== 0) {
    return parseBase256Number(field);
  }
  return parseOctalNumber(field);
};

export const computeChecksum = headerBytes => {
  let sum = 0;
  for (let i = 0; i < TAR_BLOCK_SIZE; i += 1) {
    if (i >= 148 && i < 156) {
      sum += 0x20;
    } else {
      sum += headerBytes[i];
    }
  }
  return sum;
};

export const describeFormat = (magic, version) => {
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

export const formatModeSymbolic = mode => {
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

export const formatModeOctal = mode => {
  if (mode == null) return null;
  return mode.toString(8).padStart(6, "0");
};
