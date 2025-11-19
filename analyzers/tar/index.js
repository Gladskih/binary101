/* eslint-disable max-lines */
"use strict";

import { formatUnixSecondsOrDash } from "../../binary-utils.js";

const TAR_BLOCK_SIZE = 512;
const TAR_SIGNATURE_OFFSET = 257;
const TAR_SIGNATURE = "ustar";
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: false });

const TYPEFLAG_DESCRIPTIONS = {
  "0": "Regular file",
  "\0": "Regular file",
  "1": "Hard link",
  "2": "Symbolic link",
  "3": "Character device",
  "4": "Block device",
  "5": "Directory",
  "6": "FIFO/pipe",
  "7": "Reserved",
  "g": "Global PAX header",
  "x": "PAX extended header",
  "L": "GNU long filename",
  "K": "GNU long linkname",
  "D": "GNU sparse file",
  "S": "GNU sparse metadata",
  "N": "Old GNU long filename",
  "V": "Tape volume header"
};

const toSafeNumber = value => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "bigint") {
    const max = BigInt(Number.MAX_SAFE_INTEGER);
    if (value <= max && value >= BigInt(Number.MIN_SAFE_INTEGER)) {
      return Number(value);
    }
  }
  return null;
};

const align512 = value => {
  if (value <= 0) return 0;
  return Math.ceil(value / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
};

const isZeroBlock = bytes => {
  for (let i = 0; i < bytes.length; i += 1) {
    if (bytes[i] !== 0) return false;
  }
  return true;
};

const readTarString = (bytes, offset, length, options = {}) => {
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

const combineNameParts = (prefix, baseName) => {
  const cleanPrefix = prefix ? prefix.replace(/\/+$/, "") : "";
  if (cleanPrefix && baseName) return `${cleanPrefix}/${baseName}`;
  if (cleanPrefix) return cleanPrefix;
  return baseName || "";
};

const parseBase256Number = field => {
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

const parseOctalNumber = field => {
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

const parseTarNumber = (bytes, offset, length) => {
  const field = bytes.subarray(offset, offset + length);
  if (!field.length) return null;
  const first = field[0];
  if ((first & 0x80) !== 0) {
    return parseBase256Number(field);
  }
  return parseOctalNumber(field);
};

const computeChecksum = headerBytes => {
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

const describeFormat = (magic, version) => {
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

const formatModeSymbolic = mode => {
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

const formatModeOctal = mode => {
  if (mode == null) return null;
  return mode.toString(8).padStart(6, "0");
};

const decodeNullTerminated = bytes => {
  const text = TEXT_DECODER.decode(bytes);
  const zeroIndex = text.indexOf("\0");
  return zeroIndex === -1 ? text : text.slice(0, zeroIndex);
};

const parsePaxHeaders = (bytes, issues, label) => {
  const text = TEXT_DECODER.decode(bytes);
  const values = {};
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

const applyPaxValues = (entry, paxValues) => {
  if (!paxValues) return;
  const keys = Object.keys(paxValues);
  if (!keys.length) return;
  entry.pax = paxValues;
  entry.hasPax = true;
  entry.paxKeys = keys;
  if (paxValues.path) {
    entry.name = paxValues.path;
    entry.usedPaxPath = true;
  }
  if (paxValues.linkpath) {
    entry.linkName = paxValues.linkpath;
  }
  if (paxValues.size) {
    const sizeValue = Number.parseFloat(paxValues.size);
    if (Number.isFinite(sizeValue)) {
      entry.size = Math.max(0, Math.floor(sizeValue));
    }
  }
  if (paxValues.uid) {
    const uid = Number.parseInt(paxValues.uid, 10);
    if (Number.isFinite(uid)) entry.uid = uid;
  }
  if (paxValues.gid) {
    const gid = Number.parseInt(paxValues.gid, 10);
    if (Number.isFinite(gid)) entry.gid = gid;
  }
  if (paxValues.uname) {
    entry.uname = paxValues.uname;
  }
  if (paxValues.gname) {
    entry.gname = paxValues.gname;
  }
  if (paxValues.mtime) {
    const mtime = Number.parseFloat(paxValues.mtime);
    if (Number.isFinite(mtime)) {
      entry.mtime = Math.floor(mtime);
      entry.mtimeIso = formatUnixSecondsOrDash(entry.mtime);
    }
  }
};

export function hasTarSignature(dv) {
  if (!dv || dv.byteLength < TAR_SIGNATURE_OFFSET + TAR_SIGNATURE.length) return false;
  for (let i = 0; i < TAR_SIGNATURE.length; i += 1) {
    const char = String.fromCharCode(dv.getUint8(TAR_SIGNATURE_OFFSET + i));
    if (char !== TAR_SIGNATURE[i]) return false;
  }
  return true;
}

export async function parseTar(file) {
  const issues = [];
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const fileSize = bytes.byteLength;
  const blockCount = Math.floor(fileSize / TAR_BLOCK_SIZE);
  const remainder = fileSize % TAR_BLOCK_SIZE;
  if (remainder !== 0) {
    issues.push("File size is not aligned to 512-byte TAR blocks; trailing data will be ignored.");
  }
  const entries = [];
  const stats = {
    totalEntries: 0,
    regularFiles: 0,
    directories: 0,
    symlinks: 0,
    metadataEntries: 0,
    totalFileBytes: 0,
    blocksConsumed: 0,
    truncatedEntries: 0
  };
  const features = {
    usedLongNames: false,
    usedLongLinks: false,
    usedPaxHeaders: false,
    usedGlobalPax: false,
    checksumMismatches: 0
  };

  let offset = 0;
  let zeroRun = 0;
  let formatInfo = null;
  let pendingLongName = null;
  let pendingLongLink = null;
  let nextPaxValues = null;
  let globalPaxValues = null;

  while (offset + TAR_BLOCK_SIZE <= fileSize) {
    const headerBytes = bytes.subarray(offset, offset + TAR_BLOCK_SIZE);
    if (isZeroBlock(headerBytes)) {
      zeroRun += 1;
      offset += TAR_BLOCK_SIZE;
      if (zeroRun >= 2) break;
      continue;
    }
    zeroRun = 0;

    const blockIndex = Math.floor(offset / TAR_BLOCK_SIZE);
    const name = readTarString(headerBytes, 0, 100);
    const mode = parseTarNumber(headerBytes, 100, 8);
    const uid = parseTarNumber(headerBytes, 108, 8);
    const gid = parseTarNumber(headerBytes, 116, 8);
    const size = parseTarNumber(headerBytes, 124, 12);
    const mtime = parseTarNumber(headerBytes, 136, 12);
    const checksum = parseTarNumber(headerBytes, 148, 8);
    const typeFlagChar = String.fromCharCode(headerBytes[156] || 0);
    const typeFlag = typeFlagChar === "\0" ? "0" : typeFlagChar;
    const linkName = readTarString(headerBytes, 157, 100);
    const magic = readTarString(headerBytes, 257, 6, { trimSpaces: false });
    const version = readTarString(headerBytes, 263, 2, { trimSpaces: false });
    const uname = readTarString(headerBytes, 265, 32);
    const gname = readTarString(headerBytes, 297, 32);
    const devMajor = parseTarNumber(headerBytes, 329, 8);
    const devMinor = parseTarNumber(headerBytes, 337, 8);
    const prefix = readTarString(headerBytes, 345, 155);

    if (!formatInfo) {
      formatInfo = describeFormat(magic, version);
    }

    const checksumComputed = computeChecksum(headerBytes);
    const checksumValid = checksum == null ? null : checksum === checksumComputed;
    if (checksumValid === false) {
      features.checksumMismatches += 1;
      issues.push(
        `Header checksum mismatch for entry at block ${blockIndex}: expected ${checksum}, got ${checksumComputed}.`
      );
    }

    if (size == null) {
      issues.push(
        `Entry at block ${blockIndex} is missing a valid size; assuming 0.`
      );
    }
    const safeSize = size == null ? 0 : Math.max(0, Math.floor(size));
    const dataStart = offset + TAR_BLOCK_SIZE;
    if (dataStart > fileSize) {
      issues.push("Header declares data beyond file end.");
      break;
    }
    const alignedSize = align512(safeSize);
    const dataEnd = dataStart + safeSize;
    const skipBytes = TAR_BLOCK_SIZE + alignedSize;
    if (dataStart + alignedSize > fileSize) {
      issues.push("Entry data is truncated before block boundary.");
      stats.truncatedEntries += 1;
    }

    const dataBytes = bytes.subarray(dataStart, Math.min(fileSize, dataEnd));

    if (typeFlag === "L" || typeFlag === "N") {
      pendingLongName = decodeNullTerminated(dataBytes);
      features.usedLongNames = true;
      stats.metadataEntries += 1;
      offset += skipBytes;
      continue;
    }
    if (typeFlag === "K") {
      pendingLongLink = decodeNullTerminated(dataBytes);
      features.usedLongLinks = true;
      stats.metadataEntries += 1;
      offset += skipBytes;
      continue;
    }
    if (typeFlag === "x" || typeFlag === "g") {
      const paxValues = parsePaxHeaders(dataBytes, issues, typeFlag === "g" ? "global" : "per-file");
      if (typeFlag === "g") {
        globalPaxValues = { ...(globalPaxValues || {}), ...paxValues };
        features.usedGlobalPax = true;
      } else {
        nextPaxValues = paxValues;
      }
      features.usedPaxHeaders = true;
      stats.metadataEntries += 1;
      offset += skipBytes;
      continue;
    }

    const entry = {
      index: entries.length,
      name: pendingLongName || combineNameParts(prefix, name),
      rawName: name,
      prefix,
      typeFlag,
      typeLabel: TYPEFLAG_DESCRIPTIONS[typeFlag] || "Entry",
      size: safeSize,
      mode,
      modeSymbolic: formatModeSymbolic(mode),
      modeOctal: formatModeOctal(mode),
      uid,
      gid,
      uname,
      gname,
      linkName: pendingLongLink || linkName,
      devMajor,
      devMinor,
      mtime,
      mtimeIso: mtime != null ? formatUnixSecondsOrDash(mtime) : "-",
      checksum,
      checksumComputed,
      checksumValid,
      dataOffset: dataStart,
      blocks: 1 + alignedSize / TAR_BLOCK_SIZE
    };
    entry.usesLongName = Boolean(pendingLongName);
    entry.usesLongLink = Boolean(pendingLongLink);
    pendingLongName = null;
    pendingLongLink = null;

    const combinedPax = {
      ...(globalPaxValues || {}),
      ...(nextPaxValues || {})
    };
    if (Object.keys(combinedPax).length) {
      applyPaxValues(entry, combinedPax);
    }
    nextPaxValues = null;

    entries.push(entry);
    stats.totalEntries += 1;
    stats.blocksConsumed += entry.blocks;
    if (entry.size != null) stats.totalFileBytes += entry.size;
    if (entry.typeFlag === "5") stats.directories += 1;
    else if (entry.typeFlag === "2") stats.symlinks += 1;
    else if (entry.typeFlag === "0") stats.regularFiles += 1;

    offset += skipBytes;
  }

  if (entries.length && zeroRun < 2) {
    issues.push("Archive did not terminate with the standard two zero blocks.");
  }

  const parsed = {
    isTar: entries.length > 0,
    blockSize: TAR_BLOCK_SIZE,
    blockCount,
    fileSize,
    format: formatInfo || describeFormat("", ""),
    entries,
    stats,
    features,
    terminatorBlocks: zeroRun,
    issues
  };
  return parsed;
}
