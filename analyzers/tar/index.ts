// @ts-nocheck
"use strict";

import { formatUnixSecondsOrDash } from "../../binary-utils.js";
import {
  align512,
  isZeroBlock,
  readTarString,
  combineNameParts,
  parseTarNumber,
  computeChecksum,
  describeFormat,
  formatModeSymbolic,
  formatModeOctal,
  decodeNullTerminated,
  parsePaxHeaders,
  applyPaxValues
} from "./helpers.js";

const TAR_BLOCK_SIZE = 512;
const TAR_SIGNATURE_OFFSET = 257;
const TAR_SIGNATURE = "ustar";

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
