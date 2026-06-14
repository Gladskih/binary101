"use strict";

import { formatUnixSecondsOrDash } from "../../binary-utils.js";
import type { TarEntry, TarFeatures, TarParseResult, TarStats } from "./types.js";
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

const TYPEFLAG_DESCRIPTIONS: Record<string, string> = {
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

type TarPaxValues = ReturnType<typeof parsePaxHeaders>;

type TarParseState = {
  issues: string[];
  entries: TarEntry[];
  stats: TarStats;
  features: TarFeatures;
  formatInfo: ReturnType<typeof describeFormat> | null;
  pendingLongName: string | null;
  pendingLongLink: string | null;
  nextPaxValues: TarPaxValues | null;
  globalPaxValues: TarPaxValues | null;
};

type TarHeaderFields = {
  blockIndex: number;
  name: string;
  mode: number | null;
  uid: number | null;
  gid: number | null;
  size: number | null;
  mtime: number | null;
  checksum: number | null;
  typeFlag: string;
  linkName: string;
  magic: string;
  version: string;
  uname: string;
  gname: string;
  devMajor: number | null;
  devMinor: number | null;
  prefix: string;
  checksumComputed: number;
  checksumValid: boolean | null;
};

export function hasTarSignature(dv: DataView | null): boolean {
  if (!dv || dv.byteLength < TAR_SIGNATURE_OFFSET + TAR_SIGNATURE.length) return false;
  for (let i = 0; i < TAR_SIGNATURE.length; i += 1) {
    const char = String.fromCharCode(dv.getUint8(TAR_SIGNATURE_OFFSET + i));
    if (char !== TAR_SIGNATURE[i]) return false;
  }
  return true;
}

export type { TarEntry, TarFeatures, TarFormatInfo, TarParseResult, TarStats } from "./types.js";

const createTarParseState = (): TarParseState => ({
  issues: [],
  entries: [],
  stats: {
    totalEntries: 0,
    regularFiles: 0,
    directories: 0,
    symlinks: 0,
    metadataEntries: 0,
    totalFileBytes: 0,
    blocksConsumed: 0,
    truncatedEntries: 0
  },
  features: {
    usedLongNames: false,
    usedLongLinks: false,
    usedPaxHeaders: false,
    usedGlobalPax: false,
    checksumMismatches: 0
  },
  formatInfo: null,
  pendingLongName: null,
  pendingLongLink: null,
  nextPaxValues: null,
  globalPaxValues: null
});

const readTarHeaderFields = (headerBytes: Uint8Array, blockIndex: number): TarHeaderFields => {
  const typeFlagChar = String.fromCharCode(headerBytes[156] || 0);
  const checksum = parseTarNumber(headerBytes, 148, 8);
  const checksumComputed = computeChecksum(headerBytes);
  return {
    blockIndex,
    name: readTarString(headerBytes, 0, 100),
    mode: parseTarNumber(headerBytes, 100, 8),
    uid: parseTarNumber(headerBytes, 108, 8),
    gid: parseTarNumber(headerBytes, 116, 8),
    size: parseTarNumber(headerBytes, 124, 12),
    mtime: parseTarNumber(headerBytes, 136, 12),
    checksum,
    typeFlag: typeFlagChar === "\0" ? "0" : typeFlagChar,
    linkName: readTarString(headerBytes, 157, 100),
    magic: readTarString(headerBytes, 257, 6, { trimSpaces: false }),
    version: readTarString(headerBytes, 263, 2, { trimSpaces: false }),
    uname: readTarString(headerBytes, 265, 32),
    gname: readTarString(headerBytes, 297, 32),
    devMajor: parseTarNumber(headerBytes, 329, 8),
    devMinor: parseTarNumber(headerBytes, 337, 8),
    prefix: readTarString(headerBytes, 345, 155),
    checksumComputed,
    checksumValid: checksum == null ? null : checksum === checksumComputed
  };
};

const reportHeaderIssues = (state: TarParseState, header: TarHeaderFields): void => {
  if (!state.formatInfo) state.formatInfo = describeFormat(header.magic, header.version);
  if (header.checksumValid === false) {
    state.features.checksumMismatches += 1;
    state.issues.push(
      `Header checksum mismatch for entry at block ${header.blockIndex}: expected ${header.checksum}, got ${header.checksumComputed}.`
    );
  }
  if (header.size == null) {
    state.issues.push(`Entry at block ${header.blockIndex} is missing a valid size; assuming 0.`);
  }
};

const consumeMetadataEntry = (
  state: TarParseState,
  typeFlag: string,
  dataBytes: Uint8Array
): boolean => {
  if (typeFlag === "L" || typeFlag === "N") {
    state.pendingLongName = decodeNullTerminated(dataBytes);
    state.features.usedLongNames = true;
    state.stats.metadataEntries += 1;
    return true;
  }
  if (typeFlag === "K") {
    state.pendingLongLink = decodeNullTerminated(dataBytes);
    state.features.usedLongLinks = true;
    state.stats.metadataEntries += 1;
    return true;
  }
  if (typeFlag !== "x" && typeFlag !== "g") return false;
  const paxValues = parsePaxHeaders(dataBytes, state.issues, typeFlag === "g" ? "global" : "per-file");
  if (typeFlag === "g") {
    state.globalPaxValues = { ...(state.globalPaxValues || {}), ...paxValues };
    state.features.usedGlobalPax = true;
  } else {
    state.nextPaxValues = paxValues;
  }
  state.features.usedPaxHeaders = true;
  state.stats.metadataEntries += 1;
  return true;
};

const createTarEntry = (
  state: TarParseState,
  header: TarHeaderFields,
  safeSize: number,
  alignedSize: number,
  dataStart: number
): TarEntry => {
  const entry: TarEntry = {
    index: state.entries.length,
    name: state.pendingLongName || combineNameParts(header.prefix, header.name),
    rawName: header.name,
    prefix: header.prefix,
    typeFlag: header.typeFlag,
    typeLabel: TYPEFLAG_DESCRIPTIONS[header.typeFlag] || "Entry",
    size: safeSize,
    mode: header.mode,
    modeSymbolic: formatModeSymbolic(header.mode),
    modeOctal: formatModeOctal(header.mode),
    uid: header.uid,
    gid: header.gid,
    uname: header.uname,
    gname: header.gname,
    linkName: state.pendingLongLink || header.linkName,
    devMajor: header.devMajor,
    devMinor: header.devMinor,
    mtime: header.mtime,
    mtimeIso: header.mtime != null ? formatUnixSecondsOrDash(header.mtime) : "-",
    checksum: header.checksum,
    checksumComputed: header.checksumComputed,
    checksumValid: header.checksumValid,
    dataOffset: dataStart,
    blocks: 1 + alignedSize / TAR_BLOCK_SIZE
  };
  entry.usesLongName = Boolean(state.pendingLongName);
  entry.usesLongLink = Boolean(state.pendingLongLink);
  state.pendingLongName = null;
  state.pendingLongLink = null;
  return entry;
};

const storeTarEntry = (state: TarParseState, entry: TarEntry): void => {
  const combinedPax = { ...(state.globalPaxValues || {}), ...(state.nextPaxValues || {}) };
  if (Object.keys(combinedPax).length) applyPaxValues(entry, combinedPax);
  state.nextPaxValues = null;
  state.entries.push(entry);
  state.stats.totalEntries += 1;
  state.stats.blocksConsumed += entry.blocks;
  if (entry.size != null) state.stats.totalFileBytes += entry.size;
  if (entry.typeFlag === "5") state.stats.directories += 1;
  else if (entry.typeFlag === "2") state.stats.symlinks += 1;
  else if (entry.typeFlag === "0") state.stats.regularFiles += 1;
};

export async function parseTar(file: File): Promise<TarParseResult> {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const fileSize = bytes.byteLength;
  const state = createTarParseState();
  const blockCount = Math.floor(fileSize / TAR_BLOCK_SIZE);
  if (fileSize % TAR_BLOCK_SIZE !== 0) {
    state.issues.push("File size is not aligned to 512-byte TAR blocks; trailing data will be ignored.");
  }
  let offset = 0;
  let zeroRun = 0;
  while (offset + TAR_BLOCK_SIZE <= fileSize) {
    const headerBytes = bytes.subarray(offset, offset + TAR_BLOCK_SIZE);
    if (isZeroBlock(headerBytes)) {
      zeroRun += 1;
      offset += TAR_BLOCK_SIZE;
      if (zeroRun >= 2) break;
      continue;
    }
    zeroRun = 0;
    const header = readTarHeaderFields(headerBytes, Math.floor(offset / TAR_BLOCK_SIZE));
    reportHeaderIssues(state, header);
    const safeSize = header.size == null ? 0 : Math.max(0, Math.floor(header.size));
    const dataStart = offset + TAR_BLOCK_SIZE;
    if (dataStart > fileSize) {
      state.issues.push("Header declares data beyond file end.");
      break;
    }
    const alignedSize = align512(safeSize);
    const skipBytes = TAR_BLOCK_SIZE + alignedSize;
    if (dataStart + alignedSize > fileSize) {
      state.issues.push("Entry data is truncated before block boundary.");
      state.stats.truncatedEntries += 1;
    }
    const dataBytes = bytes.subarray(dataStart, Math.min(fileSize, dataStart + safeSize));
    if (!consumeMetadataEntry(state, header.typeFlag, dataBytes)) {
      storeTarEntry(state, createTarEntry(state, header, safeSize, alignedSize, dataStart));
    }
    offset += skipBytes;
  }

  if (state.entries.length && zeroRun < 2) {
    state.issues.push("Archive did not terminate with the standard two zero blocks.");
  }
  return {
    isTar: state.entries.length > 0,
    blockSize: TAR_BLOCK_SIZE,
    blockCount,
    fileSize,
    format: state.formatInfo || describeFormat("", ""),
    entries: state.entries,
    stats: state.stats,
    features: state.features,
    terminatorBlocks: zeroRun,
    issues: state.issues
  };
}
