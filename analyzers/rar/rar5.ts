"use strict";
import { formatUnixSecondsOrDash } from "../../binary-utils.js";
import { crc32 } from "../crc32.js";
import {
  EHFL_NEXTVOLUME,
  FHFL_CRC32,
  FHFL_DIRECTORY,
  FHFL_UNPUNKNOWN,
  FHFL_UTIME,
  FCI_SOLID,
  HFL_CHILD,
  HFL_DATA,
  HFL_EXTRA,
  HFL_INHERITED,
  HFL_SPLITAFTER,
  HFL_SPLITBEFORE,
  MHFL_LOCK,
  MHFL_PROTECT,
  MHFL_SOLID,
  MHFL_VOLUME,
  MHFL_VOLNUMBER,
  RAR5_METHODS,
  SIGNATURE_V5
} from "./constants.js";
import { decodeNameBytes, mapHostV5, readDataView, readVint, toSafeNumber } from "./utils.js";
import type { RarEntry, RarParseResult, RarMainHeader, RarEndHeader } from "./index.js";
const computeRar5DictSize = (compInfo: number, algoVersion: number, isDirectory: boolean): bigint | null => {
  if (isDirectory || algoVersion > 1) return null;
  const basePower = (compInfo >> 10) & (algoVersion === 0 ? 0x0f : 0x1f);
  let size = 0x20000n << BigInt(basePower);
  if (algoVersion === 1) {
    const fraction = (compInfo >> 15) & 0x1f;
    size += (size / 32n) * BigInt(fraction);
  }
  return size;
};
type Rar5HeaderEnvelope = {
  offset: number;
  headerDv: DataView;
  headerTotal: number;
  headerType: number;
  headerFlags: number;
  headerLimit: number;
  cursor: number;
  dataSizeBig: bigint;
};
type Rar5ParseState = {
  issues: string[];
  entries: RarEntry[];
  mainHeader: (RarMainHeader & { offset: number; flags: number }) | null;
  endHeader: RarEndHeader | null;
};
type Rar5FileEntry = RarEntry & {
  headerOffset: number;
  flags: number;
  headerFlags: number;
  algoVersion: string;
  dictionarySize: bigint | null;
};
const createRar5ParseState = (): Rar5ParseState => ({
  issues: [],
  entries: [],
  mainHeader: null,
  endHeader: null
});
const readRar5HeaderEnvelope = async (
  file: File,
  offset: number,
  fileSize: number,
  issues: string[]
): Promise<Rar5HeaderEnvelope | null> => {
  const probe = await readDataView(file, offset, 32);
  if (!probe || probe.byteLength < 5) {
    issues.push("RAR header is truncated.");
    return null;
  }
  const headerCrc = probe.getUint32(0, true);
  const headerSizeInfo = readVint(probe, 4);
  if (headerSizeInfo.value == null) {
    issues.push("RAR header size could not be decoded.");
    return null;
  }
  const headerSizeNumber = toSafeNumber(headerSizeInfo.value);
  if (headerSizeNumber == null) {
    issues.push("RAR header size exceeds supported range.");
    return null;
  }
  const headerTotal = 4 + headerSizeInfo.length + headerSizeNumber;
  if (offset + headerTotal > fileSize) {
    issues.push("RAR header extends beyond file bounds.");
    return null;
  }
  const headerBytes = new Uint8Array(await file.slice(offset + 4, offset + headerTotal).arrayBuffer());
  if (crc32(headerBytes) !== headerCrc) issues.push(`RAR header CRC mismatch at offset ${offset}.`);
  const headerDv = new DataView(headerBytes.buffer, headerBytes.byteOffset, headerBytes.byteLength);
  return decodeRar5HeaderEnvelope(offset, headerDv, headerSizeInfo.length, headerSizeNumber, headerTotal, issues);
};
const decodeRar5HeaderEnvelope = (
  offset: number,
  headerDv: DataView,
  cursorStart: number,
  headerSizeNumber: number,
  headerTotal: number,
  issues: string[]
): Rar5HeaderEnvelope | null => {
  let cursor = cursorStart;
  const typeInfo = readVint(headerDv, cursor);
  if (typeInfo.value == null) return null;
  cursor += typeInfo.length;
  const headerType = toSafeNumber(typeInfo.value);
  if (headerType == null) return null;
  const flagsInfo = readVint(headerDv, cursor);
  if (flagsInfo.value == null) return null;
  cursor += flagsInfo.length;
  const headerFlags = toSafeNumber(flagsInfo.value) || 0;
  let extraSize = 0;
  if ((headerFlags & HFL_EXTRA) !== 0) {
    const extraInfo = readVint(headerDv, cursor);
    cursor += extraInfo.length;
    extraSize = toSafeNumber(extraInfo.value) || 0;
  }
  let dataSizeBig = 0n;
  if ((headerFlags & HFL_DATA) !== 0) {
    const dataInfo = readVint(headerDv, cursor);
    cursor += dataInfo.length;
    dataSizeBig = dataInfo.value || 0n;
  }
  const headerLimit = Math.max(headerSizeNumber - extraSize, 0);
  if (cursor > headerLimit) {
    issues.push("RAR header fields exceed declared size.");
    return null;
  }
  return { offset, headerDv, headerTotal, headerType, headerFlags, headerLimit, cursor, dataSizeBig };
};
const parseRar5MainHeader = (envelope: Rar5HeaderEnvelope): Rar5ParseState["mainHeader"] => {
  const archiveFlagsInfo = readVint(envelope.headerDv, envelope.cursor);
  const archiveFlags = toSafeNumber(archiveFlagsInfo.value) || 0;
  const cursor = envelope.cursor + archiveFlagsInfo.length;
  let volumeNumber = null;
  if ((archiveFlags & MHFL_VOLNUMBER) !== 0) {
    const volInfo = readVint(envelope.headerDv, cursor);
    volumeNumber = toSafeNumber(volInfo.value);
  }
  return {
    offset: envelope.offset,
    flags: archiveFlags,
    isVolume: (archiveFlags & MHFL_VOLUME) !== 0,
    isSolid: (archiveFlags & MHFL_SOLID) !== 0,
    hasRecovery: (archiveFlags & MHFL_PROTECT) !== 0,
    isLocked: (archiveFlags & MHFL_LOCK) !== 0,
    volumeNumber
  };
};
const parseRar5FileEntry = (envelope: Rar5HeaderEnvelope, entries: RarEntry[], issues: string[]): Rar5FileEntry => {
  let cursor = envelope.cursor;
  const fileFlagsInfo = readVint(envelope.headerDv, cursor);
  cursor += fileFlagsInfo.length;
  const fileFlags = toSafeNumber(fileFlagsInfo.value) || 0;
  const unpSizeInfo = readVint(envelope.headerDv, cursor);
  cursor += unpSizeInfo.length;
  const attrInfo = readVint(envelope.headerDv, cursor);
  cursor += attrInfo.length;
  const modified = readRar5FileTime(envelope.headerDv, envelope.headerLimit, fileFlags, cursor, issues);
  if ((fileFlags & FHFL_UTIME) !== 0 && cursor + 4 <= envelope.headerLimit) cursor += 4;
  const dataCrc = readRar5FileCrc(envelope.headerDv, envelope.headerLimit, fileFlags, cursor, issues);
  if ((fileFlags & FHFL_CRC32) !== 0 && cursor + 4 <= envelope.headerLimit) cursor += 4;
  const compInfo = readVint(envelope.headerDv, cursor);
  cursor += compInfo.length;
  const compValue = toSafeNumber(compInfo.value) || 0;
  const hostInfo = readVint(envelope.headerDv, cursor);
  cursor += hostInfo.length;
  const nameInfo = readRar5Name(
    envelope.headerDv,
    envelope.headerLimit,
    cursor,
    issues
  );
  const compVersionBits = compValue & 0x3f;
  return {
    index: entries.length,
    headerOffset: envelope.offset,
    flags: fileFlags,
    headerFlags: envelope.headerFlags,
    name: nameInfo.name,
    packSize: envelope.dataSizeBig,
    unpackedSize: (fileFlags & FHFL_UNPUNKNOWN) !== 0 ? null : unpSizeInfo.value,
    hostOs: mapHostV5(toSafeNumber(hostInfo.value) || 0),
    modified,
    crc32: dataCrc,
    method: RAR5_METHODS[(compValue >> 7) & 7] || `Method ${(compValue >> 7) & 7}`,
    algoVersion: compVersionBits === 0 ? "RAR5" : compVersionBits === 1 ? "RAR7" : "Unknown",
    dictionarySize: computeRar5DictSize(compValue, compVersionBits, (fileFlags & FHFL_DIRECTORY) !== 0),
    isDirectory: (fileFlags & FHFL_DIRECTORY) !== 0,
    isSolid: (compValue & FCI_SOLID) !== 0,
    isSplitBefore: (envelope.headerFlags & HFL_SPLITBEFORE) !== 0,
    isSplitAfter: (envelope.headerFlags & HFL_SPLITAFTER) !== 0,
    isInherited: (envelope.headerFlags & HFL_INHERITED) !== 0,
    isChild: (envelope.headerFlags & HFL_CHILD) !== 0
  };
};

const readRar5FileTime = (
  headerDv: DataView,
  headerLimit: number,
  fileFlags: number,
  cursor: number,
  issues: string[]
): string | null => {
  if ((fileFlags & FHFL_UTIME) === 0) return null;
  if (cursor + 4 <= headerLimit) return formatUnixSecondsOrDash(headerDv.getUint32(cursor, true));
  issues.push("RAR file time field is truncated.");
  return null;
};

const readRar5FileCrc = (
  headerDv: DataView,
  headerLimit: number,
  fileFlags: number,
  cursor: number,
  issues: string[]
): number | null => {
  if ((fileFlags & FHFL_CRC32) === 0) return null;
  if (cursor + 4 <= headerLimit) return headerDv.getUint32(cursor, true);
  issues.push("RAR file CRC field is truncated.");
  return null;
};

const readRar5Name = (
  headerDv: DataView,
  headerLimit: number,
  cursor: number,
  issues: string[]
): { name: string } => {
  const nameLenInfo = readVint(headerDv, cursor);
  const nameStart = cursor + nameLenInfo.length;
  const nameLen = toSafeNumber(nameLenInfo.value) || 0;
  const nameAvailable = Math.min(nameLen, Math.max(0, headerLimit - nameStart));
  if (nameAvailable < nameLen) issues.push("RAR file name is truncated.");
  return {
    name: decodeNameBytes(new Uint8Array(headerDv.buffer, headerDv.byteOffset + nameStart, nameAvailable), true)
  };
};

const parseRar5EndHeader = (envelope: Rar5HeaderEnvelope): RarEndHeader => {
  const arcFlagsInfo = readVint(envelope.headerDv, envelope.cursor);
  const arcFlags = toSafeNumber(arcFlagsInfo.value) || 0;
  return {
    offset: envelope.offset,
    flags: arcFlags,
    nextVolume: (arcFlags & EHFL_NEXTVOLUME) !== 0
  };
};

const advanceRar5Offset = (
  offset: number,
  fileSize: number,
  envelope: Rar5HeaderEnvelope,
  issues: string[]
): number => {
  const next = BigInt(offset) + BigInt(envelope.headerTotal) + envelope.dataSizeBig;
  if (next > BigInt(fileSize)) {
    issues.push("RAR data area extends beyond file size.");
    return fileSize;
  }
  return Number(next);
};

export const parseRar5 = async (file: File): Promise<RarParseResult> => {
  const state = createRar5ParseState();
  const fileSize = file.size || 0;
  let offset = SIGNATURE_V5.length;
  let guard = 0;
  while (offset + 7 <= fileSize && guard < 4096) {
    guard += 1;
    const envelope = await readRar5HeaderEnvelope(file, offset, fileSize, state.issues);
    if (!envelope) break;
    if (envelope.headerType === 1) {
      state.mainHeader = parseRar5MainHeader(envelope);
    } else if (envelope.headerType === 2) {
      state.entries.push(parseRar5FileEntry(envelope, state.entries, state.issues));
    } else if (envelope.headerType === 5) {
      state.endHeader = parseRar5EndHeader(envelope);
      break;
    }
    const nextOffset = advanceRar5Offset(offset, fileSize, envelope, state.issues);
    if (nextOffset <= offset) {
      state.issues.push("RAR parsing stopped due to non-advancing offset.");
      break;
    }
    offset = nextOffset;
  }
  return {
    isRar: true,
    version: 5,
    mainHeader: state.mainHeader,
    entries: state.entries,
    endHeader: state.endHeader,
    issues: state.issues
  };
};
