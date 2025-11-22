"use strict";

import { formatUnixSecondsOrDash } from "../../binary-utils.js";
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
import { crc32, decodeNameBytes, mapHostV5, readDataView, readVint, toSafeNumber } from "./utils.js";

const computeRar5DictSize = (compInfo, algoVersion, isDirectory) => {
  if (isDirectory || algoVersion > 1) return null;
  const basePower = (compInfo >> 10) & (algoVersion === 0 ? 0x0f : 0x1f);
  let size = 0x20000n << BigInt(basePower);
  if (algoVersion === 1) {
    const fraction = (compInfo >> 15) & 0x1f;
    size += (size / 32n) * BigInt(fraction);
  }
  return size;
};

export const parseRar5 = async file => {
  const issues = [];
  const entries = [];
  const fileSize = file.size || 0;
  let mainHeader = null;
  let endHeader = null;
  let offset = SIGNATURE_V5.length;
  let guard = 0;

  while (offset + 7 <= fileSize && guard < 4096) {
    guard += 1;
    const probe = await readDataView(file, offset, 32);
    if (!probe || probe.byteLength < 5) {
      issues.push("RAR header is truncated.");
      break;
    }
    const headerCrc = probe.getUint32(0, true);
    const headerSizeInfo = readVint(probe, 4);
    if (headerSizeInfo.value == null) {
      issues.push("RAR header size could not be decoded.");
      break;
    }
    const headerSizeNumber = toSafeNumber(headerSizeInfo.value);
    if (headerSizeNumber == null) {
      issues.push("RAR header size exceeds supported range.");
      break;
    }
    const headerSizeLength = headerSizeInfo.length;
    const headerTotal = 4 + headerSizeLength + headerSizeNumber;
    if (offset + headerTotal > fileSize) {
      issues.push("RAR header extends beyond file bounds.");
      break;
    }

    const headerBytes = new Uint8Array(await file.slice(offset + 4, offset + headerTotal).arrayBuffer());
    const computedCrc = crc32(headerBytes);
    if (computedCrc !== headerCrc) {
      issues.push(`RAR header CRC mismatch at offset ${offset}.`);
    }
    const headerDv = new DataView(headerBytes.buffer, headerBytes.byteOffset, headerBytes.byteLength);
    let cursor = headerSizeLength;
    const typeInfo = readVint(headerDv, cursor);
    if (typeInfo.value == null) break;
    cursor += typeInfo.length;
    const headerType = toSafeNumber(typeInfo.value);
    const flagsInfo = readVint(headerDv, cursor);
    if (flagsInfo.value == null) break;
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
      break;
    }

    if (headerType === 1) {
      const archiveFlagsInfo = readVint(headerDv, cursor);
      const archiveFlags = toSafeNumber(archiveFlagsInfo.value) || 0;
      cursor += archiveFlagsInfo.length;
      let volumeNumber = null;
      if ((archiveFlags & MHFL_VOLNUMBER) !== 0) {
        const volInfo = readVint(headerDv, cursor);
        volumeNumber = toSafeNumber(volInfo.value);
        cursor += volInfo.length;
      }
      mainHeader = {
        offset,
        flags: archiveFlags,
        isVolume: (archiveFlags & MHFL_VOLUME) !== 0,
        isSolid: (archiveFlags & MHFL_SOLID) !== 0,
        hasRecovery: (archiveFlags & MHFL_PROTECT) !== 0,
        isLocked: (archiveFlags & MHFL_LOCK) !== 0,
        volumeNumber
      };
    } else if (headerType === 2) {
      const fileFlagsInfo = readVint(headerDv, cursor);
      cursor += fileFlagsInfo.length;
      const fileFlags = toSafeNumber(fileFlagsInfo.value) || 0;
      const unpSizeInfo = readVint(headerDv, cursor);
      cursor += unpSizeInfo.length;
      const attrInfo = readVint(headerDv, cursor);
      cursor += attrInfo.length;
      let modified = null;
      if ((fileFlags & FHFL_UTIME) !== 0) {
        if (cursor + 4 <= headerLimit) {
          const mtime = headerDv.getUint32(cursor, true);
          modified = formatUnixSecondsOrDash(mtime);
          cursor += 4;
        } else {
          issues.push("RAR file time field is truncated.");
        }
      }
      let dataCrc = null;
      if ((fileFlags & FHFL_CRC32) !== 0) {
        if (cursor + 4 <= headerLimit) {
          dataCrc = headerDv.getUint32(cursor, true);
          cursor += 4;
        } else {
          issues.push("RAR file CRC field is truncated.");
        }
      }
      const compInfo = readVint(headerDv, cursor);
      cursor += compInfo.length;
      const compValue = toSafeNumber(compInfo.value) || 0;
      const methodCode = (compValue >> 7) & 7;
      const compVersionBits = compValue & 0x3f;
      const algoVersion = compVersionBits === 0 ? "RAR5" : compVersionBits === 1 ? "RAR7" : "Unknown";
      const hostInfo = readVint(headerDv, cursor);
      cursor += hostInfo.length;
      const hostOs = toSafeNumber(hostInfo.value) || 0;
      const nameLenInfo = readVint(headerDv, cursor);
      cursor += nameLenInfo.length;
      const nameLen = toSafeNumber(nameLenInfo.value) || 0;
      const nameAvailable = Math.min(nameLen, Math.max(0, headerLimit - cursor));
      if (nameAvailable < nameLen) {
        issues.push("RAR file name is truncated.");
      }
      const nameBytes = new Uint8Array(headerDv.buffer, headerDv.byteOffset + cursor, nameAvailable);
      const name = decodeNameBytes(nameBytes, true);
      cursor += nameAvailable;

      const unpackedSize = (fileFlags & FHFL_UNPUNKNOWN) !== 0 ? null : unpSizeInfo.value;
      const dictSize = computeRar5DictSize(compValue, compVersionBits, (fileFlags & FHFL_DIRECTORY) !== 0);
      const entry = {
        index: entries.length,
        headerOffset: offset,
        flags: fileFlags,
        headerFlags,
        name,
        packSize: dataSizeBig,
        unpackedSize,
        hostOs: mapHostV5(hostOs),
        modified,
        crc32: dataCrc,
        method: RAR5_METHODS[methodCode] || `Method ${methodCode}`,
        algoVersion,
        dictionarySize: dictSize,
        isDirectory: (fileFlags & FHFL_DIRECTORY) !== 0,
        isSolid: (compValue & FCI_SOLID) !== 0,
        isSplitBefore: (headerFlags & HFL_SPLITBEFORE) !== 0,
        isSplitAfter: (headerFlags & HFL_SPLITAFTER) !== 0,
        isInherited: (headerFlags & HFL_INHERITED) !== 0,
        isChild: (headerFlags & HFL_CHILD) !== 0
      };
      entries.push(entry);
    } else if (headerType === 5) {
      const arcFlagsInfo = readVint(headerDv, cursor);
      const arcFlags = toSafeNumber(arcFlagsInfo.value) || 0;
      endHeader = {
        offset,
        flags: arcFlags,
        nextVolume: (arcFlags & EHFL_NEXTVOLUME) !== 0
      };
    }

    const nextOffset = (() => {
      const next = BigInt(offset) + BigInt(headerTotal) + dataSizeBig;
      if (next > BigInt(fileSize)) {
        issues.push("RAR data area extends beyond file size.");
        return fileSize;
      }
      return Number(next);
    })();
    if (nextOffset <= offset) {
      issues.push("RAR parsing stopped due to non-advancing offset.");
      break;
    }
    offset = nextOffset;
  }

  return {
    isRar: true,
    version: 5,
    mainHeader,
    entries,
    endHeader,
    issues
  };
};
