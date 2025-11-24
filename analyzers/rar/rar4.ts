// @ts-nocheck
"use strict";

import {
  EHFL_NEXTVOLUME,
  HEAD3_ENDARC,
  HEAD3_FILE,
  HEAD3_MAIN,
  LHD_DIRECTORY,
  LHD_EXTTIME,
  LHD_LARGE,
  LHD_PASSWORD,
  LHD_SALT,
  LHD_SOLID,
  LHD_SPLIT_AFTER,
  LHD_SPLIT_BEFORE,
  LHD_UNICODE,
  LHD_WINDOWMASK,
  LONG_BLOCK,
  MHD_COMMENT,
  MHD_FIRSTVOLUME,
  MHD_LOCK,
  MHD_PASSWORD_FLAG,
  MHD_PROTECT,
  MHD_SOLID,
  MHD_VOLUME,
  RAR4_METHODS,
  SIGNATURE_V4
} from "./constants.js";
import {
  combineToBigInt,
  decodeNameBytes,
  formatDosDateTime,
  mapHostV4,
  readDataView,
  toSafeNumber
} from "./utils.js";

const parseRar4FileHeader = (headerDv, flags, issues, headerOffset) => {
  if (headerDv.byteLength < 32) {
    issues.push("RAR file header is shorter than expected.");
    return null;
  }
  const packSizeLow = headerDv.getUint32(7, true);
  const unpSizeLow = headerDv.getUint32(11, true);
  const hostOs = headerDv.getUint8(15);
  const crc32Value = headerDv.getUint32(16, true);
  const dosTime = headerDv.getUint32(20, true);
  const unpVer = headerDv.getUint8(24);
  const methodRaw = headerDv.getUint8(25);
  const nameSize = headerDv.getUint16(26, true);
  const fileAttr = headerDv.getUint32(28, true);

  let cursor = 32;
  let highPack = 0;
  let highUnp = 0;
  if ((flags & LHD_LARGE) !== 0) {
    if (headerDv.byteLength >= cursor + 8) {
      highPack = headerDv.getUint32(cursor, true);
      highUnp = headerDv.getUint32(cursor + 4, true);
      cursor += 8;
    } else {
      issues.push("RAR large file header is truncated.");
    }
  }
  const packSizeBig = combineToBigInt(highPack, packSizeLow);
  const unpSizeBig = combineToBigInt(highUnp, unpSizeLow);

  const remaining = Math.max(headerDv.byteLength - cursor, 0);
  const nameLength = Math.min(nameSize, remaining);
  const nameBytes = new Uint8Array(headerDv.buffer, headerDv.byteOffset + cursor, nameLength);
  const rawName = decodeNameBytes(nameBytes, false);
  let name = rawName;
  const zeroIndex = name.indexOf("\0");
  if (zeroIndex !== -1) name = name.slice(0, zeroIndex);

  cursor += nameLength;
  let salt = null;
  if ((flags & LHD_SALT) !== 0) {
    if (cursor + 8 <= headerDv.byteLength) {
      salt = new Uint8Array(headerDv.buffer, headerDv.byteOffset + cursor, 8);
      cursor += 8;
    } else {
      issues.push("RAR salt field is truncated.");
    }
  }

  const methodCode = Math.max(0, methodRaw - 0x30);
  const method = RAR4_METHODS[methodCode] || `Method ${methodCode}`;
  const isDirectory = (flags & LHD_WINDOWMASK) === LHD_DIRECTORY || (fileAttr & 0x10) !== 0;

  const entry = {
    headerOffset,
    flags,
    name,
    rawName,
    packSize: packSizeBig,
    unpackedSize: unpSizeBig,
    hostOs: mapHostV4(hostOs),
    crc32: crc32Value,
    modified: formatDosDateTime(dosTime),
    versionRequired: unpVer,
    method,
    isDirectory,
    isSplitBefore: (flags & LHD_SPLIT_BEFORE) !== 0,
    isSplitAfter: (flags & LHD_SPLIT_AFTER) !== 0,
    isEncrypted: (flags & LHD_PASSWORD) !== 0,
    isSolid: (flags & LHD_SOLID) !== 0,
    hasSalt: (flags & LHD_SALT) !== 0,
    hasUnicodeName: (flags & LHD_UNICODE) !== 0,
    hasExtendedTime: (flags & LHD_EXTTIME) !== 0,
    salt
  };
  return { entry, nextOffsetDelta: packSizeBig };
};

export const parseRar4 = async file => {
  const issues = [];
  const entries = [];
  const fileSize = file.size || 0;
  let mainHeader = null;
  let endHeader = null;
  let offset = SIGNATURE_V4.length;
  let guard = 0;

  while (offset + 7 <= fileSize && guard < 4096) {
    guard += 1;
    const base = await readDataView(file, offset, 7);
    if (!base || base.byteLength < 7) {
      issues.push("RAR header is truncated.");
      break;
    }
    const headType = base.getUint8(2);
    const flags = base.getUint16(3, true);
    const headSize = base.getUint16(5, true);
    if (headSize < 7) {
      issues.push("RAR header size is invalid.");
      break;
    }
    const headerDv = await readDataView(file, offset, headSize);
    if (!headerDv || headerDv.byteLength < headSize) {
      issues.push("RAR header could not be fully read.");
      break;
    }
    let nextOffset = offset + headSize;
    if (headType === HEAD3_MAIN) {
      mainHeader = {
        offset,
        flags,
        isVolume: (flags & MHD_VOLUME) !== 0,
        hasComment: (flags & MHD_COMMENT) !== 0,
        isLocked: (flags & MHD_LOCK) !== 0,
        isSolid: (flags & MHD_SOLID) !== 0,
        hasRecovery: (flags & MHD_PROTECT) !== 0,
        isEncrypted: (flags & MHD_PASSWORD_FLAG) !== 0,
        isFirstVolume: (flags & MHD_FIRSTVOLUME) !== 0
      };
    } else if (headType === HEAD3_FILE) {
      const parsed = parseRar4FileHeader(headerDv, flags, issues, offset);
      if (parsed?.entry) {
        parsed.entry.index = entries.length;
        entries.push(parsed.entry);
        const delta = parsed.nextOffsetDelta;
        const deltaNumber = toSafeNumber(delta);
        if (deltaNumber == null) {
          issues.push("RAR file size exceeds supported range; truncating traversal.");
          break;
        }
        nextOffset = offset + headSize + deltaNumber;
      }
    } else if (headType === HEAD3_ENDARC) {
      endHeader = {
        offset,
        flags,
        nextVolume: (flags & EHFL_NEXTVOLUME) !== 0
      };
    } else if ((flags & LONG_BLOCK) !== 0) {
      if (headerDv.byteLength >= 11) {
        const dataSize = headerDv.getUint32(7, true);
        nextOffset = offset + headSize + dataSize;
      }
    }
    if (nextOffset <= offset) {
      issues.push("RAR parsing stopped due to non-advancing offset.");
      break;
    }
    offset = nextOffset;
  }

  return {
    isRar: true,
    version: 4,
    mainHeader,
    entries,
    endHeader,
    issues
  };
};
