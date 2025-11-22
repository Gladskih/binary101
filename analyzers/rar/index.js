"use strict";

import { formatUnixSecondsOrDash } from "../../binary-utils.js";

const SIGNATURE_V4 = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
const SIGNATURE_V5 = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];

const LHD_SPLIT_BEFORE = 0x0001;
const LHD_SPLIT_AFTER = 0x0002;
const LHD_PASSWORD = 0x0004;
const LHD_SOLID = 0x0010;
const LHD_DIRECTORY = 0x00e0;
const LHD_WINDOWMASK = 0x00e0;
const LHD_LARGE = 0x0100;
const LHD_UNICODE = 0x0200;
const LHD_SALT = 0x0400;
const LHD_EXTTIME = 0x1000;
const LONG_BLOCK = 0x8000;

const MHD_VOLUME = 0x0001;
const MHD_COMMENT = 0x0002;
const MHD_LOCK = 0x0004;
const MHD_SOLID = 0x0008;
const MHD_PROTECT = 0x0040;
const MHD_PASSWORD_FLAG = 0x0080;
const MHD_FIRSTVOLUME = 0x0100;

const HEAD3_MAIN = 0x73;
const HEAD3_FILE = 0x74;
const HEAD3_ENDARC = 0x7b;

const HFL_EXTRA = 0x0001;
const HFL_DATA = 0x0002;
const HFL_SPLITBEFORE = 0x0008;
const HFL_SPLITAFTER = 0x0010;
const HFL_CHILD = 0x0020;
const HFL_INHERITED = 0x0040;

const MHFL_VOLUME = 0x0001;
const MHFL_VOLNUMBER = 0x0002;
const MHFL_SOLID = 0x0004;
const MHFL_PROTECT = 0x0008;
const MHFL_LOCK = 0x0010;

const FHFL_DIRECTORY = 0x0001;
const FHFL_UTIME = 0x0002;
const FHFL_CRC32 = 0x0004;
const FHFL_UNPUNKNOWN = 0x0008;

const EHFL_NEXTVOLUME = 0x0001;

const FCI_SOLID = 0x00000040;

const RAR4_METHODS = ["Store", "Fastest", "Fast", "Normal", "Good", "Best"];
const RAR5_METHODS = ["Store", "Faster", "Fast", "Normal", "Good", "Best"];

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

const crc32 = bytes => {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    const index = (crc ^ bytes[i]) & 0xff;
    crc = (crc >>> 8) ^ CRC32_TABLE[index];
  }
  return (crc ^ 0xffffffff) >>> 0;
};

const toSafeNumber = value => {
  if (typeof value === "number") return value;
  if (typeof value === "bigint") {
    if (value <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
    return null;
  }
  return null;
};

const readDataView = async (file, offset, length) => {
  if (offset >= (file.size || 0)) return null;
  const clampedLength = Math.max(0, Math.min(length, (file.size || 0) - offset));
  const buffer = await file.slice(offset, offset + clampedLength).arrayBuffer();
  return new DataView(buffer);
};

const readVint = (dv, offset) => {
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

const combineToBigInt = (high, low) => {
  const hi = BigInt(high >>> 0);
  const lo = BigInt(low >>> 0);
  return (hi << 32n) + lo;
};

const formatDosDateTime = dosValue => {
  const seconds = (dosValue & 0x1f) * 2;
  const minutes = (dosValue >> 5) & 0x3f;
  const hours = (dosValue >> 11) & 0x1f;
  const day = (dosValue >> 16) & 0x1f;
  const month = (dosValue >> 21) & 0x0f;
  const year = ((dosValue >> 25) & 0x7f) + 1980;
  if (!year || !month || !day) return "-";
  const unixSeconds =
    Date.UTC(year, month - 1, day, hours, minutes, seconds) / 1000;
  return formatUnixSecondsOrDash(unixSeconds);
};

const mapHostV4 = value =>
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

const mapHostV5 = value =>
  value === 0 ? "Windows" : value === 1 ? "Unix" : `Host ${value}`;

const decodeNameBytes = (bytes, preferUtf8 = true) => {
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

const detectRarVersionBytes = bytes => {
  const slice4 = SIGNATURE_V4;
  const slice5 = SIGNATURE_V5;
  const matches = sig => sig.every((b, idx) => bytes[idx] === b);
  if (bytes.length >= slice5.length && matches(slice5)) return 5;
  if (bytes.length >= slice4.length && matches(slice4)) return 4;
  return null;
};

export const hasRarSignature = dv => {
  const bytes = new Uint8Array(
    dv.buffer,
    dv.byteOffset,
    Math.min(dv.byteLength, SIGNATURE_V5.length)
  );
  return detectRarVersionBytes(bytes) != null;
};

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
  const nameBytes = new Uint8Array(
    headerDv.buffer,
    headerDv.byteOffset + cursor,
    nameLength
  );
  const rawName = decodeNameBytes(nameBytes, false);
  let name = rawName;
  const zeroIndex = name.indexOf("\0");
  if (zeroIndex !== -1) name = name.slice(0, zeroIndex);

  cursor += nameLength;
  let salt = null;
  if ((flags & LHD_SALT) !== 0) {
    if (cursor + 8 <= headerDv.byteLength) {
      salt = new Uint8Array(
        headerDv.buffer,
        headerDv.byteOffset + cursor,
        8
      );
      cursor += 8;
    } else {
      issues.push("RAR salt field is truncated.");
    }
  }

  const methodCode = Math.max(0, methodRaw - 0x30);
  const method = RAR4_METHODS[methodCode] || `Method ${methodCode}`;
  const isDirectory =
    (flags & LHD_WINDOWMASK) === LHD_DIRECTORY || (fileAttr & 0x10) !== 0;

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

const parseRar4 = async file => {
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

const parseRar5 = async file => {
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

    const headerBytes = new Uint8Array(
      await file.slice(offset + 4, offset + headerTotal).arrayBuffer()
    );
    const computedCrc = crc32(headerBytes);
    if (computedCrc !== headerCrc) {
      issues.push(`RAR header CRC mismatch at offset ${offset}.`);
    }
    const headerDv = new DataView(
      headerBytes.buffer,
      headerBytes.byteOffset,
      headerBytes.byteLength
    );
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
      const fileAttr = toSafeNumber(attrInfo.value) || 0;
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
      const nameAvailable = Math.min(
        nameLen,
        Math.max(0, headerLimit - cursor)
      );
      if (nameAvailable < nameLen) {
        issues.push("RAR file name is truncated.");
      }
      const nameBytes = new Uint8Array(
        headerDv.buffer,
        headerDv.byteOffset + cursor,
        nameAvailable
      );
      const name = decodeNameBytes(nameBytes, true);
      cursor += nameAvailable;

      const unpackedSize = (fileFlags & FHFL_UNPUNKNOWN) !== 0 ? null : unpSizeInfo.value;
      const dictSize = computeRar5DictSize(
        compValue,
        compVersionBits,
        (fileFlags & FHFL_DIRECTORY) !== 0
      );
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

export async function parseRar(file) {
  const signatureBytes = new Uint8Array(
    await file.slice(0, SIGNATURE_V5.length).arrayBuffer()
  );
  const version = detectRarVersionBytes(signatureBytes);
  if (version === 4) return parseRar4(file);
  if (version === 5) return parseRar5(file);
  return { isRar: false, version: null, entries: [], issues: ["Not a RAR archive."] };
}
