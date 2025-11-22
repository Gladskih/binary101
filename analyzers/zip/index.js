/* eslint-disable max-lines */
"use strict";
import { formatUnixSecondsOrDash, readAsciiString } from "../../binary-utils.js";
const EOCD_SIGNATURE = 0x06054b50;
const ZIP64_EOCD_LOCATOR_SIGNATURE = 0x07064b50;
const ZIP64_EOCD_SIGNATURE = 0x06064b50;
const CENTRAL_DIR_SIGNATURE = 0x02014b50;
const LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
const MIN_EOCD_SIZE = 22;
const MIN_LOCAL_HEADER_SIZE = 30;
const MAX_EOCD_SCAN = 131072;
const MAX_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: false });
const COMPRESSION_METHODS = new Map([
  [0, "Stored"],
  [1, "Shrunk"],
  [6, "Imploded"],
  [8, "Deflated"],
  [9, "Deflate64"],
  [12, "BZIP2"],
  [14, "LZMA"],
  [18, "IBM TERSE"],
  [19, "IBM LZ77 z"],
  [93, "Zstandard"],
  [94, "MP3"],
  [95, "XZ"],
  [96, "JPEG"],
  [97, "WavPack"],
  [98, "PPMd"],
  [99, "AES encrypted"]
]);
const readUtf8 = bytes => UTF8_DECODER.decode(bytes);
const getSafeNumber = value => {
  if (typeof value === "number") return value;
  if (value <= Number.MAX_SAFE_INTEGER) return Number(value);
  return null;
};
const getBigUint64 = (dv, offset) => dv.getBigUint64(offset, true);
const dosDateTimeToIso = (dosDate, dosTime) => {
  const seconds = (dosTime & 0x1f) * 2;
  const minutes = (dosTime >> 5) & 0x3f;
  const hours = (dosTime >> 11) & 0x1f;
  const day = dosDate & 0x1f;
  const month = (dosDate >> 5) & 0x0f;
  const year = ((dosDate >> 9) & 0x7f) + 1980;
  if (!year || !month || !day) return null;
  const unixSeconds =
    Date.UTC(year, month - 1, day, hours, minutes, seconds) / 1000;
  return formatUnixSecondsOrDash(unixSeconds);
};
const readTailForEocd = async file => {
  const fileSize = file.size || 0;
  const probeSize = Math.min(fileSize, MAX_EOCD_SCAN);
  const start = Math.max(0, fileSize - probeSize);
  const buffer = await file.slice(start, fileSize).arrayBuffer();
  return { baseOffset: start, dv: new DataView(buffer) };
};
const parseEocd = (dv, baseOffset) => {
  for (let i = dv.byteLength - MIN_EOCD_SIZE; i >= 0; i -= 1) {
    if (dv.getUint32(i, true) !== EOCD_SIGNATURE) continue;
    const commentLength = dv.getUint16(i + 20, true);
    if (i + MIN_EOCD_SIZE + commentLength > dv.byteLength) continue;
    const diskNumber = dv.getUint16(i + 4, true);
    const centralDirDisk = dv.getUint16(i + 6, true);
    const entriesThisDisk = dv.getUint16(i + 8, true);
    const totalEntries = dv.getUint16(i + 10, true);
    const centralDirSize = dv.getUint32(i + 12, true);
    const centralDirOffset = dv.getUint32(i + 16, true);
    const comment =
      commentLength > 0
        ? readAsciiString(dv, i + 22, Math.min(commentLength, 32768))
        : "";
    return {
      offset: baseOffset + i,
      diskNumber,
      centralDirDisk,
      entriesThisDisk,
      totalEntries,
      centralDirSize,
      centralDirOffset,
      comment,
      commentLength
    };
  }
  return null;
};
const findZip64Locator = (dv, baseOffset) => {
  const locatorSize = 20;
  const limit = dv.byteLength - locatorSize;
  let found = null;
  for (let i = 0; i <= limit; i += 1) {
    if (dv.getUint32(i, true) !== ZIP64_EOCD_LOCATOR_SIGNATURE) continue;
    const diskWithEocd = dv.getUint32(i + 4, true);
    const zip64EocdOffset = getBigUint64(dv, i + 8);
    const totalDisks = dv.getUint32(i + 16, true);
    found = {
      offset: baseOffset + i,
      diskWithEocd,
      zip64EocdOffset,
      totalDisks
    };
  }
  return found;
};

const readDataView = async (file, offset, length) => {
  if (offset == null) return null;
  if (length <= 0) return new DataView(new ArrayBuffer(0));
  const fileSize = file.size || 0;
  if (offset >= fileSize) return null;
  const clampedLength = Math.min(length, fileSize - offset);
  const buffer = await file.slice(offset, offset + clampedLength).arrayBuffer();
  return new DataView(buffer);
};
const parseZip64Eocd = async (file, locator, issues) => {
  const offsetNumber = getSafeNumber(locator.zip64EocdOffset);
  if (offsetNumber == null) {
    issues.push("ZIP64 EOCD offset exceeds supported range.");
    return null;
  }
  const headerView = await readDataView(file, offsetNumber, 12);
  if (!headerView || headerView.byteLength < 12) {
    issues.push("ZIP64 EOCD record is truncated or missing.");
    return null;
  }
  if (headerView.getUint32(0, true) !== ZIP64_EOCD_SIGNATURE) {
    issues.push("ZIP64 EOCD signature mismatch.");
    return null;
  }
  const recordSize = headerView.getBigUint64(4, true);
  const totalSize = getSafeNumber(recordSize + 12n);
  if (totalSize == null || totalSize > 1048576) {
    issues.push("ZIP64 EOCD record is too large to inspect.");
    return null;
  }
  const dv = await readDataView(file, offsetNumber, totalSize);
  if (!dv || dv.byteLength < 56) {
    issues.push("ZIP64 EOCD record is truncated.");
    return null;
  }
  return {
    offset: offsetNumber,
    size: totalSize,
    versionMadeBy: dv.getUint16(12, true),
    versionNeeded: dv.getUint16(14, true),
    diskNumber: dv.getUint32(16, true),
    centralDirDisk: dv.getUint32(20, true),
    entriesThisDisk: getBigUint64(dv, 24),
    totalEntries: getBigUint64(dv, 32),
    centralDirSize: getBigUint64(dv, 40),
    centralDirOffset: getBigUint64(dv, 48)
  };
};

const parseZip64Extra = (dv, start, length, entry) => {
  let cursor = start;
  if (entry.uncompressedSize === 0xffffffff && cursor + 8 <= start + length) {
    entry.uncompressedSize = getBigUint64(dv, cursor);
    cursor += 8;
  }
  if (entry.compressedSize === 0xffffffff && cursor + 8 <= start + length) {
    entry.compressedSize = getBigUint64(dv, cursor);
    cursor += 8;
  }
  if (entry.localHeaderOffset === 0xffffffff && cursor + 8 <= start + length) {
    entry.localHeaderOffset = getBigUint64(dv, cursor);
    cursor += 8;
  }
  if (entry.diskNumberStart === 0xffff && cursor + 4 <= start + length) {
    entry.diskNumberStart = dv.getUint32(cursor, true);
  }
};

const parseCentralDirectoryEntries = (dv, issues) => {
  const entries = [];
  let cursor = 0;
  let index = 0;
  while (cursor + 46 <= dv.byteLength) {
    if (dv.getUint32(cursor, true) !== CENTRAL_DIR_SIGNATURE) break;
    const compressionMethod = dv.getUint16(cursor + 10, true);
    const flags = dv.getUint16(cursor + 8, true);
    const dosTime = dv.getUint16(cursor + 12, true);
    const dosDate = dv.getUint16(cursor + 14, true);
    const crc32 = dv.getUint32(cursor + 16, true);
    const compressedSize = dv.getUint32(cursor + 20, true);
    const uncompressedSize = dv.getUint32(cursor + 24, true);
    const nameLength = dv.getUint16(cursor + 28, true);
    const extraLength = dv.getUint16(cursor + 30, true);
    const commentLength = dv.getUint16(cursor + 32, true);
    const diskNumberStart = dv.getUint16(cursor + 34, true);
    const internalAttrs = dv.getUint16(cursor + 36, true);
    const externalAttrs = dv.getUint32(cursor + 38, true);
    const localHeaderOffset = dv.getUint32(cursor + 42, true);
    const totalLength = 46 + nameLength + extraLength + commentLength;
    if (cursor + totalLength > dv.byteLength) {
      issues.push("Central directory entry is truncated.");
      break;
    }
    const nameBytes = new Uint8Array(
      dv.buffer,
      dv.byteOffset + cursor + 46,
      nameLength
    );
    const extraStart = cursor + 46 + nameLength;
    const commentStart = extraStart + extraLength;
    const name = readUtf8(nameBytes);
    const commentBytes = new Uint8Array(
      dv.buffer,
      dv.byteOffset + commentStart,
      commentLength
    );
    const comment = commentLength ? readUtf8(commentBytes) : "";
    const entry = {
      index,
      fileName: name,
      comment,
      compressionMethod,
      compressionName: COMPRESSION_METHODS.get(compressionMethod) || "Unknown",
      flags,
      isUtf8: (flags & 0x0800) !== 0,
      isEncrypted: (flags & 0x0001) !== 0,
      usesDataDescriptor: (flags & 0x0008) !== 0,
      modTimeIso: dosDateTimeToIso(dosDate, dosTime),
      crc32,
      compressedSize,
      uncompressedSize,
      diskNumberStart,
      internalAttrs,
      externalAttrs,
      localHeaderOffset
    };
    const extraBytes = new DataView(
      dv.buffer,
      dv.byteOffset + extraStart,
      extraLength
    );
    let extraCursor = 0;
    while (extraCursor + 4 <= extraBytes.byteLength) {
      const headerId = extraBytes.getUint16(extraCursor, true);
      const dataSize = extraBytes.getUint16(extraCursor + 2, true);
      const dataStart = extraCursor + 4;
      const dataEnd = dataStart + dataSize;
      if (dataEnd > extraBytes.byteLength) break;
      if (headerId === 0x0001) {
        parseZip64Extra(extraBytes, dataStart, dataSize, entry);
      }
      extraCursor = dataEnd;
    }
    entries.push(entry);
    cursor += totalLength;
    index += 1;
  }
  if (cursor < dv.byteLength) {
    issues.push("Central directory parsing stopped early due to unexpected data.");
  }
  return entries;
};

const annotateEntryDataOffsets = async (file, entries) => {
  const fileSize = file.size || 0;
  for (const entry of entries) {
    const setExtractError = message => {
      if (!entry.extractError) entry.extractError = message;
    };
    const localOffset = getSafeNumber(entry.localHeaderOffset);
    if (localOffset == null) {
      setExtractError("Local header offset exceeds supported range.");
      continue;
    }
    const localHeader = await readDataView(file, localOffset, MIN_LOCAL_HEADER_SIZE);
    if (!localHeader || localHeader.byteLength < MIN_LOCAL_HEADER_SIZE) {
      setExtractError("Local file header is truncated or missing.");
      continue;
    }
    if (localHeader.getUint32(0, true) !== LOCAL_FILE_HEADER_SIGNATURE) {
      setExtractError("Local file header signature mismatch.");
      continue;
    }
    const nameLength = localHeader.getUint16(26, true);
    const extraLength = localHeader.getUint16(28, true);
    const dataOffset = localOffset + MIN_LOCAL_HEADER_SIZE + nameLength + extraLength;
    entry.localHeader = {
      nameLength,
      extraLength,
      offset: localOffset
    };
    const compressedSize = getSafeNumber(entry.compressedSize);
    entry.dataOffset = dataOffset;
    entry.dataLength = compressedSize;
    entry.dataEnd = compressedSize == null ? null : dataOffset + compressedSize;
    const dataPastEnd = entry.dataEnd != null && entry.dataEnd > fileSize;
    const startPastEnd = dataOffset > fileSize;
    if (startPastEnd || dataPastEnd) {
      setExtractError("Compressed data extends beyond the file size.");
      continue;
    }
    if (entry.isEncrypted) {
      setExtractError("Encrypted entries are not supported for extraction.");
      continue;
    }
    const isSupportedMethod = entry.compressionMethod === 0 || entry.compressionMethod === 8;
    if (!isSupportedMethod) {
      setExtractError("Compression method is not supported for extraction.");
    }
    if (compressedSize == null) {
      setExtractError("Compressed size exceeds supported range.");
    }
  }
};

export async function parseZip(file) {
  const issues = [];
  const { baseOffset, dv: tailView } = await readTailForEocd(file);
  const eocd = parseEocd(tailView, baseOffset);
  if (!eocd) return null;
  const zip64Locator = findZip64Locator(tailView, baseOffset);
  const zip64 = zip64Locator ? await parseZip64Eocd(file, zip64Locator, issues) : null;
  const expectsZip64 =
    eocd.entriesThisDisk === 0xffff ||
    eocd.totalEntries === 0xffff ||
    eocd.centralDirSize === 0xffffffff ||
    eocd.centralDirOffset === 0xffffffff;
  if (expectsZip64) {
    if (!zip64Locator) {
      issues.push(
        "EOCD fields use ZIP64 placeholders but ZIP64 locator was not found."
      );
    } else if (!zip64) {
      issues.push(
        "ZIP64 metadata could not be read even though EOCD fields require it."
      );
    }
  }
  const cdOffsetSource = zip64?.centralDirOffset ?? eocd.centralDirOffset;
  const cdSizeSource = zip64?.centralDirSize ?? eocd.centralDirSize;
  const cdOffset = getSafeNumber(cdOffsetSource);
  const cdSize = getSafeNumber(cdSizeSource);
  if (cdOffset == null || cdSize == null) {
    issues.push("Central directory offset or size is outside supported range.");
    return { eocd, zip64, centralDirectory: null, issues };
  }
  const cdEnd = cdOffset + cdSize;
  const fileSize = file.size || 0;
  const truncated = cdEnd > fileSize;
  if (truncated) {
    issues.push("Central directory extends beyond the file size.");
  }
  const limitedSize = Math.min(cdSize, MAX_CENTRAL_DIRECTORY_BYTES, fileSize - cdOffset);
  const cdView = await readDataView(file, cdOffset, limitedSize);
  if (!cdView) {
    issues.push("Central directory could not be read.");
    return { eocd, zip64, centralDirectory: null, issues };
  }
  const entries = parseCentralDirectoryEntries(cdView, issues);
  if (eocd && entries.length !== eocd.totalEntries) {
    issues.push(
      `EOCD reports ${eocd.totalEntries} entries but parsed ${entries.length}.`
    );
  }
  await annotateEntryDataOffsets(file, entries);
  return {
    eocd,
    zip64Locator,
    zip64,
    centralDirectory: {
      offset: cdOffset,
      size: cdSize,
      parsedSize: cdView.byteLength,
      truncated,
      entries
    },
    issues
  };
}
