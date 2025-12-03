"use strict";

import { formatUnixSecondsOrDash } from "../../binary-utils.js";
import {
  CENTRAL_DIR_SIGNATURE,
  COMPRESSION_METHODS,
  LOCAL_FILE_HEADER_SIGNATURE,
  MIN_LOCAL_HEADER_SIZE,
  UTF8_DECODER
} from "./constants.js";
import { getSafeNumber, readDataView } from "./io.js";
import type { ZipCentralDirectoryEntry, ZipCentralDirectoryEntryLocalHeaderInfo } from "./types.js";

const readUtf8 = (bytes: Uint8Array): string => UTF8_DECODER.decode(bytes);

const dosDateTimeToIso = (dosDate: number, dosTime: number): string | null => {
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

const parseZip64Extra = (
  dv: DataView,
  start: number,
  length: number,
  entry: ZipCentralDirectoryEntry
): void => {
  let cursor = start;
  if (entry.uncompressedSize === 0xffffffff && cursor + 8 <= start + length) {
    entry.uncompressedSize = dv.getBigUint64(cursor, true);
    cursor += 8;
  }
  if (entry.compressedSize === 0xffffffff && cursor + 8 <= start + length) {
    entry.compressedSize = dv.getBigUint64(cursor, true);
    cursor += 8;
  }
  if (entry.localHeaderOffset === 0xffffffff && cursor + 8 <= start + length) {
    entry.localHeaderOffset = dv.getBigUint64(cursor, true);
    cursor += 8;
  }
  if (entry.diskNumberStart === 0xffff && cursor + 4 <= start + length) {
    entry.diskNumberStart = dv.getUint32(cursor, true);
  }
};

const parseCentralDirectoryEntries = (
  dv: DataView,
  issues: string[]
): ZipCentralDirectoryEntry[] => {
  const entries: ZipCentralDirectoryEntry[] = [];
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
    const entry: ZipCentralDirectoryEntry = {
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

const annotateEntryDataOffsets = async (
  file: File,
  entries: ZipCentralDirectoryEntry[]
): Promise<void> => {
  const fileSize = file.size || 0;
  for (const entry of entries) {
    const setExtractError = (message: string): void => {
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
    } as ZipCentralDirectoryEntryLocalHeaderInfo;
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

export { annotateEntryDataOffsets, parseCentralDirectoryEntries };
