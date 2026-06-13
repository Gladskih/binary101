"use strict";

import { formatUnixSecondsOrDash, toHex32 } from "../../binary-utils.js";
import {
  type SevenZipContext,
  type SevenZipFileInfoEntry,
  type SevenZipFilesInfo
} from "./types.js";
import {
  readBoolVector,
  readBitVector,
  readByte,
  readEncodedUint64,
  readUint32Le,
  readUint64Le,
  toSafeNumber
} from "./readers.js";

const UTF16_DECODER = new TextDecoder("utf-16le", { fatal: false });
// 7z DOC/7zFormat.txt NID values for FilesInfo properties.
// https://www.7-zip.org/sdk.html
const FILES_INFO_END_ID = 0x00;
const EMPTY_STREAMS_PROPERTY_ID = 0x0e;
const EMPTY_FILES_PROPERTY_ID = 0x0f;
const ANTI_ITEMS_PROPERTY_ID = 0x10;
const NAMES_PROPERTY_ID = 0x11;
const MODIFICATION_TIMES_PROPERTY_ID = 0x14;
const ATTRIBUTES_PROPERTY_ID = 0x15;
// Windows FILETIME stores 100 ns intervals since 1601-01-01 UTC.
// https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times
const FILETIME_TICKS_PER_SECOND = 10000000n;
const FILETIME_UNIX_EPOCH_SECONDS = 11644473600n;
// FILE_ATTRIBUTE_DIRECTORY from Win32 file attributes.
// https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
const WINDOWS_DIRECTORY_ATTRIBUTE = 0x10;

const filetimeToIso = (filetime: bigint | null | undefined): string | null => {
  if (typeof filetime !== "bigint") return null;
  const seconds = filetime / FILETIME_TICKS_PER_SECOND - FILETIME_UNIX_EPOCH_SECONDS;
  if (seconds < 0n || seconds > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return formatUnixSecondsOrDash(Number(seconds));
};

const parseTimes = (
  ctx: SevenZipContext,
  fileCount: number,
  endOffset: number,
  label: string
): Array<string | null> | null => {
  const defined = readBoolVector(ctx, fileCount, endOffset, `${label} defined flags`);
  if (!defined) return null;
  const external = readByte(ctx, `${label} external flag`);
  if (external == null) return null;
  if (external !== 0) {
    ctx.issues.push(`${label} stored externally; skipping.`);
    ctx.offset = endOffset;
    return null;
  }
  const times = new Array<string | null>(fileCount).fill(null);
  for (let i = 0; i < fileCount; i += 1) {
    if (!defined[i]) continue;
    const raw = readUint64Le(ctx, endOffset, `${label} value`);
    if (raw == null) break;
    times[i] = filetimeToIso(raw);
  }
  ctx.offset = Math.max(ctx.offset, endOffset);
  return times;
};

const parseAttributes = (
  ctx: SevenZipContext,
  fileCount: number,
  endOffset: number
): Array<number | null> | null => {
  const defined = readBoolVector(ctx, fileCount, endOffset, "Attribute defined flags");
  if (!defined) return null;
  const external = readByte(ctx, "Attribute external flag");
  if (external == null) return null;
  if (external !== 0) {
    ctx.issues.push("File attributes stored externally; skipping.");
    ctx.offset = endOffset;
    return null;
  }
  const attributes = new Array<number | null>(fileCount).fill(null);
  for (let i = 0; i < fileCount; i += 1) {
    if (!defined[i]) continue;
    const attr = readUint32Le(ctx, endOffset, "Attribute value");
    if (attr == null) break;
    attributes[i] = attr;
  }
  ctx.offset = Math.max(ctx.offset, endOffset);
  return attributes;
};

const parseNames = (
  ctx: SevenZipContext,
  fileCount: number,
  endOffset: number
): { names: string[]; external: boolean } => {
  const external = readByte(ctx, "Name external flag");
  if (external == null) return { names: [], external: false };
  if (external !== 0) {
    ctx.issues.push("File names are stored externally; unable to read.");
    ctx.offset = endOffset;
    return { names: [], external: true };
  }
  const bytesAvailable = Math.max(endOffset - ctx.offset, 0);
  const nameBytes = new Uint8Array(
    ctx.dv.buffer,
    ctx.dv.byteOffset + ctx.offset,
    bytesAvailable
  );
  const decoded = UTF16_DECODER.decode(nameBytes);
  const parts = decoded.split("\u0000");
  const names = new Array<string>(fileCount).fill("(no name)");
  for (let i = 0; i < fileCount && i < parts.length; i += 1) {
    const part = parts[i];
    if (part) names[i] = part;
  }
  ctx.offset = endOffset;
  return { names, external: false };
};

const expandEmptyStreamFlags = (
  flags: boolean[] | null,
  emptyStreams: boolean[] | null,
  fileCount: number
): boolean[] | null => {
  if (!flags || !emptyStreams) return flags;
  const expanded = new Array<boolean>(fileCount).fill(false);
  let emptyIndex = 0;
  for (let index = 0; index < fileCount; index += 1) {
    if (!emptyStreams[index]) continue;
    expanded[index] = Boolean(flags[emptyIndex]);
    emptyIndex += 1;
  }
  return expanded;
};

export const parseFilesInfo = (ctx: SevenZipContext): SevenZipFilesInfo => {
  const numFiles = readEncodedUint64(ctx, "File count");
  const fileCount = toSafeNumber(numFiles);
  if (fileCount == null) {
    return { fileCount: null, files: [], hasNames: false, hasModificationTimes: false };
  }
  const files: SevenZipFileInfoEntry[] = Array.from({ length: fileCount }, (_, index) => ({
    index: index + 1
  }));
  let emptyStreams: boolean[] | null = null;
  let emptyFiles: boolean[] | null = null;
  let antiItems: boolean[] | null = null;
  let names: string[] | null = null;
  let mTimes: Array<string | null> | null = null;
  let attributes: Array<number | null> | null = null;
  let hasNames = false;
  let hasModificationTimes = false;
  while (ctx.offset < ctx.dv.byteLength) {
    const propertyType = readByte(ctx, "File property id");
    if (propertyType == null) break;
    if (propertyType === FILES_INFO_END_ID) break;
    const propertySize = readEncodedUint64(ctx, "File property size");
    const sizeNumber = propertySize != null ? toSafeNumber(propertySize) : null;
    if (sizeNumber == null || ctx.offset + sizeNumber > ctx.dv.byteLength) {
      ctx.issues.push("File property size exceeds available data.");
      ctx.offset = ctx.dv.byteLength;
      break;
    }
    const propEnd = ctx.offset + sizeNumber;
    if (propertyType === EMPTY_STREAMS_PROPERTY_ID) {
      emptyStreams = readBitVector(
        ctx,
        fileCount,
        propEnd,
        "Empty stream flags"
      );
      ctx.offset = propEnd;
      continue;
    }
    if (propertyType === EMPTY_FILES_PROPERTY_ID) {
      const emptyCount = emptyStreams?.filter(Boolean).length ?? fileCount;
      emptyFiles = expandEmptyStreamFlags(
        readBitVector(ctx, emptyCount, propEnd, "Empty file flags"),
        emptyStreams,
        fileCount
      );
      ctx.offset = propEnd;
      continue;
    }
    if (propertyType === ANTI_ITEMS_PROPERTY_ID) {
      const emptyCount = emptyStreams?.filter(Boolean).length ?? fileCount;
      antiItems = expandEmptyStreamFlags(
        readBitVector(ctx, emptyCount, propEnd, "Anti item flags"),
        emptyStreams,
        fileCount
      );
      ctx.offset = propEnd;
      continue;
    }
    if (propertyType === NAMES_PROPERTY_ID) {
      const parsedNames = parseNames(ctx, fileCount, propEnd);
      names = parsedNames.names;
      hasNames = !!names;
      ctx.offset = propEnd;
      continue;
    }
    if (propertyType === MODIFICATION_TIMES_PROPERTY_ID) {
      mTimes = parseTimes(ctx, fileCount, propEnd, "Modification time");
      hasModificationTimes = !!mTimes;
      ctx.offset = propEnd;
      continue;
    }
    if (propertyType === ATTRIBUTES_PROPERTY_ID) {
      attributes = parseAttributes(ctx, fileCount, propEnd);
      ctx.offset = propEnd;
      continue;
    }
    ctx.offset = propEnd;
  }
  for (let i = 0; i < fileCount; i += 1) {
    const file = files[i];
    if (!file) continue;
    const hasStream = emptyStreams ? !emptyStreams[i] : true;
    file.hasStream = hasStream;
    file.isEmptyStream = emptyStreams ? Boolean(emptyStreams[i]) : false;
    file.isEmptyFile = emptyFiles ? Boolean(emptyFiles[i]) : false;
    file.isAnti = antiItems ? Boolean(antiItems[i]) : false;
    file.name = names?.[i] ?? "(no name)";
    file.modifiedTime = mTimes?.[i] ?? null;
    const attr = attributes ? attributes[i] : null;
    if (attr != null) {
      file.attributes = toHex32(attr, 8);
      if ((attr & WINDOWS_DIRECTORY_ATTRIBUTE) !== 0) file.isDirectory = true;
    }
    if (file.isEmptyStream && file.isEmptyFile === false) {
      file.isDirectory = true;
    }
  }
  return {
    fileCount,
    files,
    hasNames,
    hasModificationTimes
  };
};
