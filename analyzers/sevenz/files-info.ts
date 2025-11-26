"use strict";

import { formatUnixSecondsOrDash, toHex32 } from "../../binary-utils.js";
import {
  type SevenZipContext,
  type SevenZipFileInfoEntry,
  type SevenZipFilesInfo
} from "./types.js";
import {
  readBoolVector,
  readByte,
  readEncodedUint64,
  readUint32Le,
  readUint64Le,
  toSafeNumber
} from "./readers.js";

const UTF16_DECODER = new TextDecoder("utf-16le", { fatal: false });

const filetimeToIso = (filetime: bigint | null | undefined): string | null => {
  if (typeof filetime !== "bigint") return null;
  const windowsEpochDiff = 11644473600n;
  const seconds = filetime / 10000000n - windowsEpochDiff;
  if (seconds < 0n || seconds > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return formatUnixSecondsOrDash(Number(seconds));
};

const parseTimes = (
  ctx: SevenZipContext,
  fileCount: number,
  endOffset: number,
  label: string
): Array<string | null> | null => {
  const external = readByte(ctx, `${label} external flag`);
  if (external == null) return null;
  if (external !== 0) {
    ctx.issues.push(`${label} stored externally; skipping.`);
    ctx.offset = endOffset;
    return null;
  }
  const defined = readBoolVector(ctx, fileCount, endOffset, `${label} defined flags`);
  if (!defined) return null;
  const times = new Array(fileCount).fill(null);
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
  const external = readByte(ctx, "Attribute external flag");
  if (external == null) return null;
  if (external !== 0) {
    ctx.issues.push("File attributes stored externally; skipping.");
    ctx.offset = endOffset;
    return null;
  }
  const defined = readBoolVector(ctx, fileCount, endOffset, "Attribute defined flags");
  if (!defined) return null;
  const attributes = new Array(fileCount).fill(null);
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
  const names = new Array(fileCount).fill("(no name)");
  for (let i = 0; i < fileCount && i < parts.length; i += 1) {
    if (parts[i]) names[i] = parts[i];
  }
  ctx.offset = endOffset;
  return { names, external: false };
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
    if (propertyType === 0x00) break;
    const propertySize = readEncodedUint64(ctx, "File property size");
    const sizeNumber = propertySize != null ? toSafeNumber(propertySize) : null;
    if (sizeNumber == null || ctx.offset + sizeNumber > ctx.dv.byteLength) {
      ctx.issues.push("File property size exceeds available data.");
      ctx.offset = ctx.dv.byteLength;
      break;
    }
    const propEnd = ctx.offset + sizeNumber;
    if (propertyType === 0x0e) {
      emptyStreams = readBoolVector(
        ctx,
        fileCount,
        propEnd,
        "Empty stream flags"
      );
      ctx.offset = propEnd;
      continue;
    }
    if (propertyType === 0x0f) {
      emptyFiles = readBoolVector(ctx, fileCount, propEnd, "Empty file flags");
      ctx.offset = propEnd;
      continue;
    }
    if (propertyType === 0x10) {
      antiItems = readBoolVector(ctx, fileCount, propEnd, "Anti item flags");
      ctx.offset = propEnd;
      continue;
    }
    if (propertyType === 0x11) {
      const parsedNames = parseNames(ctx, fileCount, propEnd);
      names = parsedNames.names;
      hasNames = !!names;
      ctx.offset = propEnd;
      continue;
    }
    if (propertyType === 0x14) {
      mTimes = parseTimes(ctx, fileCount, propEnd, "Modification time");
      hasModificationTimes = !!mTimes;
      ctx.offset = propEnd;
      continue;
    }
    if (propertyType === 0x15) {
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
      if ((attr & 0x10) !== 0) file.isDirectory = true;
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
