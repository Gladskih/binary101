/* eslint-disable max-lines */
"use strict";

import { formatUnixSecondsOrDash, toHex32 } from "../../binary-utils.js";

interface SevenZipContext {
  dv: DataView;
  offset: number;
  issues: string[];
  // Additional helpers may attach scratch properties; keep them flexible.
  [key: string]: unknown;
}

interface SevenZipCoder {
  id: string;
  methodId: string;
  numInStreams: number;
  numOutStreams: number;
  properties: unknown | null;
  archHint?: string;
  isEncryption: boolean;
}

interface SevenZipSubstream {
  size: bigint | null;
  crc: number | null;
}

export interface SevenZipFolderSummary {
  index: number;
  unpackSize: bigint | null;
  packedSize: bigint | null;
  coders: SevenZipCoder[];
  numUnpackStreams: number;
  substreams: SevenZipSubstream[];
  isEncrypted: boolean;
}

export interface SevenZipFileSummary {
  index: number;
  name: string;
  folderIndex: number | null;
  uncompressedSize: bigint | number | null;
  packedSize: bigint | number | null;
  compressionRatio: number | null;
  crc32: number | null;
  modifiedTime: string | null;
  attributes: string | null;
  hasStream?: boolean;
  isEmptyStream?: boolean;
  isEmptyFile?: boolean;
  isDirectory?: boolean;
  isAnti?: boolean;
  isEncrypted?: boolean;
  isEmpty?: boolean;
}

export interface SevenZipArchiveFlags {
  isSolid: boolean;
  isHeaderEncrypted: boolean;
  hasEncryptedContent: boolean;
}

export interface SevenZipStructure {
  archiveFlags: SevenZipArchiveFlags;
  folders: SevenZipFolderSummary[];
  files: SevenZipFileSummary[];
}

export interface SevenZipStartHeader {
  versionMajor: number;
  versionMinor: number;
  startHeaderCrc: number;
  nextHeaderOffset: bigint;
  nextHeaderSize: bigint;
  nextHeaderCrc: number;
  absoluteNextHeaderOffset: bigint;
}

export interface SevenZipParsedNextHeader {
  kind: string;
  sections?: unknown;
  headerStreams?: unknown;
  headerCoders?: SevenZipFolderSummary[];
  hasEncryptedHeader?: boolean;
  type?: number;
}

export interface SevenZipNextHeaderInfo {
  offset: bigint;
  size: bigint;
  crc: number;
  parsed: SevenZipParsedNextHeader;
}

export interface SevenZipHeaderEncoding {
  coders: SevenZipFolderSummary[];
  hasEncryptedHeader: boolean;
}

export interface SevenZipParseResult {
  is7z: boolean;
  startHeader?: SevenZipStartHeader;
  nextHeader?: SevenZipNextHeaderInfo;
  structure?: SevenZipStructure;
  headerEncoding?: SevenZipHeaderEncoding;
  issues: string[];
}

const SIGNATURE_BYTES = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const START_HEADER_SIZE = 32;
const UTF16_DECODER = new TextDecoder("utf-16le", { fatal: false });

const CODER_NAMES: Record<string, string> = {
  "00": "Copy",
  "03": "Delta",
  "030101": "LZMA",
  "21": "LZMA2",
  "03030103": "BCJ",
  "0303011b": "BCJ2",
  "04": "BZip2",
  "040108": "Deflate",
  "030401": "PPMd",
  "06f10701": "AES-256"
};

const CODER_ARCH_HINTS: Record<string, string> = {
  "03030103": "x86",
  "0303011b": "x86",
  "03030105": "IA-64",
  "03030106": "ARM",
  "03030107": "ARM-Thumb",
  "03030108": "PowerPC"
};

const toSafeNumber = (value: number | bigint | null | undefined): number | null => {
  if (typeof value === "number") return value;
  if (typeof value === "bigint") {
    if (value <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
    return null;
  }
  return null;
};

const normalizeMethodId = (id: string | null | undefined): string =>
  (id || "").toString().toLowerCase();

const describeCoderId = (id: string): string =>
  CODER_NAMES[normalizeMethodId(id)] || `0x${id}`;

const parseLzmaProps = (bytes: Uint8Array | null | undefined):
  | { dictSize: number; lc: number; lp: number; pb: number }
  | null => {
  if (!bytes || bytes.length < 5) return null;
  const first = bytes[0];
  const pb = Math.floor(first / 45);
  const remainder = first - pb * 45;
  const lp = Math.floor(remainder / 9);
  const lc = remainder - lp * 9;
  const dictSize =
    bytes[1] | (bytes[2] << 8) | (bytes[3] << 16) | (bytes[4] << 24);
  return { dictSize, lc, lp, pb };
};

const parseLzma2Props = (bytes: Uint8Array | null | undefined): { dictSize: number | null } | null => {
  if (!bytes || bytes.length < 1) return null;
  const prop = bytes[0];
  if (prop > 40) return { dictSize: null };
  const base = (prop & 1) + 2;
  const dictSize = base << (Math.floor(prop / 2) + 11);
  return { dictSize };
};

const parseDeltaProps = (bytes: Uint8Array | null | undefined): { distance: number } | null => {
  if (!bytes || bytes.length < 1) return null;
  const distance = bytes[0] + 1;
  return { distance };
};

const parseBcjProps = (
  id: string,
  bytes: Uint8Array | null | undefined
): { filterType?: string; startOffset?: number } | null => {
  const arch = CODER_ARCH_HINTS[normalizeMethodId(id)];
  if (!bytes || !bytes.length) return arch ? { filterType: arch } : null;
  if (bytes.length >= 4) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const startOffset = view.getInt32(0, true);
    return arch ? { filterType: arch, startOffset } : { startOffset };
  }
  return arch ? { filterType: arch } : null;
};

const parseCoderProperties = (
  methodId: string,
  bytes: Uint8Array | null | undefined
): unknown => {
  const normalized = normalizeMethodId(methodId);
  if (normalized === "030101") return parseLzmaProps(bytes);
  if (normalized === "21") return parseLzma2Props(bytes);
  if (normalized === "03") return parseDeltaProps(bytes);
  if (normalized.startsWith("030301")) return parseBcjProps(methodId, bytes);
  return null;
};

const filetimeToIso = (filetime: bigint | null | undefined): string | null => {
  if (typeof filetime !== "bigint") return null;
  const windowsEpochDiff = 11644473600n;
  const seconds = filetime / 10000000n - windowsEpochDiff;
  if (seconds < 0n || seconds > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return formatUnixSecondsOrDash(Number(seconds));
};

const readByte = (ctx: SevenZipContext, label?: string): number | null => {
  if (ctx.offset >= ctx.dv.byteLength) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    return null;
  }
  const value = ctx.dv.getUint8(ctx.offset);
  ctx.offset += 1;
  return value;
};

const readEncodedUint64 = (ctx: SevenZipContext, label?: string): bigint | null => {
  const firstByte = readByte(ctx, label);
  if (firstByte == null) return null;
  let mask = 0x80;
  let extraBytes = 0;
  for (; extraBytes < 8; extraBytes += 1) {
    if ((firstByte & mask) === 0) break;
    mask >>= 1;
  }
  const highBits = firstByte & (mask - 1);
  let value = BigInt(highBits);
  if (extraBytes === 8) {
    value = 0n;
  }
  let low = 0n;
  for (let i = 0; i < extraBytes; i += 1) {
    const next = readByte(ctx, label);
    if (next == null) return null;
    low |= BigInt(next) << BigInt(8 * i);
  }
  if (extraBytes > 0) {
    value = (value << BigInt(8 * extraBytes)) + low;
  }
  return value;
};

const readBoolVector = (
  ctx: SevenZipContext,
  count: number,
  endOffset: number,
  label?: string
): boolean[] | null => {
  if (ctx.offset >= endOffset) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    return null;
  }
  const allDefined = readByte(ctx, label);
  if (allDefined == null) return null;
  const values = new Array(count).fill(false);
  if (allDefined !== 0) {
    values.fill(true);
    return values;
  }
  const numBytes = Math.ceil(count / 8);
  if (ctx.offset + numBytes > endOffset) {
    ctx.issues.push(`${label || "Bit vector"} extends beyond the available data.`);
    ctx.offset = endOffset;
    return values;
  }
  for (let i = 0; i < count; i += 1) {
    const byteIndex = Math.floor(i / 8);
    const bitIndex = i & 7;
    const bit = ctx.dv.getUint8(ctx.offset + byteIndex) & (1 << bitIndex);
    values[i] = bit !== 0;
  }
  ctx.offset += numBytes;
  return values;
};

const readUint64Le = (
  ctx: SevenZipContext,
  endOffset: number,
  label?: string
): bigint | null => {
  if (ctx.offset + 8 > endOffset) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    ctx.offset = endOffset;
    return null;
  }
  const value = ctx.dv.getBigUint64(ctx.offset, true);
  ctx.offset += 8;
  return value;
};

const readUint32Le = (
  ctx: SevenZipContext,
  endOffset: number,
  label?: string
): number | null => {
  if (ctx.offset + 4 > endOffset) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    ctx.offset = endOffset;
    return null;
  }
  const value = ctx.dv.getUint32(ctx.offset, true);
  ctx.offset += 4;
  return value;
};

const parseArchiveProperties = (ctx: SevenZipContext): { count: number } => {
  const properties: Array<{ id: number; size: number }> = [];
  while (ctx.offset < ctx.dv.byteLength) {
    const propertyType = readByte(ctx, "Archive property id");
    if (propertyType == null) break;
    if (propertyType === 0x00) break;
    const size = readEncodedUint64(ctx, "Archive property size");
    if (size == null) break;
    const sizeNumber = toSafeNumber(size);
    if (sizeNumber == null || ctx.offset + sizeNumber > ctx.dv.byteLength) {
      ctx.issues.push("Archive property size exceeds available data.");
      ctx.offset = ctx.dv.byteLength;
      break;
    }
    properties.push({ id: propertyType, size: sizeNumber });
    ctx.offset += sizeNumber;
  }
  return { count: properties.length };
};

const parsePackDigests = (
  ctx: SevenZipContext,
  count: number,
  endOffset: number,
  label: string
): {
  digests: Array<{ index: number; crc: number }>;
  allDefined?: boolean;
  definedFlags?: boolean[];
} => {
  const digests: Array<{ index: number; crc: number }> = [];
  const definedFlags = readBoolVector(ctx, count, endOffset, `${label} definition flags`);
  if (!definedFlags) return { digests };
  for (let i = 0; i < count; i += 1) {
    if (!definedFlags[i]) continue;
    const crc = readUint32Le(ctx, endOffset, `${label} CRC`);
    if (crc == null) break;
    digests.push({ index: i, crc });
  }
  return { digests, allDefined: definedFlags.every(Boolean), definedFlags };
};

const parsePackInfo = (ctx: SevenZipContext): {
  packPos: bigint | null;
  numPackStreams: bigint | null;
  packSizes: bigint[];
  packCrcs: Array<{ index: number; crc: number }>;
} => {
  const packPos = readEncodedUint64(ctx, "Pack position");
  const numPackStreams = readEncodedUint64(ctx, "Pack stream count");
  const result: {
    packPos: bigint | null;
    numPackStreams: bigint | null;
    packSizes: bigint[];
    packCrcs: Array<{ index: number; crc: number }>;
  } = {
    packPos,
    numPackStreams,
    packSizes: [],
    packCrcs: []
  };
  const countNumber = toSafeNumber(numPackStreams);
  if (packPos == null || numPackStreams == null || countNumber == null) return result;
  let done = false;
  while (ctx.offset < ctx.dv.byteLength && !done) {
    const id = readByte(ctx, "Pack info field id");
    if (id == null) break;
    if (id === 0x00) {
      done = true;
      break;
    }
    if (id === 0x09) {
      for (let i = 0; i < countNumber; i += 1) {
        const size = readEncodedUint64(ctx, "Pack stream size");
        if (size == null) break;
        result.packSizes.push(size);
      }
      continue;
    }
    if (id === 0x0a) {
      const digestInfo = parsePackDigests(
        ctx,
        countNumber,
        ctx.dv.byteLength,
        "Pack stream"
      );
      result.packCrcs = digestInfo.digests;
      continue;
    }
    ctx.issues.push(`Unknown PackInfo field id 0x${id.toString(16)}.`);
    break;
  }
  return result;
};

const parseFolder = (
  ctx: SevenZipContext,
  endOffset: number
): {
  coders: any[];
  totalInStreams: number;
  totalOutStreams: number;
  bindPairs: Array<{ inIndex: bigint | null; outIndex: bigint | null }>;
  packedStreams: Array<bigint | null>;
  numPackedStreams: number;
  numBindPairs: number;
  numOutStreams: number;
} => {
  const numCoders = readEncodedUint64(ctx, "Coder count");
  const numCodersNumber = toSafeNumber(numCoders) || 0;
  const coders = [];
  let totalInStreams = 0;
  let totalOutStreams = 0;
  for (let i = 0; i < numCodersNumber; i += 1) {
    const flags = readByte(ctx, "Coder flags");
    if (flags == null) break;
    const idSize = flags & 0x0f;
    const isSimple = (flags & 0x10) === 0;
    const hasAttributes = (flags & 0x20) !== 0;
    if (idSize === 0 || ctx.offset + idSize > endOffset) {
      ctx.issues.push("Coder ID is truncated.");
      ctx.offset = endOffset;
      break;
    }
    const methodBytes = new Uint8Array(ctx.dv.buffer, ctx.dv.byteOffset + ctx.offset, idSize);
    const methodId = Array.from(methodBytes)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
    ctx.offset += idSize;
    let inStreams = 1;
    let outStreams = 1;
    if (!isSimple) {
      const inVal = readEncodedUint64(ctx, "Coder input count");
      const outVal = readEncodedUint64(ctx, "Coder output count");
      if (inVal != null) inStreams = toSafeNumber(inVal) || 0;
      if (outVal != null) outStreams = toSafeNumber(outVal) || 0;
    }
    let propertiesSize = 0;
    let properties = null;
    if (hasAttributes) {
      const propSize = readEncodedUint64(ctx, "Coder property size");
      if (propSize != null) {
        propertiesSize = toSafeNumber(propSize) || 0;
        if (ctx.offset + propertiesSize > endOffset) {
          ctx.issues.push("Coder properties extend beyond available data.");
          ctx.offset = endOffset;
          break;
        }
        const bytes = new Uint8Array(
          ctx.dv.buffer,
          ctx.dv.byteOffset + ctx.offset,
          propertiesSize
        );
        properties = parseCoderProperties(methodId, bytes);
        ctx.offset += propertiesSize;
      }
    }
    totalInStreams += inStreams;
    totalOutStreams += outStreams;
    coders.push({ methodId, inStreams, outStreams, propertiesSize, properties });
  }
  const bindPairs = [];
  const numBindPairs = Math.max(totalOutStreams - 1, 0);
  for (let i = 0; i < numBindPairs; i += 1) {
    const inIndex = readEncodedUint64(ctx, "Bind pair input index");
    const outIndex = readEncodedUint64(ctx, "Bind pair output index");
    bindPairs.push({ inIndex, outIndex });
  }
  const numPackedStreams = Math.max(totalInStreams - numBindPairs, 0);
  const numOutStreams = Math.max(totalOutStreams - numBindPairs, 0);
  const packedStreams = [];
  if (numPackedStreams > 1) {
    for (let i = 0; i < numPackedStreams; i += 1) {
      const index = readEncodedUint64(ctx, "Packed stream index");
      packedStreams.push(index);
    }
  }
  return {
    coders,
    totalInStreams,
    totalOutStreams,
    bindPairs,
    packedStreams,
    numPackedStreams,
    numBindPairs,
    numOutStreams
  };
};

const parseUnpackInfo = (ctx: SevenZipContext): any => {
  const info: any = { folders: [] };
  const folderId = readByte(ctx, "UnpackInfo section id");
  if (folderId == null) return info;
  if (folderId !== 0x0b) {
    ctx.issues.push("Unexpected UnpackInfo structure; skipping.");
    return info;
  }
  const numFolders = readEncodedUint64(ctx, "Folder count");
  const numFoldersNumber = toSafeNumber(numFolders) || 0;
  const external = readByte(ctx, "Folder external flag");
  if (external == null) return info;
  info.external = external !== 0;
  const sectionEnd = ctx.dv.byteLength;
  if (!info.external) {
    for (let i = 0; i < numFoldersNumber; i += 1) {
      if (ctx.offset >= sectionEnd) break;
      const folder = parseFolder(ctx, sectionEnd);
      info.folders.push(folder);
    }
  }
  const sizesId = readByte(ctx, "Unpack sizes id");
  if (sizesId === 0x0c) {
    info.unpackSizes = [];
    for (let i = 0; i < numFoldersNumber; i += 1) {
      const folder = info.folders[i];
      const outStreams = folder?.numOutStreams || 1;
      const sizes = [];
      for (let j = 0; j < outStreams; j += 1) {
        const size = readEncodedUint64(ctx, "Unpack size");
        sizes.push(size);
      }
      info.unpackSizes.push(sizes);
    }
  } else if (sizesId != null) {
    ctx.offset -= 1;
  }
  if (ctx.offset < ctx.dv.byteLength) {
    const crcMarker = readByte(ctx, "UnpackInfo CRC marker");
    if (crcMarker === 0x0a) {
      const crcInfo = parsePackDigests(
        ctx,
        numFoldersNumber,
        ctx.dv.byteLength,
        "Folder"
      );
      info.folderCrcs = crcInfo.digests;
    } else if (crcMarker != null) {
      ctx.offset -= 1;
    }
  }
  const endMarker = readByte(ctx, "UnpackInfo end marker");
  if (endMarker !== 0x00) {
    ctx.issues.push("UnpackInfo did not terminate cleanly.");
  }
  return info;
};

const parseSubStreamsInfo = (ctx: SevenZipContext, folderCount: number): any => {
  const info: any = { numUnpackStreams: new Array(folderCount).fill(1) };
  let done = false;
  while (ctx.offset < ctx.dv.byteLength && !done) {
    const id = readByte(ctx, "SubStreamsInfo field id");
    if (id == null) break;
    if (id === 0x00) {
      done = true;
      break;
    }
    if (id === 0x0d) {
      info.numUnpackStreams = [];
      for (let i = 0; i < folderCount; i += 1) {
        const value = readEncodedUint64(ctx, "Unpack stream count");
        info.numUnpackStreams.push(value);
      }
      continue;
    }
    if (id === 0x09) {
      info.substreamSizes = [];
      const totalEntries = (info.numUnpackStreams as Array<bigint | number | null | undefined>).reduce(
        (sum: number, value: bigint | number | null | undefined) => {
          const count = toSafeNumber(value) ?? 1;
          return sum + Math.max(count - 1, 0);
        },
        0
      );
      for (let i = 0; i < totalEntries; i += 1) {
        const size = readEncodedUint64(ctx, "Substream size");
        info.substreamSizes.push(size);
      }
      continue;
    }
    if (id === 0x0a) {
      const totalStreams = (info.numUnpackStreams as Array<bigint | number | null | undefined>).reduce(
        (sum: number, value: bigint | number | null | undefined) => {
          const count = toSafeNumber(value) ?? 1;
          return sum + count;
        },
        0
      );
      const digestInfo = parsePackDigests(
        ctx,
        totalStreams,
        ctx.dv.byteLength,
        "Substream"
      );
      info.substreamCrcs = digestInfo;
      continue;
    }
    ctx.issues.push(`Unknown SubStreamsInfo field id 0x${id.toString(16)}.`);
    break;
  }
  return info;
};

const parseStreamsInfo = (ctx: SevenZipContext): any => {
  const info: any = {};
  let done = false;
  while (ctx.offset < ctx.dv.byteLength && !done) {
    const id = readByte(ctx, "StreamsInfo field id");
    if (id == null) break;
    if (id === 0x00) {
      done = true;
      break;
    }
    if (id === 0x06) {
      info.packInfo = parsePackInfo(ctx);
      continue;
    }
    if (id === 0x07) {
      info.unpackInfo = parseUnpackInfo(ctx);
      continue;
    }
    if (id === 0x08) {
      const folderCount =
        toSafeNumber(info.unpackInfo?.folders?.length || 0) || 0;
      info.subStreamsInfo = parseSubStreamsInfo(ctx, folderCount);
      continue;
    }
    ctx.issues.push(`Unknown StreamsInfo field id 0x${id.toString(16)}.`);
    break;
  }
  return info;
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

const parseFilesInfo = (ctx: SevenZipContext): any => {
  const numFiles = readEncodedUint64(ctx, "File count");
  const fileCount = toSafeNumber(numFiles);
  if (fileCount == null) {
    return { fileCount: null, files: [] };
  }
  const files: any[] = new Array(fileCount).fill(null).map((_, index) => ({ index: index + 1 }));
  let emptyStreams: boolean[] | null = null;
  let emptyFiles: boolean[] | null = null;
  let antiItems: boolean[] | null = null;
  let names: string[] | null = null;
  let mTimes: Array<string | null> | null = null;
  let attributes: Array<number | null> | null = null;
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
      ctx.offset = propEnd;
      continue;
    }
    if (propertyType === 0x14) {
      mTimes = parseTimes(ctx, fileCount, propEnd, "Modification time");
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
    const hasStream = emptyStreams ? !emptyStreams[i] : true;
    file.hasStream = hasStream;
    file.isEmptyStream = emptyStreams ? emptyStreams[i] : false;
    file.isEmptyFile = emptyFiles ? emptyFiles[i] : false;
    file.isAnti = antiItems ? antiItems[i] : false;
    file.name = names && names[i] ? names[i] : "(no name)";
    file.modifiedTime = mTimes ? mTimes[i] : null;
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
    hasNames: !!names,
    hasModificationTimes: !!mTimes
  };
};

const parseHeader = (ctx: SevenZipContext): any => {
  const header: any = {};
  while (ctx.offset < ctx.dv.byteLength) {
    const sectionId = readByte(ctx, "Header section id");
    if (sectionId == null) break;
    if (sectionId === 0x00) break;
    if (sectionId === 0x02) {
      header.archiveProperties = parseArchiveProperties(ctx);
      continue;
    }
    if (sectionId === 0x03) {
      header.additionalStreamsInfo = parseStreamsInfo(ctx);
      continue;
    }
    if (sectionId === 0x04) {
      header.mainStreamsInfo = parseStreamsInfo(ctx);
      continue;
    }
    if (sectionId === 0x05) {
      header.filesInfo = parseFilesInfo(ctx);
      continue;
    }
    if (sectionId === 0x17) {
      ctx.issues.push("Header references an encoded header; decoding not implemented.");
      break;
    }
    ctx.issues.push(`Unknown header section id 0x${sectionId.toString(16)}.`);
    break;
  }
  return header;
};

const sumBigIntArray = (values: Array<bigint | number | null | undefined>): bigint =>
  values.reduce<bigint>(
    (total: bigint, value: bigint | number | null | undefined) =>
      total + (typeof value === "bigint" ? value : 0n),
    0n
  );

const buildFolderDetails = (sections: any, issues: string[]): { folders: SevenZipFolderSummary[] } => {
  const mainStreams = sections?.mainStreamsInfo;
  const unpackInfo = mainStreams?.unpackInfo;
  const packInfo = mainStreams?.packInfo;
  if (!unpackInfo?.folders?.length) return { folders: [] };
  const folderCount = unpackInfo.folders.length;
  const numUnpackStreams =
    mainStreams?.subStreamsInfo?.numUnpackStreams || new Array(folderCount).fill(1);
  const substreamSizes = mainStreams?.subStreamsInfo?.substreamSizes || [];
  const substreamCrcs = mainStreams?.subStreamsInfo?.substreamCrcs;
  const crcDefined = substreamCrcs?.definedFlags || [];
  const crcMap = new Map((substreamCrcs?.digests || []).map((d: any) => [d.index, d.crc]));
  const packSizes = packInfo?.packSizes || [];
  const folders: SevenZipFolderSummary[] = [];
  let packCursor = 0;
  let substreamSizeCursor = 0;
  let crcCursor = 0;
  for (let i = 0; i < folderCount; i += 1) {
    const folder = unpackInfo.folders[i];
    const unpackStreams = toSafeNumber(numUnpackStreams[i]) ?? 1;
    const unpackSizes = unpackInfo.unpackSizes?.[i] || [];
    const unpackSize = unpackSizes.length ? sumBigIntArray(unpackSizes) : null;
    const packedStreams = Math.max(folder.numPackedStreams || 0, 0);
    const packedSizes = [];
    for (let j = 0; j < packedStreams; j += 1) {
      if (packCursor >= packSizes.length) break;
      packedSizes.push(packSizes[packCursor]);
      packCursor += 1;
    }
    const packedSize = packedSizes.length ? sumBigIntArray(packedSizes) : null;
    const substreams: SevenZipSubstream[] = [];
    let consumed = 0n;
    for (let s = 0; s < unpackStreams; s += 1) {
      let size = null;
      if (unpackStreams === 1) {
        size = unpackSize ?? unpackSizes[0] ?? null;
      } else if (s < unpackStreams - 1) {
        size = substreamSizes[substreamSizeCursor] ?? null;
        substreamSizeCursor += 1;
      } else if (typeof unpackSize === "bigint") {
        size = unpackSize - consumed;
      }
      if (typeof size === "number") size = BigInt(size);
      if (typeof size === "bigint") consumed += size;
      const crcFlag = crcDefined[crcCursor];
      let crc: number | null = null;
      if (crcFlag) {
        const value = crcMap.get(crcCursor);
        crc = typeof value === "number" ? value : null;
      }
      crcCursor += 1;
      substreams.push({ size: size as bigint | null, crc });
    }
    const folderUnpackSize =
      substreams.some(sub => typeof sub.size === "bigint")
        ? sumBigIntArray(substreams.map(sub => sub.size || 0n))
        : unpackSize;
    const coders: SevenZipCoder[] = (folder.coders || []).map((coder: any) => {
      const normalized = normalizeMethodId(coder.methodId);
      const id = describeCoderId(normalized);
      const archHint = CODER_ARCH_HINTS[normalized];
      const isEncryption = normalized === "06f10701";
      return {
        id,
        methodId: coder.methodId,
        numInStreams: coder.inStreams,
        numOutStreams: coder.outStreams,
        properties: coder.properties || null,
        archHint,
        isEncryption
      };
    });
    const isEncrypted = coders.some(coder => coder.isEncryption);
    const folderSummary: SevenZipFolderSummary = {
      index: i,
      unpackSize: folderUnpackSize,
      packedSize,
      coders,
      numUnpackStreams: unpackStreams,
      substreams,
      isEncrypted
    };
    folders.push(folderSummary);
  }
  if (substreamSizeCursor < substreamSizes.length) {
    issues.push("Extra substream size entries were not matched to folders.");
  }
  return { folders };
};

const buildFileDetails = (
  sections: any,
  folders: SevenZipFolderSummary[],
  issues: string[]
): { files: SevenZipFileSummary[] } => {
  const files: SevenZipFileSummary[] = (sections?.filesInfo?.files || []).map((file: any) => ({ ...file }));
  if (!files.length) return { files };
  const filesWithStreams = files.filter(file => file.hasStream !== false);
  let fileStreamIndex = 0;
  folders.forEach(folder => {
    folder.substreams.forEach(sub => {
      const file = filesWithStreams[fileStreamIndex];
      if (!file) return;
      file.folderIndex = folder.index;
      file.uncompressedSize = sub.size ?? folder.unpackSize ?? null;
      const packedSize = folder.numUnpackStreams === 1 ? folder.packedSize : null;
      file.packedSize = packedSize;
      const uncompNum =
        typeof file.uncompressedSize === "bigint"
          ? toSafeNumber(file.uncompressedSize)
          : file.uncompressedSize;
      const packedNum = typeof packedSize === "bigint" ? toSafeNumber(packedSize) : packedSize;
      const ratio =
        packedNum != null && uncompNum != null && uncompNum > 0
          ? (packedNum / uncompNum) * 100
          : null;
      file.compressionRatio = Number.isFinite(ratio) ? ratio : null;
      file.crc32 = sub.crc ?? null;
      file.isEncrypted = folder.isEncrypted;
      file.isDirectory = Boolean(file.isDirectory);
      file.isEmpty =
        (uncompNum === 0 || file.uncompressedSize === 0n) && file.isDirectory !== true;
      fileStreamIndex += 1;
    });
  });
  if (fileStreamIndex < filesWithStreams.length) {
    issues.push("Some file streams were not matched to folders.");
  }
  files.forEach(file => {
    if (file.folderIndex == null) file.folderIndex = null;
    if (file.uncompressedSize == null) file.uncompressedSize = null;
    if (file.packedSize == null) file.packedSize = null;
    if (file.compressionRatio == null) file.compressionRatio = null;
    if (file.crc32 == null) file.crc32 = null;
    if (file.isEncrypted == null) file.isEncrypted = false;
    if (file.isEmpty == null) {
      const uncompNum =
        typeof file.uncompressedSize === "bigint"
          ? toSafeNumber(file.uncompressedSize)
          : file.uncompressedSize;
      file.isEmpty = (uncompNum === 0 || file.uncompressedSize === 0n) && !file.isDirectory;
    }
  });
  return { files };
};

const deriveStructure = (
  parsed: SevenZipParsedNextHeader,
  issues: string[]
): SevenZipStructure | null => {
  if (!parsed?.sections) return null;
  const folderDetails = buildFolderDetails(parsed.sections, issues);
  const fileDetails = buildFileDetails(parsed.sections, folderDetails.folders, issues);
  const filesWithStreams = fileDetails.files.filter(file => file.hasStream !== false);
  const archiveFlags = {
    isSolid:
      folderDetails.folders.some(folder => folder.numUnpackStreams > 1) ||
      filesWithStreams.length > folderDetails.folders.length,
    isHeaderEncrypted: parsed.kind === "encoded",
    hasEncryptedContent: folderDetails.folders.some(folder => folder.isEncrypted)
  };
  return {
    archiveFlags,
    folders: folderDetails.folders,
    files: fileDetails.files
  };
};

const parseNextHeader = (dv: DataView | null, issues: string[]): SevenZipParsedNextHeader => {
  if (!dv || dv.byteLength === 0) {
    issues.push("Next header is empty.");
    return { kind: "empty" };
  }
  const firstId = dv.getUint8(0);
  const ctx: SevenZipContext = { dv, offset: 1, issues };
  if (firstId === 0x01) {
    const sections = parseHeader(ctx);
    return { kind: "header", sections };
  }
  if (firstId === 0x17) {
    const streams = parseStreamsInfo(ctx);
    const unpackInfo = streams.unpackInfo;
    const folders =
      unpackInfo?.folders?.map((folder: any, index: number) => {
        const coders = (folder.coders || []).map((coder: any) => {
          const normalized = normalizeMethodId(coder.methodId);
          const id = describeCoderId(normalized);
          const archHint = CODER_ARCH_HINTS[normalized];
          const isEncryption = normalized === "06f10701";
          return {
            id,
            methodId: coder.methodId,
            numInStreams: coder.inStreams,
            numOutStreams: coder.outStreams,
            properties: coder.properties || null,
            archHint,
            isEncryption
          };
        });
        const isEncrypted = coders.some((coder: SevenZipCoder) => coder.isEncryption);
        return {
          index,
          coders,
          isEncrypted
        };
      }) || [];
    const hasEncryptedHeader = folders.some((folder: SevenZipFolderSummary) => folder.isEncrypted);
    return {
      kind: "encoded",
      headerStreams: streams,
      headerCoders: folders,
      hasEncryptedHeader
    };
  }
  issues.push(`Unexpected next header type 0x${firstId.toString(16)}.`);
  return { kind: "unknown", type: firstId };
};

const hasSignature = (dv: DataView | null): boolean => {
  if (!dv || dv.byteLength < SIGNATURE_BYTES.length) return false;
  for (let i = 0; i < SIGNATURE_BYTES.length; i += 1) {
    if (dv.getUint8(i) !== SIGNATURE_BYTES[i]) return false;
  }
  return true;
};

export async function parseSevenZip(file: File): Promise<SevenZipParseResult> {
  const issues: string[] = [];
  const startHeaderBuffer = await file.slice(0, START_HEADER_SIZE).arrayBuffer();
  const startHeader = new DataView(startHeaderBuffer);
  if (startHeader.byteLength < START_HEADER_SIZE || !hasSignature(startHeader)) {
    return { is7z: false, issues };
  }
  const versionMajor = startHeader.getUint8(6);
  const versionMinor = startHeader.getUint8(7);
  const startHeaderCrc = startHeader.getUint32(8, true);
  const nextHeaderOffset = startHeader.getBigUint64(12, true);
  const nextHeaderSize = startHeader.getBigUint64(20, true);
  const nextHeaderCrc = startHeader.getUint32(28, true);
  const absoluteNextHeaderOffset = 32n + nextHeaderOffset;
  const sizeNumber = toSafeNumber(nextHeaderSize);
  const offsetNumber = toSafeNumber(absoluteNextHeaderOffset);
  const result: SevenZipParseResult = {
    is7z: true,
    startHeader: {
      versionMajor,
      versionMinor,
      startHeaderCrc,
      nextHeaderOffset,
      nextHeaderSize,
      nextHeaderCrc,
      absoluteNextHeaderOffset
    },
    nextHeader: undefined,
    issues
  };
  if (offsetNumber == null || sizeNumber == null) {
    issues.push("Next header offset or size exceeds supported range.");
    return result;
  }
  const fileSize = file.size || 0;
  if (absoluteNextHeaderOffset + nextHeaderSize > BigInt(fileSize)) {
    issues.push("Next header lies outside the file bounds.");
    return result;
  }
  let nextHeaderDv: DataView | null = null;
  if (sizeNumber > 0) {
    const buffer = await file
      .slice(offsetNumber, offsetNumber + sizeNumber)
      .arrayBuffer();
    nextHeaderDv = new DataView(buffer);
  }
  const parsedNextHeader = parseNextHeader(nextHeaderDv, issues);
  result.nextHeader = {
    offset: absoluteNextHeaderOffset,
    size: nextHeaderSize,
    crc: nextHeaderCrc,
    parsed: parsedNextHeader
  };
  const sections: any = parsedNextHeader.sections as any;
  if (sections?.filesInfo?.fileCount === 0) {
    issues.push("No file entries were found in the archive header.");
  }
  const structure = deriveStructure(parsedNextHeader, issues);
  if (structure) {
    result.structure = structure;
    if (sections?.filesInfo) {
      sections.filesInfo.files = structure.files;
    }
  }
  if (parsedNextHeader.kind === "encoded") {
    result.headerEncoding = {
      coders: parsedNextHeader.headerCoders || [],
      hasEncryptedHeader: parsedNextHeader.hasEncryptedHeader || false
    };
  }
  return result;
}

export const isSevenZip = async (file: File): Promise<boolean> => {
  const dv = new DataView(await file.slice(0, START_HEADER_SIZE).arrayBuffer());
  return hasSignature(dv);
};

export const hasSevenZipSignature = (dv: DataView): boolean => hasSignature(dv);
