"use strict";

import { formatUnixSecondsOrDash, toHex32 } from "../../binary-utils.js";

const SIGNATURE_BYTES = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const START_HEADER_SIZE = 32;
const UTF16_DECODER = new TextDecoder("utf-16le", { fatal: false });

const toSafeNumber = value => {
  if (typeof value === "number") return value;
  if (value <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
  return null;
};

const filetimeToIso = filetime => {
  if (typeof filetime !== "bigint") return null;
  const windowsEpochDiff = 11644473600n;
  const seconds = filetime / 10000000n - windowsEpochDiff;
  if (seconds < 0n || seconds > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return formatUnixSecondsOrDash(Number(seconds));
};

const readByte = (ctx, label) => {
  if (ctx.offset >= ctx.dv.byteLength) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    return null;
  }
  const value = ctx.dv.getUint8(ctx.offset);
  ctx.offset += 1;
  return value;
};

const readEncodedUint64 = (ctx, label) => {
  const firstByte = readByte(ctx, label);
  if (firstByte == null) return null;
  let mask = 0x80;
  let i = 0;
  for (; i < 8; i += 1) {
    if ((firstByte & mask) === 0) break;
    mask >>= 1;
  }
  let value = BigInt(firstByte & (mask - 1));
  if (i === 8) {
    value = 0n;
  }
  for (let j = 0; j < i; j += 1) {
    const next = readByte(ctx, label);
    if (next == null) return null;
    value = (value << 8n) | BigInt(next);
  }
  return value;
};

const readBoolVector = (ctx, count, endOffset, label) => {
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

const readUint64Le = (ctx, endOffset, label) => {
  if (ctx.offset + 8 > endOffset) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    ctx.offset = endOffset;
    return null;
  }
  const value = ctx.dv.getBigUint64(ctx.offset, true);
  ctx.offset += 8;
  return value;
};

const readUint32Le = (ctx, endOffset, label) => {
  if (ctx.offset + 4 > endOffset) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    ctx.offset = endOffset;
    return null;
  }
  const value = ctx.dv.getUint32(ctx.offset, true);
  ctx.offset += 4;
  return value;
};

const parseArchiveProperties = ctx => {
  const properties = [];
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

const parsePackDigests = (ctx, count, endOffset, label) => {
  const digests = [];
  const definedFlags = readBoolVector(ctx, count, endOffset, `${label} definition flags`);
  if (!definedFlags) return { digests };
  for (let i = 0; i < count; i += 1) {
    if (!definedFlags[i]) continue;
    const crc = readUint32Le(ctx, endOffset, `${label} CRC`);
    if (crc == null) break;
    digests.push({ index: i, crc });
  }
  return { digests, allDefined: definedFlags.every(Boolean) };
};

const parsePackInfo = ctx => {
  const packPos = readEncodedUint64(ctx, "Pack position");
  const numPackStreams = readEncodedUint64(ctx, "Pack stream count");
  const result = {
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

const parseFolder = (ctx, endOffset) => {
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
    if (hasAttributes) {
      const propSize = readEncodedUint64(ctx, "Coder property size");
      if (propSize != null) {
        propertiesSize = toSafeNumber(propSize) || 0;
        if (ctx.offset + propertiesSize > endOffset) {
          ctx.issues.push("Coder properties extend beyond available data.");
          ctx.offset = endOffset;
          break;
        }
        ctx.offset += propertiesSize;
      }
    }
    totalInStreams += inStreams;
    totalOutStreams += outStreams;
    coders.push({ methodId, inStreams, outStreams, propertiesSize });
  }
  const bindPairs = [];
  const numBindPairs = Math.max(totalOutStreams - 1, 0);
  for (let i = 0; i < numBindPairs; i += 1) {
    const inIndex = readEncodedUint64(ctx, "Bind pair input index");
    const outIndex = readEncodedUint64(ctx, "Bind pair output index");
    bindPairs.push({ inIndex, outIndex });
  }
  const numPackedStreams = Math.max(totalInStreams - numBindPairs, 0);
  const packedStreams = [];
  if (numPackedStreams > 1) {
    for (let i = 0; i < numPackedStreams; i += 1) {
      const index = readEncodedUint64(ctx, "Packed stream index");
      packedStreams.push(index);
    }
  }
  return { coders, totalInStreams, totalOutStreams, bindPairs, packedStreams };
};

const parseUnpackInfo = ctx => {
  const info = { folders: [] };
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
      const outStreams = folder?.totalOutStreams || 1;
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

const parseSubStreamsInfo = (ctx, folderCount) => {
  const info = {};
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
      const totalEntries = folderCount;
      for (let i = 0; i < totalEntries; i += 1) {
        const size = readEncodedUint64(ctx, "Substream size");
        info.substreamSizes.push(size);
      }
      continue;
    }
    if (id === 0x0a) {
      const digestInfo = parsePackDigests(
        ctx,
        folderCount,
        ctx.dv.byteLength,
        "Substream"
      );
      info.substreamCrcs = digestInfo.digests;
      continue;
    }
    ctx.issues.push(`Unknown SubStreamsInfo field id 0x${id.toString(16)}.`);
    break;
  }
  return info;
};

const parseStreamsInfo = ctx => {
  const info = {};
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

const parseTimes = (ctx, fileCount, endOffset, label) => {
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

const parseAttributes = (ctx, fileCount, endOffset) => {
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

const parseNames = (ctx, fileCount, endOffset) => {
  const external = readByte(ctx, "Name external flag");
  if (external == null) return { names: [] };
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

const parseFilesInfo = ctx => {
  const numFiles = readEncodedUint64(ctx, "File count");
  const fileCount = toSafeNumber(numFiles);
  if (fileCount == null) {
    return { fileCount: null, files: [] };
  }
  const files = new Array(fileCount).fill(null).map((_, index) => ({ index: index + 1 }));
  let emptyStreams = null;
  let emptyFiles = null;
  let antiItems = null;
  let names = null;
  let mTimes = null;
  let attributes = null;
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

const parseHeader = ctx => {
  const header = {};
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

const parseNextHeader = (dv, issues) => {
  if (!dv || dv.byteLength === 0) {
    issues.push("Next header is empty.");
    return { kind: "empty" };
  }
  const firstId = dv.getUint8(0);
  const ctx = { dv, offset: 1, issues };
  if (firstId === 0x01) {
    const sections = parseHeader(ctx);
    return { kind: "header", sections };
  }
  if (firstId === 0x17) {
    issues.push("Next header is encoded (often encrypted or compressed) and was not decoded.");
    return { kind: "encoded" };
  }
  issues.push(`Unexpected next header type 0x${firstId.toString(16)}.`);
  return { kind: "unknown", type: firstId };
};

const hasSignature = dv => {
  if (!dv || dv.byteLength < SIGNATURE_BYTES.length) return false;
  for (let i = 0; i < SIGNATURE_BYTES.length; i += 1) {
    if (dv.getUint8(i) !== SIGNATURE_BYTES[i]) return false;
  }
  return true;
};

export async function parseSevenZip(file) {
  const issues = [];
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
  const result = {
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
    nextHeader: null,
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
  let nextHeaderDv = null;
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
  if (parsedNextHeader.sections?.filesInfo?.fileCount === 0) {
    issues.push("No file entries were found in the archive header.");
  }
  return result;
}

export const isSevenZip = async file => {
  const dv = new DataView(await file.slice(0, START_HEADER_SIZE).arrayBuffer());
  return hasSignature(dv);
};

export const hasSevenZipSignature = dv => hasSignature(dv);
