"use strict";

import {
  type SevenZipContext,
  type SevenZipFolderCoderRecord,
  type SevenZipFolderParseResult,
  type SevenZipUnpackInfo
} from "./types.js";
import { parseCoderProperties } from "./coders.js";
import { parsePackDigests } from "./pack-info.js";
import { readByte, readEncodedUint64, toSafeNumber } from "./readers.js";

export const parseFolder = (
  ctx: SevenZipContext,
  endOffset: number
): SevenZipFolderParseResult => {
  const numCoders = readEncodedUint64(ctx, "Coder count");
  const numCodersNumber = toSafeNumber(numCoders) || 0;
  const coders: SevenZipFolderCoderRecord[] = [];
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
  const bindPairs: SevenZipFolderParseResult["bindPairs"] = [];
  const numBindPairs = Math.max(totalOutStreams - 1, 0);
  for (let i = 0; i < numBindPairs; i += 1) {
    const inIndex = readEncodedUint64(ctx, "Bind pair input index");
    const outIndex = readEncodedUint64(ctx, "Bind pair output index");
    bindPairs.push({ inIndex, outIndex });
  }
  const numPackedStreams = Math.max(totalInStreams - numBindPairs, 0);
  const numOutStreams = Math.max(totalOutStreams - numBindPairs, 0);
  const packedStreams: Array<bigint | null> = [];
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

export const parseUnpackInfo = (ctx: SevenZipContext): SevenZipUnpackInfo => {
  const info: SevenZipUnpackInfo = { folders: [], external: false };
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
      const sizes: Array<bigint | null> = [];
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
      info.folderCrcs = crcInfo;
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
