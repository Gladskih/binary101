"use strict";

import { type SevenZipArchiveProperties, type SevenZipContext, type SevenZipHeaderSections } from "./types.js";
import { readByte, readEncodedUint64, toSafeNumber } from "./readers.js";
import { parseStreamsInfo } from "./streams-info.js";
import { parseFilesInfo } from "./files-info.js";

export const parseArchiveProperties = (ctx: SevenZipContext): SevenZipArchiveProperties => {
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

export const parseHeader = (ctx: SevenZipContext): SevenZipHeaderSections => {
  const header: SevenZipHeaderSections = {};
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
