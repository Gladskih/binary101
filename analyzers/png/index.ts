"use strict";

import type {
  PngChunk,
  PngIccProfile,
  PngIhdr,
  PngParseResult,
  PngPhysicalInfo,
  PngTextChunk
} from "./types.js";
import {
  parseGamma,
  parseIcc,
  parseIhdr,
  parsePhys,
  parseTextChunk,
  parseTransparency,
  readChunkHeader,
  readChunkType
} from "./chunk-parsers.js";

const PNG_SIG0 = 0x89504e47;
const PNG_SIG1 = 0x0d0a1a0a;
const MAX_CHUNKS = 4096;

export async function parsePng(file: File): Promise<PngParseResult | null> {
  const buffer = await file.arrayBuffer();
  const dv = new DataView(buffer);
  const size = dv.byteLength;
  if (size < 8) return null;
  if (dv.getUint32(0, false) !== PNG_SIG0 || dv.getUint32(4, false) !== PNG_SIG1) {
    return null;
  }

  const chunks: PngChunk[] = [];
  const issues: string[] = [];
  const texts: PngTextChunk[] = [];
  let offset = 8;
  let chunkCount = 0;
  let ihdr: PngIhdr | null = null;
  let firstChunkType: string | null = null;
  let paletteEntries = 0;
  let hasTransparency = false;
  let gamma: number | null = null;
  let iccProfile: PngIccProfile | null = null;
  let physical: PngPhysicalInfo | null = null;
  let idatChunks = 0;
  let idatSize = 0;
  let sawIend = false;

  while (offset + 8 <= size && chunkCount < MAX_CHUNKS) {
    const header = readChunkHeader(dv, offset);
    if (!header) break;
    const { length } = header;
    const typeString = readChunkType(dv, offset);
    if (!firstChunkType) firstChunkType = typeString;
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    const crcOffset = dataEnd;
    const nextOffset = crcOffset + 4;
    const truncated = dataEnd > size || nextOffset > size;
    const chunk: PngChunk = {
      type: typeString,
      length,
      offset,
      crc: truncated ? null : dv.getUint32(crcOffset, false),
      truncated
    };

    if (truncated) {
      issues.push(`Chunk ${typeString} at ${offset} is truncated.`);
      chunks.push(chunk);
      break;
    }

    if (typeString === "IHDR") {
      if (ihdr) issues.push("Multiple IHDR chunks found (only one allowed).");
      ihdr = parseIhdr(dv, offset, length, issues);
      if (chunkCount !== 0) issues.push("IHDR is not the first chunk.");
    } else if (typeString === "PLTE") {
      paletteEntries = length % 3 === 0 ? length / 3 : paletteEntries;
      if (length % 3 !== 0) {
        issues.push("PLTE length is not a multiple of 3 bytes per entry.");
      }
    } else if (typeString === "IDAT") {
      idatChunks += 1;
      idatSize += length;
    } else if (typeString === "tRNS") {
      hasTransparency =
        hasTransparency || parseTransparency(length, ihdr ? ihdr.colorType : null);
    } else if (typeString === "pHYs" && !physical) {
      physical = parsePhys(dv, offset, length);
    } else if (typeString === "gAMA" && gamma == null) {
      gamma = parseGamma(dv, offset, length);
    } else if (typeString === "iCCP" && !iccProfile) {
      iccProfile = parseIcc(dv, offset, length);
    } else if ((typeString === "tEXt" || typeString === "iTXt") && texts.length < 8) {
      const text = parseTextChunk(dv, offset, length);
      if (text) texts.push(text);
    } else if (typeString === "IEND") {
      sawIend = true;
    }

    chunks.push(chunk);
    chunkCount += 1;
    offset = nextOffset;
    if (typeString === "IEND") break;
  }

  if (!ihdr) issues.push("IHDR chunk missing or unreadable.");
  if (!sawIend) {
    issues.push("IEND chunk missing; file may be truncated or extra data present.");
  }
  if (ihdr && ihdr.usesPalette && paletteEntries === 0) {
    issues.push("Indexed-color images should include a PLTE palette.");
  }
  if (idatChunks === 0) issues.push("No IDAT chunks found; image data missing.");
  if (chunks.length >= MAX_CHUNKS) {
    issues.push(`Parsing stopped after ${MAX_CHUNKS} chunks to avoid runaway input.`);
  }

  return {
    size,
    ihdr,
    chunkCount: chunks.length,
    firstChunkType,
    paletteEntries,
    hasTransparency: hasTransparency || (ihdr ? ihdr.hasAlphaChannel : false),
    gamma,
    iccProfile,
    physical,
    idatChunks,
    idatSize,
    sawIend,
    texts,
    chunks,
    issues
  };
}
