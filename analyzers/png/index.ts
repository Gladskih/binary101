// @ts-nocheck
"use strict";

import { readAsciiString } from "../../binary-utils.js";

const PNG_SIG0 = 0x89504e47;
const PNG_SIG1 = 0x0d0a1a0a;
const IHDR_LENGTH = 13;
const MAX_CHUNKS = 4096;
const MAX_TEXT_PREVIEW = 256;

const COLOR_TYPES = new Map([
  [
    0,
    {
      name: "Grayscale",
      channels: 1,
      palette: false,
      alpha: false,
      bits: [1, 2, 4, 8, 16]
    }
  ],
  [
    2,
    {
      name: "Truecolor",
      channels: 3,
      palette: false,
      alpha: false,
      bits: [8, 16]
    }
  ],
  [
    3,
    {
      name: "Indexed-color",
      channels: 1,
      palette: true,
      alpha: false,
      bits: [1, 2, 4, 8]
    }
  ],
  [
    4,
    {
      name: "Grayscale + alpha",
      channels: 2,
      palette: false,
      alpha: true,
      bits: [8, 16]
    }
  ],
  [
    6,
    {
      name: "Truecolor + alpha",
      channels: 4,
      palette: false,
      alpha: true,
      bits: [8, 16]
    }
  ]
]);

function readChunkHeader(dv, offset) {
  if (offset + 8 > dv.byteLength) return null;
  const length = dv.getUint32(offset, false);
  return { length };
}

function readChunkType(dv, offset) {
  return readAsciiString(dv, offset + 4, 4);
}

function parseIhdr(dv, offset, length, issues) {
  if (length !== IHDR_LENGTH) {
    issues.push(`IHDR length should be 13 bytes, found ${length}.`);
    if (offset + 8 + IHDR_LENGTH > dv.byteLength) return null;
  }
  if (offset + 8 + IHDR_LENGTH > dv.byteLength) return null;
  const dataOffset = offset + 8;
  const width = dv.getUint32(dataOffset, false);
  const height = dv.getUint32(dataOffset + 4, false);
  const bitDepth = dv.getUint8(dataOffset + 8);
  const colorType = dv.getUint8(dataOffset + 9);
  const compression = dv.getUint8(dataOffset + 10);
  const filter = dv.getUint8(dataOffset + 11);
  const interlace = dv.getUint8(dataOffset + 12);
  const colorInfo = COLOR_TYPES.get(colorType);
  if (!colorInfo) {
    issues.push(`Unknown color type ${colorType}.`);
  } else if (!colorInfo.bits.includes(bitDepth)) {
    issues.push(`Bit depth ${bitDepth} is invalid for ${colorInfo.name}.`);
  }
  if (compression !== 0) {
    issues.push(`Unexpected compression method ${compression} (expected 0).`);
  }
  if (filter !== 0) {
    issues.push(`Unexpected filter method ${filter} (expected 0).`);
  }
  if (interlace !== 0 && interlace !== 1) {
    issues.push(`Unknown interlace method ${interlace}.`);
  }
  const channels = colorInfo ? colorInfo.channels : null;
  const bitsPerPixel = channels ? bitDepth * channels : null;
  const bytesPerPixel = bitsPerPixel ? Math.ceil(bitsPerPixel / 8) : null;
  return {
    width,
    height,
    bitDepth,
    colorType,
    compression,
    filter,
    interlace,
    channels,
    bitsPerPixel,
    bytesPerPixel,
    colorName: colorInfo ? colorInfo.name : "Unknown",
    usesPalette: !!(colorInfo && colorInfo.palette),
    hasAlphaChannel: !!(colorInfo && colorInfo.alpha)
  };
}

function parseTextChunk(dv, offset, length) {
  const dataOffset = offset + 8;
  const end = dataOffset + length;
  if (end > dv.byteLength) return null;
  let key = "";
  let value = "";
  for (let i = dataOffset; i < end; i += 1) {
    const byte = dv.getUint8(i);
    if (byte === 0x00) {
      key = readAsciiString(dv, dataOffset, i - dataOffset);
      if (i + 1 <= end) {
        const valueLength = Math.min(end - (i + 1), MAX_TEXT_PREVIEW);
        value = readAsciiString(dv, i + 1, valueLength);
      }
      break;
    }
  }
  if (!key) return null;
  return { key, value, length };
}

function parsePhys(dv, offset, length) {
  if (length !== 9 || offset + 17 > dv.byteLength) return null;
  const dataOffset = offset + 8;
  const pixelsPerUnitX = dv.getUint32(dataOffset, false);
  const pixelsPerUnitY = dv.getUint32(dataOffset + 4, false);
  const unitSpecifier = dv.getUint8(dataOffset + 8);
  return { pixelsPerUnitX, pixelsPerUnitY, unitSpecifier };
}

function parseGamma(dv, offset, length) {
  if (length !== 4 || offset + 16 > dv.byteLength) return null;
  const dataOffset = offset + 8;
  const gammaInt = dv.getUint32(dataOffset, false);
  return gammaInt / 100000;
}

function parseIcc(dv, offset, length) {
  if (length < 2 || offset + 8 + length > dv.byteLength) return null;
  const dataOffset = offset + 8;
  const end = dataOffset + length;
  let name = "";
  for (let i = dataOffset; i < end; i += 1) {
    const byte = dv.getUint8(i);
    if (byte === 0) {
      name = readAsciiString(dv, dataOffset, i - dataOffset);
      break;
    }
  }
  if (!name) return null;
  const compressionOffset = dataOffset + name.length + 1;
  if (compressionOffset >= end) return null;
  const compression = dv.getUint8(compressionOffset);
  return { name, compression };
}

function parseTransparency(length, colorType) {
  if (length === 0) return false;
  if (colorType === 3) return true;
  if (colorType === 0) return length === 2;
  if (colorType === 2) return length === 6;
  return colorType === 4 || colorType === 6;
}

export async function parsePng(file) {
  const buffer = await file.arrayBuffer();
  const dv = new DataView(buffer);
  const size = dv.byteLength;
  if (size < 8) return null;
  if (dv.getUint32(0, false) !== PNG_SIG0 || dv.getUint32(4, false) !== PNG_SIG1) {
    return null;
  }

  const chunks = [];
  const issues = [];
  const texts = [];
  let offset = 8;
  let chunkCount = 0;
  let ihdr = null;
  let firstChunkType = null;
  let paletteEntries = 0;
  let hasTransparency = false;
  let gamma = null;
  let iccProfile = null;
  let physical = null;
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
    const chunk = {
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
