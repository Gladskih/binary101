"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type { PngIccProfile, PngIhdr, PngPhysicalInfo, PngTextChunk } from "./types.js";

const IHDR_LENGTH = 13;
const MAX_TEXT_PREVIEW = 256;

const COLOR_TYPES = new Map<number, {
  name: string;
  channels: number;
  palette: boolean;
  alpha: boolean;
  bits: number[];
}>([
  [
    0,
    { name: "Grayscale", channels: 1, palette: false, alpha: false, bits: [1, 2, 4, 8, 16] }
  ],
  [
    2,
    { name: "Truecolor", channels: 3, palette: false, alpha: false, bits: [8, 16] }
  ],
  [
    3,
    { name: "Indexed-color", channels: 1, palette: true, alpha: false, bits: [1, 2, 4, 8] }
  ],
  [
    4,
    { name: "Grayscale + alpha", channels: 2, palette: false, alpha: true, bits: [8, 16] }
  ],
  [
    6,
    { name: "Truecolor + alpha", channels: 4, palette: false, alpha: true, bits: [8, 16] }
  ]
]);

export const readChunkHeader = (dv: DataView, offset: number): { length: number } | null => {
  if (offset + 8 > dv.byteLength) return null;
  const length = dv.getUint32(offset, false);
  return { length };
};

export const readChunkType = (dv: DataView, offset: number): string =>
  readAsciiString(dv, offset + 4, 4);

export const parseIhdr = (
  dv: DataView,
  offset: number,
  length: number,
  issues: string[]
): PngIhdr | null => {
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
};

export const parseTextChunk = (
  dv: DataView,
  offset: number,
  length: number
): PngTextChunk | null => {
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
};

export const parsePhys = (
  dv: DataView,
  offset: number,
  length: number
): PngPhysicalInfo | null => {
  if (length !== 9 || offset + 17 > dv.byteLength) return null;
  const dataOffset = offset + 8;
  const pixelsPerUnitX = dv.getUint32(dataOffset, false);
  const pixelsPerUnitY = dv.getUint32(dataOffset + 4, false);
  const unitSpecifier = dv.getUint8(dataOffset + 8);
  return { pixelsPerUnitX, pixelsPerUnitY, unitSpecifier };
};

export const parseGamma = (
  dv: DataView,
  offset: number,
  length: number
): number | null => {
  if (length !== 4 || offset + 16 > dv.byteLength) return null;
  const dataOffset = offset + 8;
  const gammaInt = dv.getUint32(dataOffset, false);
  return gammaInt / 100000;
};

export const parseIcc = (
  dv: DataView,
  offset: number,
  length: number
): PngIccProfile | null => {
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
};

export const parseTransparency = (length: number, colorType: number | null): boolean => {
  if (length === 0) return false;
  if (colorType === 3) return true;
  if (colorType === 0) return length === 2;
  if (colorType === 2) return length === 6;
  return colorType === 4 || colorType === 6;
};

