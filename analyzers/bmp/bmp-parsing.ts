"use strict";

import type { BmpBitmaskChannel } from "./types.js";

export const FILE_HEADER_SIZE = 14;
export const MAX_PREFIX_BYTES = 1024 * 1024;

const COMPRESSION_NAMES: Record<number, string> = {
  0: "BI_RGB (uncompressed)",
  1: "BI_RLE8 (RLE 8-bit)",
  2: "BI_RLE4 (RLE 4-bit)",
  3: "BI_BITFIELDS (uncompressed with masks)",
  4: "BI_JPEG",
  5: "BI_PNG",
  6: "BI_ALPHABITFIELDS (uncompressed with alpha mask)",
  11: "BI_CMYK",
  12: "BI_CMYKRLE8",
  13: "BI_CMYKRLE4"
};

export const readUint16le = (bytes: Uint8Array, offset: number): number | null => {
  if (offset + 2 > bytes.length) return null;
  return (bytes[offset] ?? 0) | ((bytes[offset + 1] ?? 0) << 8);
};

export const readUint32le = (bytes: Uint8Array, offset: number): number | null => {
  if (offset + 4 > bytes.length) return null;
  return (
    (bytes[offset] ?? 0) |
    ((bytes[offset + 1] ?? 0) << 8) |
    ((bytes[offset + 2] ?? 0) << 16) |
    ((bytes[offset + 3] ?? 0) << 24)
  ) >>> 0;
};

export const readInt32le = (bytes: Uint8Array, offset: number): number | null => {
  const value = readUint32le(bytes, offset);
  if (value == null) return null;
  return value > 0x7fffffff ? value - 0x1_0000_0000 : value;
};

export const describeCompression = (compression: number | null): string | null => {
  if (compression == null) return null;
  return COMPRESSION_NAMES[compression] || `Unknown (${compression})`;
};

export const describeDibKind = (dibSize: number | null): string | null => {
  if (dibSize == null) return null;
  if (dibSize === 12) return "BITMAPCOREHEADER";
  if (dibSize === 40) return "BITMAPINFOHEADER";
  if (dibSize === 52) return "BITMAPV2INFOHEADER";
  if (dibSize === 56) return "BITMAPV3INFOHEADER";
  if (dibSize === 108) return "BITMAPV4HEADER";
  if (dibSize === 124) return "BITMAPV5HEADER";
  if (dibSize >= 40) return `DIB (${dibSize} bytes)`;
  return `Core DIB (${dibSize} bytes)`;
};

export const buildBitmaskChannel = (mask: number | null): BmpBitmaskChannel | null => {
  const normalized = mask == null ? 0 : mask >>> 0;
  if (!normalized) return null;
  let shift = 0;
  let shifted = normalized;
  while ((shifted & 1) === 0 && shift < 32) {
    shifted >>>= 1;
    shift += 1;
  }
  let bits = 0;
  while ((shifted & 1) === 1 && bits < 32) {
    shifted >>>= 1;
    bits += 1;
  }
  const contiguous = shifted === 0;
  return { mask: normalized, shift, bits, contiguous };
};

export const computeRowStride = (width: number | null, bitsPerPixel: number | null): number | null => {
  if (width == null || bitsPerPixel == null) return null;
  if (!Number.isFinite(width) || width <= 0) return null;
  if (!Number.isFinite(bitsPerPixel) || bitsPerPixel <= 0) return null;
  const bitsPerRow = bitsPerPixel * width;
  return Math.floor((bitsPerRow + 31) / 32) * 4;
};

export const isUncompressedLayout = (compression: number | null): boolean =>
  compression == null || compression === 0 || compression === 3 || compression === 6;

