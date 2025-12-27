"use strict";

import { isPrintableByte, toHex32 } from "../../binary-utils.js";

export const TGA_HEADER_SIZE = 18;
export const TGA_FOOTER_SIZE = 26;
export const TGA_EXTENSION_AREA_SIZE = 495;
export const TGA_COLOR_CORRECTION_TABLE_SIZE = 1000;

export const readUint8 = (bytes: Uint8Array, offset: number): number | null => {
  if (offset + 1 > bytes.length) return null;
  return bytes[offset] ?? 0;
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

export const decodeFixedString = (bytes: Uint8Array, offset: number, length: number): string => {
  const end = Math.min(bytes.length, offset + length);
  let out = "";
  for (let index = offset; index < end; index += 1) {
    const byteValue = bytes[index] ?? 0;
    if (byteValue === 0) break;
    out += String.fromCharCode(byteValue);
  }
  return out.trimEnd();
};

export const decodePossiblyBinaryField = (
  bytes: Uint8Array,
  maxPreviewBytes = 64
): { text: string | null; previewHex: string | null } => {
  if (bytes.length === 0) return { text: null, previewHex: null };
  let printable = 0;
  for (const byteValue of bytes) {
    if (isPrintableByte(byteValue) || byteValue === 0x0a || byteValue === 0x0d || byteValue === 0x09) {
      printable += 1;
    }
  }
  const printableRatio = printable / bytes.length;
  if (printableRatio >= 0.9) {
    const text = decodeFixedString(bytes, 0, bytes.length);
    return { text: text.length ? text : null, previewHex: null };
  }
  const previewLength = Math.min(maxPreviewBytes, bytes.length);
  const hexPreview = [...bytes.slice(0, previewLength)]
    .map(byteValue => byteValue.toString(16).padStart(2, "0"))
    .join("");
  const suffix = previewLength < bytes.length ? "…" : "";
  return { text: null, previewHex: `0x${hexPreview}${suffix}` };
};

export const describeColorMapType = (value: number | null): string | null => {
  if (value == null) return null;
  if (value === 0) return "No color map";
  if (value === 1) return "Color map included";
  if (value >= 128) return `Developer-defined (${value})`;
  return `Reserved (${value})`;
};

export const describeImageType = (value: number | null): string | null => {
  if (value == null) return null;
  switch (value) {
    case 0:
      return "No image data";
    case 1:
      return "Color-mapped (uncompressed)";
    case 2:
      return "Truecolor (uncompressed)";
    case 3:
      return "Monochrome (uncompressed)";
    case 9:
      return "Color-mapped (RLE)";
    case 10:
      return "Truecolor (RLE)";
    case 11:
      return "Monochrome (RLE)";
    default:
      if (value >= 128) return `Developer-defined (${value})`;
      return `Unknown (${value})`;
  }
};

export const computeBytesPerPixel = (pixelDepthBits: number | null): number | null => {
  if (pixelDepthBits == null) return null;
  if (!Number.isFinite(pixelDepthBits) || pixelDepthBits <= 0) return null;
  return Math.ceil(pixelDepthBits / 8);
};

export const decodeOrigin = (imageDescriptor: number | null): string | null => {
  if (imageDescriptor == null) return null;
  const horizontal = (imageDescriptor & 0x10) !== 0 ? "right" : "left";
  const vertical = (imageDescriptor & 0x20) !== 0 ? "top" : "bottom";
  return `${vertical}-${horizontal}`;
};

export const describeDescriptorReservedBits = (imageDescriptor: number | null): string | null => {
  if (imageDescriptor == null) return null;
  const reserved = (imageDescriptor & 0xc0) >>> 0;
  return reserved ? `${toHex32(reserved, 2)} (should be 0)` : null;
};

