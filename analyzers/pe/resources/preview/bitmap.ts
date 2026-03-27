"use strict";

import { makeDataUrl } from "./data-url.js";
import type { ResourcePreviewResult } from "./types.js";

const BMP_FILE_HEADER_SIZE = 14; // BITMAPFILEHEADER
// BI_* compression values used by BITMAPINFOHEADER/BITMAPV4HEADER/BITMAPV5HEADER. Sources:
// Microsoft Learn, BITMAPINFOHEADER / BITMAPV4HEADER / BITMAPV5HEADER.
const BI_RGB = 0;
const BI_BITFIELDS = 3;
const BI_ALPHABITFIELDS = 6;

const readU16 = (view: DataView, offset: number): number => view.getUint16(offset, true);
const readU32 = (view: DataView, offset: number): number => view.getUint32(offset, true);

const estimateBitmapHeaderExtras = (
  headerSize: number,
  compression: number,
  bitCount: number
): number => {
  if (headerSize !== 40) return 0;
  if (compression !== BI_BITFIELDS && compression !== BI_ALPHABITFIELDS) return 0;
  return bitCount === 32 ? 16 : 12;
};

const estimatePaletteBytes = (
  headerSize: number,
  bitCount: number,
  colorsUsed: number
): number => {
  if (bitCount > 8) return 0;
  const entryCount = colorsUsed > 0 ? colorsUsed : (1 << bitCount);
  const entrySize = headerSize === 12 ? 3 : 4;
  return entryCount * entrySize;
};

const buildBitmapFile = (data: Uint8Array): Uint8Array | null => {
  if (data.length < 16) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const headerSize = readU32(view, 0);
  // DIB header size is the first DWORD; these accepted sizes mirror the BMP analyzer's supported
  // header kinds in analyzers/bmp/bmp-parsing.ts and Win32 bitmap-header docs.
  if (
    headerSize !== 12 &&
    headerSize !== 40 &&
    headerSize !== 52 &&
    headerSize !== 56 &&
    headerSize !== 108 &&
    headerSize !== 124
  ) {
    return null;
  }
  const bitCount = headerSize === 12 ? readU16(view, 10) : readU16(view, 14);
  const compression = headerSize >= 40 ? readU32(view, 16) : BI_RGB;
  const colorsUsed = headerSize >= 40 ? readU32(view, 32) : 0;
  const pixelOffset =
    BMP_FILE_HEADER_SIZE +
    headerSize +
    estimateBitmapHeaderExtras(headerSize, compression, bitCount) +
    estimatePaletteBytes(headerSize, bitCount, colorsUsed);
  if (pixelOffset > BMP_FILE_HEADER_SIZE + data.length) return null;
  const fileBytes = new Uint8Array(BMP_FILE_HEADER_SIZE + data.length);
  const out = new DataView(fileBytes.buffer);
  out.setUint8(0, 0x42);
  out.setUint8(1, 0x4d);
  out.setUint32(2, fileBytes.length, true);
  out.setUint16(6, 0, true);
  out.setUint16(8, 0, true);
  out.setUint32(10, pixelOffset, true);
  fileBytes.set(data, BMP_FILE_HEADER_SIZE);
  return fileBytes;
};

export const addBitmapPreview = (
  data: Uint8Array,
  typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "BITMAP") return null;
  const bmpFile = buildBitmapFile(data);
  if (!bmpFile) {
    return { issues: ["BITMAP resource could not be wrapped into a BMP file preview."] };
  }
  return {
    preview: {
      previewKind: "image",
      previewMime: "image/bmp",
      previewDataUrl: makeDataUrl("image/bmp", bmpFile)
    }
  };
};
