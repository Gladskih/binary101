"use strict";

export type BmpFileHeader = {
  signature: string | null;
  declaredFileSize: number | null;
  reserved1: number | null;
  reserved2: number | null;
  pixelArrayOffset: number | null;
  truncated: boolean;
};

export type BmpBitmaskChannel = {
  mask: number;
  shift: number;
  bits: number;
  contiguous: boolean;
};

export type BmpBitmasks = {
  red: BmpBitmaskChannel | null;
  green: BmpBitmaskChannel | null;
  blue: BmpBitmaskChannel | null;
  alpha: BmpBitmaskChannel | null;
};

export type BmpDibHeader = {
  headerSize: number | null;
  headerKind: string | null;
  width: number | null;
  height: number | null;
  signedHeight: number | null;
  topDown: boolean | null;
  planes: number | null;
  bitsPerPixel: number | null;
  compression: number | null;
  compressionName: string | null;
  imageSize: number | null;
  xPixelsPerMeter: number | null;
  yPixelsPerMeter: number | null;
  colorsUsed: number | null;
  importantColors: number | null;
  masks: BmpBitmasks | null;
  truncated: boolean;
};

export type BmpPaletteSummary = {
  offset: number;
  entrySize: number;
  expectedEntries: number | null;
  expectedBytes: number | null;
  presentEntries: number;
  availableBytes: number;
  truncated: boolean;
};

export type BmpPixelArraySummary = {
  offset: number | null;
  availableBytes: number | null;
  rowStride: number | null;
  expectedBytes: bigint | null;
  truncated: boolean;
  extraBytes: bigint | null;
};

export type BmpParseResult = {
  isBmp: true;
  fileSize: number;
  fileHeader: BmpFileHeader;
  dibHeader: BmpDibHeader;
  palette: BmpPaletteSummary | null;
  pixelArray: BmpPixelArraySummary | null;
  issues: string[];
};

