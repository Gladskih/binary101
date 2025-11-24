"use strict";

export interface PngColorInfo {
  name: string;
  channels: number;
  palette: boolean;
  alpha: boolean;
  bits: number[];
}

export interface PngIhdr {
  width: number;
  height: number;
  bitDepth: number;
  colorType: number;
  compression: number;
  filter: number;
  interlace: number;
  channels: number | null;
  bitsPerPixel: number | null;
  bytesPerPixel: number | null;
  colorName: string;
  usesPalette: boolean;
  hasAlphaChannel: boolean;
}

export interface PngTextChunk {
  key: string;
  value: string;
  length: number;
}

export interface PngPhysicalInfo {
  pixelsPerUnitX: number;
  pixelsPerUnitY: number;
  unitSpecifier: number;
}

export interface PngIccProfile {
  name: string;
  compression: number;
}

export interface PngChunk {
  type: string | null;
  length: number;
  offset: number;
  crc: number | null;
  truncated: boolean;
}

export interface PngParseResult {
  size: number;
  ihdr: PngIhdr | null;
  chunkCount: number;
  firstChunkType: string | null;
  paletteEntries: number;
  hasTransparency: boolean;
  gamma: number | null;
  iccProfile: PngIccProfile | null;
  physical: PngPhysicalInfo | null;
  idatChunks: number;
  idatSize: number;
  sawIend: boolean;
  texts: PngTextChunk[];
  chunks: PngChunk[];
  issues: string[];
}

