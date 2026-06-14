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

type PngParseState = {
  chunks: PngChunk[];
  issues: string[];
  texts: PngTextChunk[];
  ihdr: PngIhdr | null;
  firstChunkType: string | null;
  paletteEntries: number;
  hasTransparency: boolean;
  gamma: number | null;
  iccProfile: PngIccProfile | null;
  physical: PngPhysicalInfo | null;
  idatChunks: number;
  idatSize: number;
  sawIend: boolean;
};

const parseKnownChunk = (
  dv: DataView,
  offset: number,
  length: number,
  typeString: string,
  chunkCount: number,
  state: PngParseState
): void => {
  if (typeString === "IHDR") {
    if (state.ihdr) state.issues.push("Multiple IHDR chunks found (only one allowed).");
    state.ihdr = parseIhdr(dv, offset, length, state.issues);
    if (chunkCount !== 0) state.issues.push("IHDR is not the first chunk.");
  } else if (typeString === "PLTE") {
    state.paletteEntries = length % 3 === 0 ? length / 3 : state.paletteEntries;
    if (length % 3 !== 0) {
      state.issues.push("PLTE length is not a multiple of 3 bytes per entry.");
    }
  } else if (typeString === "IDAT") {
    state.idatChunks += 1;
    state.idatSize += length;
  } else if (typeString === "tRNS") {
    state.hasTransparency =
      state.hasTransparency || parseTransparency(length, state.ihdr ? state.ihdr.colorType : null);
  } else if (typeString === "pHYs" && !state.physical) {
    state.physical = parsePhys(dv, offset, length);
  } else if (typeString === "gAMA" && state.gamma == null) {
    state.gamma = parseGamma(dv, offset, length);
  } else if (typeString === "iCCP" && !state.iccProfile) {
    state.iccProfile = parseIcc(dv, offset, length);
  } else if ((typeString === "tEXt" || typeString === "iTXt") && state.texts.length < 8) {
    const text = parseTextChunk(dv, offset, length);
    if (text) state.texts.push(text);
  } else if (typeString === "IEND") {
    state.sawIend = true;
  }
};

const addPngFinalIssues = (state: PngParseState): void => {
  if (!state.ihdr) state.issues.push("IHDR chunk missing or unreadable.");
  if (!state.sawIend) {
    state.issues.push("IEND chunk missing; file may be truncated or extra data present.");
  }
  if (state.ihdr && state.ihdr.usesPalette && state.paletteEntries === 0) {
    state.issues.push("Indexed-color images should include a PLTE palette.");
  }
  if (state.idatChunks === 0) state.issues.push("No IDAT chunks found; image data missing.");
  if (state.chunks.length >= MAX_CHUNKS) {
    state.issues.push(`Parsing stopped after ${MAX_CHUNKS} chunks to avoid runaway input.`);
  }
};

export async function parsePng(file: File): Promise<PngParseResult | null> {
  const buffer = await file.arrayBuffer();
  const dv = new DataView(buffer);
  const size = dv.byteLength;
  if (size < 8) return null;
  if (dv.getUint32(0, false) !== PNG_SIG0 || dv.getUint32(4, false) !== PNG_SIG1) {
    return null;
  }

  const state: PngParseState = {
    chunks: [],
    issues: [],
    texts: [],
    ihdr: null,
    firstChunkType: null,
    paletteEntries: 0,
    hasTransparency: false,
    gamma: null,
    iccProfile: null,
    physical: null,
    idatChunks: 0,
    idatSize: 0,
    sawIend: false
  };
  let offset = 8;
  let chunkCount = 0;
  while (offset + 8 <= size && chunkCount < MAX_CHUNKS) {
    const header = readChunkHeader(dv, offset);
    if (!header) break;
    const { length } = header;
    const typeString = readChunkType(dv, offset);
    if (!state.firstChunkType) state.firstChunkType = typeString;
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
      state.issues.push(`Chunk ${typeString} at ${offset} is truncated.`);
      state.chunks.push(chunk);
      break;
    }

    parseKnownChunk(dv, offset, length, typeString, chunkCount, state);
    state.chunks.push(chunk);
    chunkCount += 1;
    offset = nextOffset;
    if (typeString === "IEND") break;
  }

  addPngFinalIssues(state);

  return {
    size,
    ihdr: state.ihdr,
    chunkCount: state.chunks.length,
    firstChunkType: state.firstChunkType,
    paletteEntries: state.paletteEntries,
    hasTransparency: state.hasTransparency || (state.ihdr ? state.ihdr.hasAlphaChannel : false),
    gamma: state.gamma,
    iccProfile: state.iccProfile,
    physical: state.physical,
    idatChunks: state.idatChunks,
    idatSize: state.idatSize,
    sawIend: state.sawIend,
    texts: state.texts,
    chunks: state.chunks,
    issues: state.issues
  };
}
