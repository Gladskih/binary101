"use strict";

import {
  findFirstChunk,
  findListChunks,
  parseInfoTags,
  parseRiffFromView,
  readFourCc
} from "../riff/index.js";
import { parseWaveFormat } from "../riff/wave-format.js";
import type {
  AviParseResult,
  AviStream,
  AviStreamHeader,
  AviVideoFormat,
  AviMainHeader
} from "./types.js";
import type { RiffChunk } from "../riff/types.js";

const MAIN_HEADER_SIZE = 56;
const STREAM_HEADER_MIN_SIZE = 48;
const BITMAPINFOHEADER_SIZE = 16; // minimal fields we read

const toDuration = (
  frames: number | null,
  frameRate: number | null
): number | null => {
  if (!frames || !frameRate || frameRate <= 0) return null;
  const seconds = frames / frameRate;
  return Number.isFinite(seconds) ? Math.round(seconds * 1000) / 1000 : null;
};

const parseMainHeader = (
  dv: DataView,
  chunkOffset: number,
  chunkSize: number,
  littleEndian: boolean,
  issues: string[]
): AviMainHeader | null => {
  if (chunkSize < MAIN_HEADER_SIZE || chunkOffset + MAIN_HEADER_SIZE > dv.byteLength) {
    issues.push("avih chunk is truncated.");
    return null;
  }
  const read32 = (rel: number) => dv.getUint32(chunkOffset + rel, littleEndian);
  const microSecPerFrame = read32(0);
  const frameRate =
    microSecPerFrame > 0 ? Math.round((1_000_000 / microSecPerFrame) * 1000) / 1000 : null;
  const totalFrames = read32(16);
  const streams = read32(24);
  const width = read32(32);
  const height = read32(36);
  return {
    microSecPerFrame,
    frameRate,
    maxBytesPerSec: read32(4),
    totalFrames,
    streams,
    width,
    height,
    suggestedBufferSize: read32(28),
    flags: read32(12),
    durationSeconds: toDuration(totalFrames, frameRate)
  };
};

const parseStreamHeader = (
  dv: DataView,
  chunkOffset: number,
  chunkSize: number,
  littleEndian: boolean,
  issues: string[]
): AviStreamHeader | null => {
  if (chunkSize < STREAM_HEADER_MIN_SIZE || chunkOffset + STREAM_HEADER_MIN_SIZE > dv.byteLength) {
    issues.push("strh chunk is truncated.");
    return null;
  }
  const read32 = (rel: number) => dv.getUint32(chunkOffset + rel, littleEndian);
  const header: AviStreamHeader = {
    type: readFourCc(dv, chunkOffset),
    handler: readFourCc(dv, chunkOffset + 4),
    flags: read32(8),
    initialFrames: read32(16),
    scale: read32(20),
    rate: read32(24),
    start: read32(28),
    length: read32(32),
    suggestedBufferSize: read32(36),
    quality: read32(40),
    sampleSize: read32(44),
    frame: null
  };
  if (chunkSize >= 64 && chunkOffset + 64 <= dv.byteLength) {
    header.frame = {
      left: dv.getInt32(chunkOffset + 48, littleEndian),
      top: dv.getInt32(chunkOffset + 52, littleEndian),
      right: dv.getInt32(chunkOffset + 56, littleEndian),
      bottom: dv.getInt32(chunkOffset + 60, littleEndian)
    };
  }
  return header;
};

const parseBitmapInfo = (
  dv: DataView,
  chunkOffset: number,
  chunkSize: number,
  littleEndian: boolean,
  issues: string[]
): AviVideoFormat | null => {
  if (chunkSize < BITMAPINFOHEADER_SIZE || chunkOffset + 16 > dv.byteLength) {
    issues.push("strf chunk for video is truncated.");
    return null;
  }
  const width = dv.getInt32(chunkOffset + 4, littleEndian);
  const height = dv.getInt32(chunkOffset + 8, littleEndian);
  const bitCount =
    chunkSize >= 16 && chunkOffset + 16 <= dv.byteLength
      ? dv.getUint16(chunkOffset + 14, littleEndian)
      : null;
  const compressionValue =
    chunkSize >= 20 && chunkOffset + 20 <= dv.byteLength
      ? dv.getUint32(chunkOffset + 16, littleEndian)
      : null;
  const compressionFourCc = chunkSize >= 20 ? readFourCc(dv, chunkOffset + 16) : null;
  const compression =
    compressionFourCc && /^[ -~]{4}$/.test(compressionFourCc)
      ? compressionFourCc
      : compressionValue != null
        ? `0x${compressionValue.toString(16)}`
        : null;
  const sizeImage =
    chunkSize >= 24 && chunkOffset + 24 <= dv.byteLength
      ? dv.getUint32(chunkOffset + 20, littleEndian)
      : null;
  return { width, height, bitCount, compression, sizeImage };
};

const findChildChunk = (listChunk: RiffChunk, id: string): RiffChunk | null => {
  if (!listChunk.children) return null;
  for (const child of listChunk.children) {
    if (child.id === id) return child;
  }
  return null;
};

const parseStream = (
  dv: DataView,
  streamList: RiffChunk,
  littleEndian: boolean,
  index: number,
  issues: string[]
): AviStream => {
  const streamIssues: string[] = [];
  const strh = findChildChunk(streamList, "strh");
  const header = strh
    ? parseStreamHeader(dv, strh.dataOffset, strh.size, littleEndian, streamIssues)
    : null;
  if (!strh) streamIssues.push("Missing strh chunk.");

  const strf = findChildChunk(streamList, "strf");
  let format: AviStream["format"] = null;
  if (header?.type === "vids") {
    if (strf && !strf.truncated) {
      format = parseBitmapInfo(dv, strf.dataOffset, strf.size, littleEndian, streamIssues);
    } else if (strf?.truncated) {
      streamIssues.push("Video format (strf) chunk is truncated.");
    } else {
      streamIssues.push("Missing strf chunk for video stream.");
    }
  } else if (header?.type === "auds") {
    if (strf && !strf.truncated) {
      format = parseWaveFormat(dv, strf.dataOffset, strf.size, littleEndian, streamIssues);
    } else if (strf?.truncated) {
      streamIssues.push("Audio format (strf) chunk is truncated.");
    } else if (header) {
      streamIssues.push("Missing strf chunk for audio stream.");
    }
  }

  const strn = findChildChunk(streamList, "strn");
  let name = null;
  if (strn) {
    const readable = Math.max(0, Math.min(strn.size, dv.byteLength - strn.dataOffset));
    let text = "";
    for (let i = 0; i < readable; i += 1) {
      const byte = dv.getUint8(strn.dataOffset + i);
      if (byte === 0) break;
      if (byte >= 0x09 && byte <= 0x7e) text += String.fromCharCode(byte);
    }
    name = text.trim() || null;
    if (strn.truncated) streamIssues.push("Stream name (strn) chunk is truncated.");
  }

  streamIssues.forEach(msg => issues.push(`Stream ${index}: ${msg}`));
  return { index, header, format, name, issues: streamIssues };
};

export async function parseAvi(file: File): Promise<AviParseResult | null> {
  const dv = new DataView(await file.arrayBuffer());
  const riff = parseRiffFromView(dv, { maxChunks: 8192, maxDepth: 5 });
  if (!riff || (riff.formType !== "AVI " && riff.formType !== "AVIX")) return null;
  const issues = [...riff.issues];

  const avih = findFirstChunk(riff.chunks, "avih");
  const mainHeader = avih
    ? parseMainHeader(dv, avih.dataOffset, avih.size, riff.littleEndian, issues)
    : null;
  if (!avih) issues.push("Missing avih header chunk.");

  const streamLists = findListChunks(riff.chunks, "strl");
  const streams: AviStream[] = streamLists.map((list, idx) =>
    parseStream(dv, list, riff.littleEndian, idx, issues)
  );

  const infoTags = parseInfoTags(dv, riff);

  return { riff, mainHeader, streams, infoTags, issues };
}
