"use strict";

import { bufferToHex } from "../../binary-utils.js";
import { parsePicture } from "./picture-block.js";
import { decodeAscii, decodeUtf8, isPrintableAscii } from "./text-reading.js";
import type {
  FlacApplicationBlock,
  FlacCueSheetBlock,
  FlacMetadataBlockDetail,
  FlacMetadataBlockType,
  FlacSeekPoint,
  FlacSeekTableBlock,
  FlacStreamInfo,
  FlacStreamInfoBlock,
  FlacVorbisCommentBlock
} from "./types.js";

const STREAMINFO_SIZE = 34;
const utf8Decoder = new TextDecoder("utf-8", { fatal: false });

const readUint24 = (dv: DataView, offset: number): number =>
  (dv.getUint8(offset) << 16) | (dv.getUint8(offset + 1) << 8) | dv.getUint8(offset + 2);

const toDurationSeconds = (samples: number | null, sampleRate: number | null): number | null => {
  if (!samples || !sampleRate) return null;
  const duration = samples / sampleRate;
  return Number.isFinite(duration) ? Math.round(duration * 1000) / 1000 : null;
};

const mapBlockType = (rawType: number): FlacMetadataBlockType => {
  if (rawType === 0) return "STREAMINFO";
  if (rawType === 1) return "PADDING";
  if (rawType === 2) return "APPLICATION";
  if (rawType === 3) return "SEEKTABLE";
  if (rawType === 4) return "VORBIS_COMMENT";
  if (rawType === 5) return "CUESHEET";
  if (rawType === 6) return "PICTURE";
  return "UNKNOWN";
};

const parseStreamInfo = (data: DataView, warnings: string[]): FlacStreamInfo | null => {
  if (data.byteLength < STREAMINFO_SIZE) {
    warnings.push("STREAMINFO block is truncated.");
    return null;
  }
  const minBlockSize = data.getUint16(0, false),
    maxBlockSize = data.getUint16(2, false),
    minFrameSize = readUint24(data, 4),
    maxFrameSize = readUint24(data, 7),
    hi = data.getUint32(10, false),
    lo = data.getUint32(14, false),
    sampleRate = (hi >>> 12) & 0xfffff,
    channels = ((hi >>> 9) & 0x7) + 1,
    bitsPerSample = ((hi >>> 4) & 0x1f) + 1;
  const totalSamples = ((hi & 0x0f) * 0x100000000) + lo;
  const md5 = bufferToHex(new Uint8Array(data.buffer, data.byteOffset + 18, 16));
  const durationSeconds = toDurationSeconds(totalSamples, sampleRate);
  return {
    minBlockSize,
    maxBlockSize,
    minFrameSize,
    maxFrameSize,
    sampleRate,
    channels,
    bitsPerSample,
    totalSamples,
    md5,
    durationSeconds,
    averageBitrateKbps: null
  };
};

const parseApplicationBlock = (
  base: FlacApplicationBlock,
  data: DataView,
  warnings: string[]
): FlacApplicationBlock => {
  let rawId: number | null = null;
  if (data.byteLength >= 4) rawId = data.getUint32(0, false);
  else warnings.push("APPLICATION block is shorter than 4 bytes.");
  let id: string | null = null;
  if (rawId != null) {
    const bytes = new Uint8Array(data.buffer, data.byteOffset, Math.min(4, data.byteLength));
    id = isPrintableAscii(bytes) ? decodeAscii(data, 0, 4) : `0x${rawId.toString(16)}`;
  }
  const dataLength = base.length >= 4 ? base.length - 4 : null;
  return { ...base, rawId, id, dataLength };
};

const parseSeekTable = (
  base: FlacSeekTableBlock,
  data: DataView,
  warnings: string[]
): FlacSeekTableBlock => {
  const points: FlacSeekPoint[] = [];
  const fullEntries = Math.floor(data.byteLength / 18);
  for (let index = 0; index < fullEntries; index += 1) {
    const offset = index * 18;
    const sampleNumber = data.getBigUint64(offset, false);
    const streamOffset = data.getBigUint64(offset + 8, false);
    const frameSamples = data.getUint16(offset + 16, false);
    points.push({
      sampleNumber,
      streamOffset,
      frameSamples,
      placeholder: sampleNumber === 0xffffffffffffffffn
    });
  }
  if (data.byteLength % 18 !== 0) warnings.push("SEEKTABLE ends with a partial seekpoint entry.");
  return { ...base, points, parsedEntries: fullEntries };
};

const parseVorbisComment = (
  base: FlacVorbisCommentBlock,
  data: DataView,
  warnings: string[]
): FlacVorbisCommentBlock => {
  let offset = 0;
  if (data.byteLength < 4) {
    warnings.push("VORBIS_COMMENT block missing vendor length.");
    return base;
  }
  const vendorLength = data.getUint32(offset, true);
  offset += 4;
  if (offset + vendorLength > data.byteLength) {
    warnings.push("VORBIS_COMMENT vendor string is truncated.");
    base.vendor = decodeUtf8(data, offset, data.byteLength - offset, utf8Decoder);
    return base;
  }
  base.vendor = decodeUtf8(data, offset, vendorLength, utf8Decoder);
  offset += vendorLength;
  if (offset + 4 > data.byteLength) {
    warnings.push("VORBIS_COMMENT missing user comment count.");
    return base;
  }
  const commentCount = data.getUint32(offset, true);
  base.commentCount = commentCount;
  offset += 4;
  const comments = [];
  for (let index = 0; index < commentCount && offset + 4 <= data.byteLength; index += 1) {
    const length = data.getUint32(offset, true);
    offset += 4;
    const available = Math.max(0, data.byteLength - offset);
    const raw = decodeUtf8(data, offset, Math.min(length, available), utf8Decoder);
    const separator = raw.indexOf("=");
    comments.push({
      key: separator >= 0 ? raw.slice(0, separator) : "",
      value: separator >= 0 ? raw.slice(separator + 1) : raw
    });
    if (length > available) {
      warnings.push("VORBIS_COMMENT entry is truncated.");
      break;
    }
    offset += length;
  }
  base.comments = comments;
  return base;
};

const parseCueSheet = (
  base: FlacCueSheetBlock,
  data: DataView,
  warnings: string[]
): FlacCueSheetBlock => {
  if (data.byteLength < 137) {
    warnings.push("CUESHEET block is truncated.");
    return base;
  }
  base.catalog = decodeAscii(data, 0, 128).replace(/\0+$/, "") || null;
  base.leadInSamples = data.getBigUint64(128, false);
  const flags = data.getUint8(136);
  base.isCd = (flags & 0x01) !== 0;
  if (data.byteLength >= 395) base.trackCount = data.getUint8(394);
  else warnings.push("CUESHEET track list is not fully parsed.");
  return base;
};

const parseMetadataBlock = (
  rawType: number,
  isLast: boolean,
  length: number,
  offset: number,
  data: DataView,
  truncated: boolean,
  warnings: string[]
): FlacMetadataBlockDetail => {
  const type = mapBlockType(rawType);
  const base = { type, rawType, isLast, length, offset, truncated };
  switch (type) {
    case "STREAMINFO":
      return { ...base, type, info: parseStreamInfo(data, warnings) } satisfies FlacStreamInfoBlock;
    case "PADDING":
      return { ...base, type: "PADDING" };
    case "APPLICATION":
      return parseApplicationBlock(
        { ...base, type, id: null, rawId: null, dataLength: null },
        data,
        warnings
      );
    case "SEEKTABLE":
      return parseSeekTable({ ...base, type, points: [], parsedEntries: 0 }, data, warnings);
    case "VORBIS_COMMENT":
      return parseVorbisComment(
        { ...base, type, vendor: null, commentCount: null, comments: [] },
        data,
        warnings
      );
    case "CUESHEET":
      return parseCueSheet(
        { ...base, type, catalog: null, leadInSamples: null, isCd: null, trackCount: null },
        data,
        warnings
      );
    case "PICTURE":
      return parsePicture(
        {
          ...base,
          type,
          pictureType: null,
          mimeType: null,
          description: null,
          width: null,
          height: null,
          depth: null,
          colors: null,
          dataLength: null
        },
        data,
        warnings
      );
    default:
      return {
        type: "UNKNOWN",
        rawType,
        isLast,
        length,
        offset,
        truncated
      };
  }
};

export { mapBlockType, parseMetadataBlock, STREAMINFO_SIZE };
