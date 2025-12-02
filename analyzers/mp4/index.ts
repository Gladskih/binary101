"use strict";

/* eslint-disable max-lines */

import type {
  Mp4BoxSummary,
  Mp4BrandInfo,
  Mp4CodecDetails,
  Mp4MovieHeader,
  Mp4ParseResult,
  Mp4Track,
  Mp4TrackKind
} from "./types.js";

type BoxHeader = {
  type: string;
  size: number;
  start: number;
  end: number;
  headerSize: number;
  dataOffset: number;
  largesize?: number | null;
  truncated?: boolean;
};

type SttsInfo = {
  sampleCount: number;
  totalDuration: number;
};

type StszInfo = {
  sampleSizeConstant: number | null;
  sampleCount: number | null;
};

type StcoInfo = {
  chunkCount: number | null;
};

type StssInfo = {
  keyframeCount: number | null;
};

type TrackTables = {
  stts: SttsInfo | null;
  stsz: StszInfo | null;
  stco: StcoInfo | null;
  stss: StssInfo | null;
};

type ParsedHdlr = {
  handlerType: string | null;
  handlerName: string | null;
};

type ParsedMdhd = {
  creationTime: string | null;
  modificationTime: string | null;
  timescale: number | null;
  duration: number | null;
  durationSeconds: number | null;
  language: string | null;
};

type ParsedTkhd = {
  id: number | null;
  duration: number | null;
  durationSeconds: number | null;
  width: number | null;
  height: number | null;
  volume: number | null;
  creationTime: string | null;
  modificationTime: string | null;
};

const MP4_EPOCH_MS = Date.UTC(1904, 0, 1);
const AAC_SAMPLE_RATES = [
  96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350
];

const toFourCcFromView = (view: DataView, offset: number): string => {
  if (offset + 4 > view.byteLength) return "";
  return String.fromCharCode(
    view.getUint8(offset),
    view.getUint8(offset + 1),
    view.getUint8(offset + 2),
    view.getUint8(offset + 3)
  );
};

const mp4EpochToIsoString = (seconds: number | null): string | null => {
  if (seconds == null || Number.isNaN(seconds)) return null;
  const millis = seconds * 1000;
  const timestamp = MP4_EPOCH_MS + millis;
  if (!Number.isFinite(timestamp) || timestamp < 0) return null;
  return new Date(timestamp).toISOString();
};

const readUint16Safe = (view: DataView, offset: number): number | null =>
  offset + 2 <= view.byteLength ? view.getUint16(offset, false) : null;

const readFixed1616 = (value: number): number => Math.round((value / 65536) * 1000) / 1000;
const readFixed88 = (value: number): number => Math.round((value / 256) * 1000) / 1000;

const readBoxHeaderFromFile = async (
  file: File,
  offset: number,
  issues: string[],
  context: string
): Promise<BoxHeader | null> => {
  if (offset + 8 > file.size) {
    issues.push(`${context}: not enough data for box header at ${offset}.`);
    return null;
  }
  const headerBuffer = await file.slice(offset, offset + 16).arrayBuffer();
  const dv = new DataView(headerBuffer);
  const size = dv.getUint32(0, false);
  const type = toFourCcFromView(dv, 4);
  let headerSize = 8;
  let largesize: number | null = null;
  if (size === 1) {
    const large = dv.getBigUint64(8, false);
    largesize = Number(large);
    headerSize = 16;
  }
  const boxSize = size === 0 ? file.size - offset : size === 1 ? largesize ?? 0 : size;
  if (!Number.isFinite(boxSize) || boxSize < headerSize) {
    issues.push(`${context}: invalid size for ${type || "unknown"} at ${offset}.`);
    return null;
  }
  const end = Math.min(file.size, offset + boxSize);
  const truncated = offset + boxSize > file.size;
  return {
    type,
    size: boxSize,
    start: offset,
    end,
    headerSize,
    dataOffset: offset + headerSize,
    largesize,
    truncated
  };
};

const readBoxHeaderFromView = (
  view: DataView,
  relativeOffset: number,
  absoluteStart: number,
  issues: string[] | null
): BoxHeader | null => {
  if (relativeOffset + 8 > view.byteLength) {
    if (issues) issues.push(`Box header truncated at ${absoluteStart + relativeOffset}.`);
    return null;
  }
  const size = view.getUint32(relativeOffset, false);
  const type = toFourCcFromView(view, relativeOffset + 4);
  let headerSize = 8;
  let largesize: number | null = null;
  if (size === 1) {
    if (relativeOffset + 16 > view.byteLength) {
      if (issues) issues.push(`Large size header truncated for ${type} at ${absoluteStart + relativeOffset}.`);
      return null;
    }
    const large = view.getBigUint64(relativeOffset + 8, false);
    largesize = Number(large);
    headerSize = 16;
  }
  const boxSize = size === 0 ? view.byteLength - relativeOffset : size === 1 ? largesize ?? 0 : size;
  if (!Number.isFinite(boxSize) || boxSize < headerSize) {
    if (issues) issues.push(`Invalid size for ${type || "unknown"} at ${absoluteStart + relativeOffset}.`);
    return null;
  }
  const end = Math.min(view.byteLength, relativeOffset + boxSize);
  const truncated = relativeOffset + boxSize > view.byteLength;
  return {
    type,
    size: boxSize,
    start: absoluteStart + relativeOffset,
    end: absoluteStart + end,
    headerSize,
    dataOffset: absoluteStart + relativeOffset + headerSize,
    largesize,
    truncated
  };
};

const parseFtyp = async (file: File, header: BoxHeader, issues: string[]): Promise<Mp4BrandInfo | null> => {
  const length = header.end - header.dataOffset;
  const buffer = await file.slice(header.dataOffset, header.end).arrayBuffer();
  const dv = new DataView(buffer);
  if (length < 8) {
    issues.push("ftyp box is too small to read brands.");
    return null;
  }
  const majorBrand = toFourCcFromView(dv, 0) || null;
  const minorVersion = dv.getUint32(4, false);
  const compatibleBrands: string[] = [];
  for (let offset = 8; offset + 4 <= dv.byteLength; offset += 4) {
    const brand = toFourCcFromView(dv, offset);
    if (brand) compatibleBrands.push(brand);
  }
  return { majorBrand, minorVersion, compatibleBrands };
};

const parseMvhd = (view: DataView, start: number, size: number, issues: string[]): Mp4MovieHeader | null => {
  if (size < 24) {
    issues.push("mvhd box truncated.");
    return null;
  }
  const version = view.getUint8(start);
  let offset = start + 4;
  let creation: number | null = null;
  let modification: number | null = null;
  let timescale: number | null = null;
  let duration: number | null = null;
  if (version === 1) {
    if (offset + 28 > start + size) {
      issues.push("mvhd version 1 box truncated.");
      return null;
    }
    creation = Number(view.getBigUint64(offset, false));
    modification = Number(view.getBigUint64(offset + 8, false));
    timescale = view.getUint32(offset + 16, false);
    duration = Number(view.getBigUint64(offset + 20, false));
    offset += 28;
  } else {
    if (offset + 16 > start + size) {
      issues.push("mvhd version 0 box truncated.");
      return null;
    }
    creation = view.getUint32(offset, false);
    modification = view.getUint32(offset + 4, false);
    timescale = view.getUint32(offset + 8, false);
    duration = view.getUint32(offset + 12, false);
    offset += 16;
  }
  const rate = readFixed1616(view.getUint32(offset, false));
  const volume = readFixed88(view.getUint16(offset + 4, false));
  const nextTrackIdOffset = start + size - 4;
  const nextTrackId = nextTrackIdOffset >= start ? view.getUint32(nextTrackIdOffset, false) : null;
  const durationSeconds = timescale && duration != null ? duration / timescale : null;
  return {
    creationTime: mp4EpochToIsoString(creation),
    modificationTime: mp4EpochToIsoString(modification),
    timescale: timescale ?? null,
    duration,
    durationSeconds,
    rate,
    volume,
    nextTrackId
  };
};

const parseTkhd = (view: DataView, start: number, size: number, issues: string[]): ParsedTkhd | null => {
  if (size < 20) {
    issues.push("tkhd box truncated.");
    return null;
  }
  const version = view.getUint8(start);
  let cursor = start + 4;
  let creation: number | null = null;
  let modification: number | null = null;
  let duration: number | null = null;
  let trackId: number | null = null;
  if (version === 1) {
    if (cursor + 28 > start + size) {
      issues.push("tkhd version 1 box truncated.");
      return null;
    }
    creation = Number(view.getBigUint64(cursor, false));
    cursor += 8;
    modification = Number(view.getBigUint64(cursor, false));
    cursor += 8;
    trackId = view.getUint32(cursor, false);
    cursor += 4;
    cursor += 4; // reserved
    duration = Number(view.getBigUint64(cursor, false));
    cursor += 8;
  } else {
    if (cursor + 16 > start + size) {
      issues.push("tkhd version 0 box truncated.");
      return null;
    }
    creation = view.getUint32(cursor, false);
    cursor += 4;
    modification = view.getUint32(cursor, false);
    cursor += 4;
    trackId = view.getUint32(cursor, false);
    cursor += 4;
    cursor += 4; // reserved
    duration = view.getUint32(cursor, false);
    cursor += 4;
  }
  cursor += 8; // reserved[2]
  cursor += 2; // layer
  cursor += 2; // alternate group
  const volume = readFixed88(view.getUint16(cursor, false));
  cursor += 2;
  cursor += 2; // reserved
  cursor += 36; // matrix
  const width = readFixed1616(view.getUint32(cursor, false));
  cursor += 4;
  const height = readFixed1616(view.getUint32(cursor, false));
  return {
    id: trackId || null,
    duration,
    durationSeconds: null,
    width,
    height,
    volume,
    creationTime: mp4EpochToIsoString(creation),
    modificationTime: mp4EpochToIsoString(modification)
  };
};

const parseLanguage = (value: number | null): string | null => {
  if (value == null) return null;
  const c1 = ((value >> 10) & 0x1f) + 0x60;
  const c2 = ((value >> 5) & 0x1f) + 0x60;
  const c3 = (value & 0x1f) + 0x60;
  if (c1 < 0x61 || c2 < 0x61 || c3 < 0x61) return null;
  return String.fromCharCode(c1, c2, c3);
};

const parseMdhd = (view: DataView, start: number, size: number, issues: string[]): ParsedMdhd | null => {
  if (size < 12) {
    issues.push("mdhd box truncated.");
    return null;
  }
  const version = view.getUint8(start);
  let offset = start + 4;
  let creation: number | null = null;
  let modification: number | null = null;
  let timescale: number | null = null;
  let duration: number | null = null;
  if (version === 1) {
    if (offset + 28 > start + size) {
      issues.push("mdhd version 1 box truncated.");
      return null;
    }
    creation = Number(view.getBigUint64(offset, false));
    modification = Number(view.getBigUint64(offset + 8, false));
    timescale = view.getUint32(offset + 16, false);
    duration = Number(view.getBigUint64(offset + 20, false));
    offset += 28;
  } else {
    if (offset + 12 > start + size) {
      issues.push("mdhd version 0 box truncated.");
      return null;
    }
    creation = view.getUint32(offset, false);
    modification = view.getUint32(offset + 4, false);
    timescale = view.getUint32(offset + 8, false);
    duration = view.getUint32(offset + 12, false);
    offset += 16;
  }
  const languageCode = readUint16Safe(view, offset);
  const language = parseLanguage(languageCode);
  const durationSeconds = timescale && duration != null ? duration / timescale : null;
  return {
    creationTime: mp4EpochToIsoString(creation),
    modificationTime: mp4EpochToIsoString(modification),
    timescale: timescale ?? null,
    duration,
    durationSeconds,
    language
  };
};

const parseHdlr = (view: DataView, start: number, size: number, issues: string[]): ParsedHdlr | null => {
  if (size < 12) {
    issues.push("hdlr box truncated.");
    return null;
  }
  const handlerType = toFourCcFromView(view, start + 8) || null;
  const nameOffset = start + 24;
  let handlerName: string | null = null;
  if (nameOffset < start + size) {
    const slice = new Uint8Array(view.buffer, view.byteOffset + nameOffset, Math.max(0, size - 24));
    const nullIndex = slice.indexOf(0);
    const text = new TextDecoder().decode(nullIndex === -1 ? slice : slice.slice(0, nullIndex));
    handlerName = text || null;
  }
  return { handlerType, handlerName };
};

const parsePasp = (view: DataView, start: number, size: number): string | null => {
  if (size < 8) return null;
  const hSpacing = view.getUint32(start, false);
  const vSpacing = view.getUint32(start + 4, false);
  if (hSpacing === 0 || vSpacing === 0) return null;
  return `${hSpacing}:${vSpacing}`;
};

const describeAvcProfile = (profileIdc: number | null): string | null => {
  if (profileIdc == null) return null;
  if (profileIdc === 66) return "Baseline";
  if (profileIdc === 77) return "Main";
  if (profileIdc === 88) return "Extended";
  if (profileIdc === 100) return "High";
  if (profileIdc === 110) return "High 10";
  if (profileIdc === 122) return "High 4:2:2";
  if (profileIdc === 144) return "High 4:4:4";
  return `Profile ${profileIdc}`;
};

const describeHevcProfile = (profileIdc: number | null): string | null => {
  if (profileIdc == null) return null;
  if (profileIdc === 1) return "Main";
  if (profileIdc === 2) return "Main 10";
  if (profileIdc === 3) return "Main Still Picture";
  if (profileIdc === 4) return "Rext";
  return `Profile ${profileIdc}`;
};

const readAvcC = (view: DataView, start: number, size: number, format: string): Mp4CodecDetails => {
  const profileIdc = size >= 2 ? view.getUint8(start + 1) : null;
  const compat = size >= 3 ? view.getUint8(start + 2) : null;
  const levelIdc = size >= 4 ? view.getUint8(start + 3) : null;
  const codecString =
    profileIdc != null && compat != null && levelIdc != null
      ? `${format}.${profileIdc.toString(16).padStart(2, "0")}${compat
          .toString(16)
          .padStart(2, "0")}${levelIdc.toString(16).padStart(2, "0")}`
      : null;
  return {
    format,
    codecString,
    profile: describeAvcProfile(profileIdc),
    level: levelIdc != null ? `Level ${Math.round(levelIdc / 10)}.${levelIdc % 10}` : null,
    description: null,
    width: null,
    height: null,
    pixelAspectRatio: null,
    channels: null,
    sampleRate: null,
    bitDepth: null,
    bitrate: null,
    avc: {
      profileIdc,
      profileCompatibility: compat ?? null,
      levelIdc
    }
  };
};

const readHvcC = (view: DataView, start: number, size: number, format: string): Mp4CodecDetails => {
  if (size < 13) {
    return {
      format,
      codecString: null,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: null,
      sampleRate: null,
      bitDepth: null,
      bitrate: null,
      hevc: { profileIdc: null, tierFlag: null, levelIdc: null }
    };
  }
  const profileByte = view.getUint8(start + 1);
  const tierFlag = (profileByte & 0x20) >> 5;
  const profileIdc = profileByte & 0x1f;
  const levelIdc = view.getUint8(start + 12);
  const codecString =
    levelIdc != null && profileIdc != null ? `${format}.${profileIdc}.${tierFlag ? "H" : "L"}${levelIdc}` : null;
  return {
    format,
    codecString,
    profile: describeHevcProfile(profileIdc),
    level: levelIdc != null ? `Level ${levelIdc / 30}` : null,
    description: null,
    width: null,
    height: null,
    pixelAspectRatio: null,
    channels: null,
    sampleRate: null,
    bitDepth: null,
    bitrate: null,
    hevc: { profileIdc, tierFlag, levelIdc }
  };
};

const readAv1C = (view: DataView, start: number, size: number, format: string): Mp4CodecDetails => {
  if (size < 4) {
    return {
      format,
      codecString: null,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: null,
      sampleRate: null,
      bitDepth: null,
      bitrate: null,
      av1: { profile: null, level: null, bitDepth: null }
    };
  }
  const byte0 = view.getUint8(start);
  const profile = (byte0 & 0x30) >> 4;
  const level = view.getUint8(start + 1) & 0x1f;
  const seqProfile = view.getUint8(start + 1);
  const seqLevel = seqProfile & 0x1f;
  const configByte = view.getUint8(start + 2);
  const highBitDepth = (configByte & 0x40) !== 0;
  const twelveBit = (configByte & 0x10) !== 0;
  const bitDepth = twelveBit ? 12 : highBitDepth ? 10 : 8;
  const codecString = `${format}.${profile}.${seqLevel}`;
  return {
    format,
    codecString,
    profile: `Profile ${profile}`,
    level: `Level ${level}`,
    description: null,
    width: null,
    height: null,
    pixelAspectRatio: null,
    channels: null,
    sampleRate: null,
    bitDepth,
    bitrate: null,
    av1: { profile, level, bitDepth }
  };
};

const readVpcc = (view: DataView, start: number, size: number, format: string): Mp4CodecDetails => {
  if (size < 4) {
    return {
      format,
      codecString: null,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: null,
      sampleRate: null,
      bitDepth: null,
      bitrate: null,
      vp9: { profile: null, level: null, bitDepth: null }
    };
  }
  const profile = view.getUint8(start);
  const level = view.getUint8(start + 1);
  const bitDepth = view.getUint8(start + 2);
  const codecString = `${format}.0${profile}.${level}`;
  return {
    format,
    codecString,
    profile: `Profile ${profile}`,
    level: `Level ${level}`,
    description: null,
    width: null,
    height: null,
    pixelAspectRatio: null,
    channels: null,
    sampleRate: null,
    bitDepth,
    bitrate: null,
    vp9: { profile, level, bitDepth }
  };
};

const readExpandableSize = (view: DataView, offset: number, limit: number): { size: number; length: number } | null => {
  let size = 0;
  let consumed = 0;
  while (consumed < 4 && offset + consumed < limit) {
    const b = view.getUint8(offset + consumed);
    size = (size << 7) | (b & 0x7f);
    consumed += 1;
    if ((b & 0x80) === 0) return { size, length: consumed };
  }
  return null;
};

const parseAudioSpecificConfig = (view: DataView, offset: number, length: number) => {
  if (length < 2) return { audioObjectType: null, samplingFrequencyIndex: null, channelConfiguration: null };
  const b0 = view.getUint8(offset);
  const b1 = view.getUint8(offset + 1);
  const audioObjectType = b0 >> 3;
  const samplingFrequencyIndex = ((b0 & 0x07) << 1) | (b1 >> 7);
  const channelConfiguration = (b1 >> 3) & 0x0f;
  return { audioObjectType, samplingFrequencyIndex, channelConfiguration };
};

const readEsds = (
  view: DataView,
  start: number,
  size: number,
  format: string,
  sampleRateFromEntry: number | null,
  channelCount: number | null
): Mp4CodecDetails => {
  const limit = start + size;
  let cursor = start + 4;
  let codecString: string | null = null;
  let description: string | null = null;
  let audioObjectType: number | null = null;
  let samplingFrequencyIndex: number | null = null;
  let channelConfiguration: number | null = null;

  if (cursor >= limit) {
    return {
      format,
      codecString: format,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: channelCount,
      sampleRate: sampleRateFromEntry,
      bitDepth: null,
      bitrate: null,
      aac: { audioObjectType, samplingFrequencyIndex, channelConfiguration }
    };
  }

  const tag = view.getUint8(cursor);
  if (tag !== 0x03) {
    return {
      format,
      codecString: format,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: channelCount,
      sampleRate: sampleRateFromEntry,
      bitDepth: null,
      bitrate: null,
      aac: { audioObjectType, samplingFrequencyIndex, channelConfiguration }
    };
  }
  const sizeField = readExpandableSize(view, cursor + 1, limit);
  if (!sizeField) {
    return {
      format,
      codecString: format,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: channelCount,
      sampleRate: sampleRateFromEntry,
      bitDepth: null,
      bitrate: null,
      aac: { audioObjectType, samplingFrequencyIndex, channelConfiguration }
    };
  }
  cursor += 1 + sizeField.length;
  cursor += 2;
  cursor += 1;
  if (cursor >= limit) {
    return {
      format,
      codecString: format,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: channelCount,
      sampleRate: sampleRateFromEntry,
      bitDepth: null,
      bitrate: null,
      aac: { audioObjectType, samplingFrequencyIndex, channelConfiguration }
    };
  }
  if (view.getUint8(cursor) === 0x04) {
    const dcdSize = readExpandableSize(view, cursor + 1, limit);
    if (dcdSize) {
      const dcdStart = cursor + 1 + dcdSize.length;
      if (dcdStart + dcdSize.size <= limit) {
        const objectTypeIndication = view.getUint8(dcdStart);
        codecString = `${format}.${objectTypeIndication.toString(16)}`;
        const streamTypeByte = view.getUint8(dcdStart + 1);
        const bufferSize =
          (view.getUint8(dcdStart + 2) << 16) |
          (view.getUint8(dcdStart + 3) << 8) |
          view.getUint8(dcdStart + 4);
        const maxBitrate = view.getUint32(dcdStart + 5, false);
        const avgBitrate = view.getUint32(dcdStart + 9, false);
        const streamType = (streamTypeByte >> 2) & 0x3f;
        description = `streamType ${streamType}, buffer ${bufferSize}, bitrate ${avgBitrate || maxBitrate || 0}`;
        const nextTag = dcdStart + 13;
        if (nextTag < limit && view.getUint8(nextTag) === 0x05) {
          const dsi = readExpandableSize(view, nextTag + 1, limit);
          if (dsi) {
            const asc = parseAudioSpecificConfig(view, nextTag + 1 + dsi.length, dsi.size);
            audioObjectType = asc.audioObjectType;
            samplingFrequencyIndex = asc.samplingFrequencyIndex;
            channelConfiguration = asc.channelConfiguration;
            codecString = `${format}.40.${audioObjectType ?? objectTypeIndication}`;
          }
        }
      }
    }
  }
  const sampleRate: number | null =
    samplingFrequencyIndex != null && samplingFrequencyIndex < AAC_SAMPLE_RATES.length
      ? AAC_SAMPLE_RATES[samplingFrequencyIndex] ?? null
      : sampleRateFromEntry;
  const channels: number | null =
    channelConfiguration != null && channelConfiguration > 0 ? channelConfiguration : channelCount;
  return {
    format,
    codecString: codecString ?? format,
    profile: null,
    level: null,
    description,
    width: null,
    height: null,
    pixelAspectRatio: null,
    channels,
    sampleRate,
    bitDepth: null,
    bitrate: null,
    aac: { audioObjectType, samplingFrequencyIndex, channelConfiguration }
  };
};

const parseStts = (view: DataView, start: number, size: number, issues: string[]): SttsInfo | null => {
  if (size < 8) {
    issues.push("stts box truncated.");
    return null;
  }
  const entryCount = view.getUint32(start + 4, false);
  let offset = start + 8;
  let sampleCount = 0;
  let totalDuration = 0;
  for (let i = 0; i < entryCount; i += 1) {
    if (offset + 8 > start + size) {
      issues.push("stts entries truncated.");
      break;
    }
    const count = view.getUint32(offset, false);
    const delta = view.getUint32(offset + 4, false);
    sampleCount += count;
    totalDuration += count * delta;
    offset += 8;
  }
  return { sampleCount, totalDuration };
};

const parseStsz = (view: DataView, start: number, size: number, issues: string[]): StszInfo | null => {
  if (size < 12) {
    issues.push("stsz box truncated.");
    return null;
  }
  const sampleSize = view.getUint32(start + 4, false);
  const sampleCount = view.getUint32(start + 8, false);
  if (sampleSize === 0) {
    const tableBytes = sampleCount * 4;
    if (start + 12 + tableBytes > start + size) {
      issues.push("stsz sample size table truncated.");
    }
  }
  return { sampleSizeConstant: sampleSize || null, sampleCount };
};

const parseStco = (view: DataView, start: number, size: number, issues: string[]): StcoInfo | null => {
  if (size < 8) {
    issues.push("stco box truncated.");
    return null;
  }
  const entryCount = view.getUint32(start + 4, false);
  const required = entryCount * 4;
  if (start + 8 + required > start + size) {
    issues.push("stco entries truncated.");
  }
  return { chunkCount: entryCount };
};

const parseCo64 = (view: DataView, start: number, size: number, issues: string[]): StcoInfo | null => {
  if (size < 8) {
    issues.push("co64 box truncated.");
    return null;
  }
  const entryCount = view.getUint32(start + 4, false);
  const required = entryCount * 8;
  if (start + 8 + required > start + size) {
    issues.push("co64 entries truncated.");
  }
  return { chunkCount: entryCount };
};

const parseStss = (view: DataView, start: number, size: number, issues: string[]): StssInfo | null => {
  if (size < 8) {
    issues.push("stss box truncated.");
    return null;
  }
  const entryCount = view.getUint32(start + 4, false);
  const required = entryCount * 4;
  if (start + 8 + required > start + size) {
    issues.push("stss entries truncated.");
  }
  return { keyframeCount: entryCount };
};

const parseStsd = (
  view: DataView,
  start: number,
  size: number,
  handlerType: string | null,
  issues: string[]
): Mp4CodecDetails | null => {
  if (size < 8) {
    issues.push("stsd box truncated.");
    return null;
  }
  const entryCount = view.getUint32(start + 4, false);
  const offset = start + 8;
  if (entryCount === 0) {
    issues.push("stsd has no sample descriptions.");
    return null;
  }
  if (offset + 8 > start + size) {
    issues.push("stsd first entry truncated.");
    return null;
  }
  const entrySize = view.getUint32(offset, false);
  const format = toFourCcFromView(view, offset + 4);
  if (!entrySize || offset + entrySize > start + size) {
    issues.push("stsd sample entry size invalid or truncated.");
    return null;
  }
  const entryStart = offset + 8;
  const entryEnd = offset + entrySize;
  const remaining = entryEnd - entryStart;

  const isVisual = handlerType === "vide" || format === "avc1" || format === "avc3" || format === "hvc1" || format === "hev1" || format === "vp09" || format === "vp08" || format === "av01";
  const isAudio = handlerType === "soun" || format === "mp4a" || format === "ac-3" || format === "ec-3";
  let codecDetails: Mp4CodecDetails | null = null;

  if (isVisual) {
    if (remaining < 70) {
      issues.push("Visual sample entry truncated.");
      return null;
    }
    const width = view.getUint16(entryStart + 24, false);
    const height = view.getUint16(entryStart + 26, false);
    const depth = view.getUint16(entryStart + 74, false);
    const compressorNameLength = view.getUint8(entryStart + 42);
    const compressorName =
      compressorNameLength > 0 && compressorNameLength < 31
        ? new TextDecoder().decode(
            new Uint8Array(view.buffer, view.byteOffset + entryStart + 43, compressorNameLength)
          )
        : null;
    let childOffset = entryStart + 78;
    let pixelAspectRatio: string | null = null;
    while (childOffset + 8 <= entryEnd) {
      const childHeader = readBoxHeaderFromView(view, childOffset, childOffset + view.byteOffset, issues);
      if (!childHeader || childHeader.start >= childHeader.end) break;
      const payloadOffset = childOffset + childHeader.headerSize;
      const payloadSize = childHeader.size - childHeader.headerSize;
      if (childHeader.type === "avcC" || childHeader.type === "hvcC" || childHeader.type === "av1C" || childHeader.type === "vpcC") {
        if (childHeader.type === "avcC") {
          codecDetails = readAvcC(view, payloadOffset, payloadSize, format || "avc1");
        } else if (childHeader.type === "hvcC") {
          codecDetails = readHvcC(view, payloadOffset, payloadSize, format || "hvc1");
        } else if (childHeader.type === "av1C") {
          codecDetails = readAv1C(view, payloadOffset, payloadSize, format || "av01");
        } else if (childHeader.type === "vpcC") {
          codecDetails = readVpcc(view, payloadOffset, payloadSize, format || "vp09");
        }
      } else if (childHeader.type === "pasp") {
        pixelAspectRatio = parsePasp(view, payloadOffset, payloadSize) || pixelAspectRatio;
      }
      childOffset += childHeader.size;
    }
    if (!codecDetails) {
      codecDetails = {
        format,
        codecString: format,
        profile: null,
        level: null,
        description: compressorName,
        width,
        height,
        pixelAspectRatio,
        channels: null,
        sampleRate: null,
        bitDepth: depth || null,
        bitrate: null
      };
    } else {
      codecDetails.width = codecDetails.width ?? width;
      codecDetails.height = codecDetails.height ?? height;
      codecDetails.pixelAspectRatio = codecDetails.pixelAspectRatio ?? pixelAspectRatio;
      codecDetails.description = codecDetails.description ?? compressorName;
      codecDetails.bitDepth = codecDetails.bitDepth ?? (depth || null);
    }
  } else if (isAudio) {
    if (remaining < 20) {
      issues.push("Audio sample entry truncated.");
      return null;
    }
    const channelCount = view.getUint16(entryStart + 16, false);
    const sampleSize = view.getUint16(entryStart + 18, false);
    const sampleRate = readFixed1616(view.getUint32(entryStart + 24, false));
    let childOffset = entryStart + 28;
    while (childOffset + 8 <= entryEnd) {
      const childHeader = readBoxHeaderFromView(view, childOffset, childOffset + view.byteOffset, issues);
      if (!childHeader || childHeader.start >= childHeader.end) break;
      if (childHeader.type === "esds") {
        const payloadStart = childOffset + childHeader.headerSize;
        const payloadSize = childHeader.size - childHeader.headerSize;
        codecDetails = readEsds(view, payloadStart, payloadSize, format || "mp4a", sampleRate, channelCount);
      }
      childOffset += childHeader.size;
    }
    if (!codecDetails) {
      codecDetails = {
        format,
        codecString: format,
        profile: null,
        level: null,
        description: null,
        width: null,
        height: null,
        pixelAspectRatio: null,
        channels: channelCount || null,
        sampleRate: sampleRate || null,
        bitDepth: sampleSize || null,
        bitrate: null
      };
    } else {
      codecDetails.channels = codecDetails.channels ?? (channelCount || null);
      codecDetails.sampleRate = codecDetails.sampleRate ?? (sampleRate || null);
      codecDetails.bitDepth = codecDetails.bitDepth ?? (sampleSize || null);
    }
  } else {
    codecDetails = {
      format,
      codecString: format,
      profile: null,
      level: null,
      description: null,
      width: null,
      height: null,
      pixelAspectRatio: null,
      channels: null,
      sampleRate: null,
      bitDepth: null,
      bitrate: null
    };
  }
  return codecDetails;
};

const parseStbl = (
  view: DataView,
  start: number,
  size: number,
  handlerType: string | null,
  issues: string[]
): { codec: Mp4CodecDetails | null; tables: TrackTables } => {
  let offset = start;
  const end = start + size;
  let codec: Mp4CodecDetails | null = null;
  const tables: TrackTables = { stts: null, stsz: null, stco: null, stss: null };
  while (offset + 8 <= end) {
    const header = readBoxHeaderFromView(view, offset, view.byteOffset + offset, issues);
    if (!header || header.start >= header.end) break;
    const payloadStart = offset + header.headerSize;
    const payloadSize = header.size - header.headerSize;
    if (header.type === "stsd") {
      codec = parseStsd(view, payloadStart, payloadSize, handlerType, issues) || codec;
    } else if (header.type === "stts") {
      tables.stts = parseStts(view, payloadStart, payloadSize, issues);
    } else if (header.type === "stsz") {
      tables.stsz = parseStsz(view, payloadStart, payloadSize, issues);
    } else if (header.type === "stco") {
      tables.stco = parseStco(view, payloadStart, payloadSize, issues);
    } else if (header.type === "co64") {
      tables.stco = parseCo64(view, payloadStart, payloadSize, issues);
    } else if (header.type === "stss") {
      tables.stss = parseStss(view, payloadStart, payloadSize, issues);
    }
    offset += header.size;
  }
  return { codec, tables };
};

const parseMinf = (
  view: DataView,
  start: number,
  size: number,
  handlerType: string | null,
  issues: string[]
): { codec: Mp4CodecDetails | null; tables: TrackTables } => {
  let offset = start;
  const end = start + size;
  let codec: Mp4CodecDetails | null = null;
  const tables: TrackTables = { stts: null, stsz: null, stco: null, stss: null };
  while (offset + 8 <= end) {
    const header = readBoxHeaderFromView(view, offset, view.byteOffset + offset, issues);
    if (!header || header.start >= header.end) break;
    const payloadStart = offset + header.headerSize;
    const payloadSize = header.size - header.headerSize;
    if (header.type === "stbl") {
      const stbl = parseStbl(view, payloadStart, payloadSize, handlerType, issues);
      codec = stbl.codec || codec;
      tables.stts = stbl.tables.stts || tables.stts;
      tables.stsz = stbl.tables.stsz || tables.stsz;
      tables.stco = stbl.tables.stco || tables.stco;
      tables.stss = stbl.tables.stss || tables.stss;
    }
    offset += header.size;
  }
  return { codec, tables };
};

const parseMdia = (view: DataView, start: number, size: number, issues: string[]): {
  mdhd: ParsedMdhd | null;
  hdlr: ParsedHdlr | null;
  codec: Mp4CodecDetails | null;
  tables: TrackTables;
} => {
  let offset = start;
  const end = start + size;
  let mdhd: ParsedMdhd | null = null;
  let hdlr: ParsedHdlr | null = null;
  let codec: Mp4CodecDetails | null = null;
  const tables: TrackTables = { stts: null, stsz: null, stco: null, stss: null };
  while (offset + 8 <= end) {
    const header = readBoxHeaderFromView(view, offset, view.byteOffset + offset, issues);
    if (!header || header.start >= header.end) break;
    const payloadStart = offset + header.headerSize;
    const payloadSize = header.size - header.headerSize;
    if (header.type === "mdhd") {
      mdhd = parseMdhd(view, payloadStart, payloadSize, issues);
    } else if (header.type === "hdlr") {
      hdlr = parseHdlr(view, payloadStart, payloadSize, issues);
    } else if (header.type === "minf") {
      const minf = parseMinf(view, payloadStart, payloadSize, hdlr?.handlerType ?? null, issues);
      codec = minf.codec || codec;
      tables.stts = minf.tables.stts || tables.stts;
      tables.stsz = minf.tables.stsz || tables.stsz;
      tables.stco = minf.tables.stco || tables.stco;
      tables.stss = minf.tables.stss || tables.stss;
    }
    offset += header.size;
  }
  return { mdhd, hdlr, codec, tables };
};

const parseTrak = (view: DataView, start: number, size: number, _issues: string[]): Mp4Track | null => {
  const trackIssues: string[] = [];
  let offset = start;
  const end = start + size;
  let tkhd: ParsedTkhd | null = null;
  let mdia: ReturnType<typeof parseMdia> | null = null;
  while (offset + 8 <= end) {
    const header = readBoxHeaderFromView(view, offset, view.byteOffset + offset, trackIssues);
    if (!header || header.start >= header.end) break;
    const payloadStart = offset + header.headerSize;
    const payloadSize = header.size - header.headerSize;
    if (header.type === "tkhd") {
      tkhd = parseTkhd(view, payloadStart, payloadSize, trackIssues);
    } else if (header.type === "mdia") {
      mdia = parseMdia(view, payloadStart, payloadSize, trackIssues);
    }
    offset += header.size;
  }
  if (!tkhd && !mdia) return null;
  const handlerType = mdia?.hdlr?.handlerType || null;
  const kind: Mp4TrackKind =
    handlerType === "vide"
      ? "video"
      : handlerType === "soun"
        ? "audio"
        : handlerType === "hint"
          ? "hint"
          : handlerType === "subt"
            ? "subtitles"
            : handlerType === "text"
              ? "text"
              : handlerType === "meta"
                ? "meta"
                : "unknown";
  const timescale = mdia?.mdhd?.timescale ?? null;
  const durationRaw = mdia?.mdhd?.duration ?? tkhd?.duration ?? null;
  const durationSeconds =
    mdia?.mdhd?.durationSeconds ??
    (timescale && durationRaw != null ? durationRaw / timescale : null);
  const width = tkhd?.width ?? mdia?.codec?.width ?? null;
  const height = tkhd?.height ?? mdia?.codec?.height ?? null;
  const language = mdia?.mdhd?.language ?? null;
  const sampleCount = mdia?.tables.stts?.sampleCount ?? mdia?.tables.stsz?.sampleCount ?? null;
  const keyframeCount = mdia?.tables.stss?.keyframeCount ?? null;
  const chunkCount = mdia?.tables.stco?.chunkCount ?? null;
  const sampleSizeConstant = mdia?.tables.stsz?.sampleSizeConstant ?? null;
  return {
    id: tkhd?.id ?? null,
    kind,
    handlerType,
    handlerName: mdia?.hdlr?.handlerName ?? null,
    creationTime: mdia?.mdhd?.creationTime ?? tkhd?.creationTime ?? null,
    modificationTime: mdia?.mdhd?.modificationTime ?? tkhd?.modificationTime ?? null,
    duration: durationRaw,
    durationSeconds,
    timescale,
    language,
    width,
    height,
    volume: tkhd?.volume ?? null,
    sampleCount,
    keyframeCount,
    chunkCount,
    sampleSizeConstant,
    codec: mdia?.codec ?? null,
    warnings: trackIssues
  };
};

const parseMoov = async (
  file: File,
  header: BoxHeader,
  issues: string[]
): Promise<{ mvhd: Mp4MovieHeader | null; tracks: Mp4Track[] }> => {
  const buffer = await file.slice(header.dataOffset, header.end).arrayBuffer();
  const view = new DataView(buffer);
  let offset = 0;
  let mvhd: Mp4MovieHeader | null = null;
  const tracks: Mp4Track[] = [];
  while (offset + 8 <= view.byteLength) {
    const child = readBoxHeaderFromView(view, offset, header.dataOffset + offset, issues);
    if (!child || child.start >= child.end) break;
    const payloadStart = offset + child.headerSize;
    const payloadSize = child.size - child.headerSize;
    if (child.type === "mvhd") {
      mvhd = parseMvhd(view, payloadStart, payloadSize, issues);
    } else if (child.type === "trak") {
      const track = parseTrak(view, payloadStart, payloadSize, issues);
      if (track) tracks.push(track);
    }
    offset += child.size;
  }
  return { mvhd, tracks };
};

export async function parseMp4(file: File): Promise<Mp4ParseResult | null> {
  if (file.size < 12) return null;
  const prefix = new DataView(await file.slice(0, Math.min(file.size, 64)).arrayBuffer());
  const firstType = prefix.getUint32(4, false);
  if (firstType !== 0x66747970) return null;
  const issues: string[] = [];
  const topLevelBoxes: Mp4BoxSummary[] = [];
  let brands: Mp4BrandInfo | null = null;
  let movieHeader: Mp4MovieHeader | null = null;
  const tracks: Mp4Track[] = [];
  let fragmentCount = 0;
  let mdatBytes = 0;
  let firstMoovOffset: number | null = null;
  let firstMdatOffset: number | null = null;

  let offset = 0;
  while (offset + 8 <= file.size) {
    const header = await readBoxHeaderFromFile(file, offset, issues, "MP4");
    if (!header) break;
    topLevelBoxes.push({
      type: header.type,
      start: header.start,
      end: header.end,
      size: header.size,
      headerSize: header.headerSize,
      largesize: header.largesize ?? null,
      truncated: header.truncated === true
    });
    if (header.type === "ftyp" && !brands) {
      brands = await parseFtyp(file, header, issues);
    } else if (header.type === "moov") {
      firstMoovOffset = firstMoovOffset ?? header.start;
      const moov = await parseMoov(file, header, issues);
      movieHeader = moov.mvhd || movieHeader;
      tracks.push(...moov.tracks);
    } else if (header.type === "moof") {
      fragmentCount += 1;
    } else if (header.type === "mdat") {
      if (firstMdatOffset == null) firstMdatOffset = header.start;
      mdatBytes += header.size;
    }
    if (!header.size) break;
    offset = header.end;
  }

  const fastStart =
    firstMoovOffset != null && firstMdatOffset != null
      ? firstMoovOffset < firstMdatOffset
      : null;

  if (!movieHeader) issues.push("Movie header not found.");
  if (tracks.length === 0) issues.push("No tracks were parsed from this file.");

  return {
    isMp4: true,
    brands,
    movieHeader,
    tracks,
    fragmentCount,
    mdatBytes,
    fastStart,
    topLevelBoxes,
    warnings: issues
  };
}

export const buildMp4Label = (parsed: Mp4ParseResult | null | undefined): string | null => {
  if (!parsed) return null;
  const brand = parsed.brands?.majorBrand || "MP4";
  const video = parsed.tracks.find(track => track.kind === "video");
  const audio = parsed.tracks.find(track => track.kind === "audio");
  const parts: string[] = [];
  if (video) {
    const videoParts: string[] = [];
    if (video.codec?.codecString) videoParts.push(video.codec.codecString);
    if (!videoParts.length && video.codec?.description) videoParts.push(video.codec.description);
    if (video.width && video.height) videoParts.push(`${video.width}x${video.height}`);
    parts.push(`video: ${videoParts.join(", ") || "track"}`);
  }
  if (audio) {
    const audioParts: string[] = [];
    if (audio.codec?.codecString) audioParts.push(audio.codec.codecString);
    if (!audioParts.length && audio.codec?.description) audioParts.push(audio.codec.description);
    if (audio.codec?.sampleRate) audioParts.push(`${Math.round(audio.codec.sampleRate)} Hz`);
    if (audio.codec?.channels) audioParts.push(`${audio.codec.channels} ch`);
    parts.push(`audio: ${audioParts.join(", ") || "track"}`);
  }
  const duration =
    parsed.movieHeader?.durationSeconds ??
    video?.durationSeconds ??
    audio?.durationSeconds ??
    null;
  const durationLabel =
    duration != null ? `${(Math.round(duration * 1000) / 1000).toFixed(duration < 10 ? 3 : 1)} s` : null;
  if (durationLabel) parts.push(durationLabel);
  const suffix = parts.length ? ` (${parts.join("; ")})` : "";
  return `${brand} MP4${suffix}`;
};
