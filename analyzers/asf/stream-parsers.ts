"use strict";

import {
  HUNDRED_NS_PER_SECOND,
  STREAM_TYPE_AUDIO,
  STREAM_TYPE_NAMES,
  STREAM_TYPE_VIDEO
} from "./constants.js";
import {
  AUDIO_FORMAT_NAMES,
  filetimeToIso,
  fourCcFromNumber,
  guidToString,
  hundredNsToSeconds,
  numberOrString,
  readUint64
} from "./shared.js";
import type {
  AsfAudioFormat,
  AsfDataObject,
  AsfFileProperties,
  AsfStreamFormat,
  AsfStreamProperties
} from "./types.js";

const parseAudioFormat = (
  dv: DataView,
  start: number,
  length: number,
  issues: string[]
): AsfAudioFormat => {
  const truncated = length < 16;
  if (truncated) issues.push("Audio format data is truncated.");
  if (length < 16) {
    return {
      kind: "audio",
      formatTag: null,
      formatName: null,
      channels: null,
      sampleRate: null,
      avgBytesPerSec: null,
      blockAlign: null,
      bitsPerSample: null,
      extraDataSize: null,
      truncated: true
    };
  }
  const formatTag = dv.getUint16(start, true);
  return {
    kind: "audio",
    formatTag,
    formatName: AUDIO_FORMAT_NAMES[formatTag] || null,
    channels: dv.getUint16(start + 2, true),
    sampleRate: dv.getUint32(start + 4, true),
    avgBytesPerSec: dv.getUint32(start + 8, true),
    blockAlign: dv.getUint16(start + 12, true),
    bitsPerSample: dv.getUint16(start + 14, true),
    extraDataSize: length >= 18 ? dv.getUint16(start + 16, true) : null,
    truncated
  };
};

const parseVideoFormat = (
  dv: DataView,
  start: number,
  length: number,
  issues: string[]
): AsfStreamFormat => {
  const truncated = length < 88;
  if (truncated) issues.push("Video format data is truncated.");
  if (length < 48) return { kind: "unknown", note: "Video header too small to read." };
  const bitRate = dv.getUint32(start + 32, true);
  const bitErrorRate = dv.getUint32(start + 36, true);
  const frameTime = readUint64(dv, start + 40);
  const frameRate =
    frameTime && frameTime > 0n
      ? Math.round((HUNDRED_NS_PER_SECOND / Number(frameTime)) * 1000) / 1000
      : null;
  const bmiStart = start + 48;
  return {
    kind: "video",
    width: dv.getInt32(bmiStart + 4, true),
    height: dv.getInt32(bmiStart + 8, true),
    bitRate,
    bitErrorRate,
    frameRate,
    bitCount: dv.getUint16(bmiStart + 14, true),
    compression: fourCcFromNumber(dv.getUint32(bmiStart + 16, true)),
    imageSize: dv.getUint32(bmiStart + 20, true),
    extraDataSize: length > 88 ? length - 88 : 0,
    truncated
  };
};

export const parseFileProperties = (
  dv: DataView,
  start: number,
  length: number,
  issues: string[]
): AsfFileProperties | null => {
  if (length < 80) {
    issues.push("File properties object is too small to read mandatory fields.");
    return null;
  }
  const fileSize = numberOrString(readUint64(dv, start + 16));
  const creationRaw = readUint64(dv, start + 24);
  const playDuration = numberOrString(readUint64(dv, start + 40));
  const flags = dv.getUint32(start + 64, true);
  return {
    fileId: guidToString(dv, start),
    fileSize,
    creationDate: filetimeToIso(creationRaw),
    dataPackets: numberOrString(readUint64(dv, start + 32)),
    playDuration,
    sendDuration: numberOrString(readUint64(dv, start + 48)),
    prerollMs: numberOrString(readUint64(dv, start + 56)),
    flags,
    broadcast: (flags & 0x1) !== 0,
    seekable: (flags & 0x2) !== 0,
    minPacketSize: dv.getUint32(start + 68, true),
    maxPacketSize: dv.getUint32(start + 72, true),
    maxBitrate: dv.getUint32(start + 76, true),
    durationSeconds: hundredNsToSeconds(playDuration)
  };
};

export const parseStreamProperties = (
  dv: DataView,
  start: number,
  length: number,
  issues: string[]
): AsfStreamProperties | null => {
  const truncated = length < 54;
  if (length < 24) {
    issues.push("Stream properties object is too small to read identifiers.");
    return null;
  }
  const streamType = guidToString(dv, start);
  const typeSpecificDataLength = length >= 44 ? dv.getUint32(start + 40, true) : null;
  const flags = length >= 50 ? dv.getUint16(start + 48, true) : null;
  const typeSpecificStart = start + 54;
  const availableSpecific = Math.max(
    0,
    Math.min(
      typeSpecificDataLength ?? 0,
      dv.byteLength - typeSpecificStart,
      start + length - typeSpecificStart
    )
  );
  let typeSpecific: AsfStreamFormat | null = null;
  if (streamType === STREAM_TYPE_AUDIO) {
    typeSpecific = parseAudioFormat(dv, typeSpecificStart, availableSpecific, issues);
  } else if (streamType === STREAM_TYPE_VIDEO) {
    typeSpecific = parseVideoFormat(dv, typeSpecificStart, availableSpecific, issues);
  } else if (typeSpecificDataLength != null) {
    typeSpecific = { kind: "unknown", note: `${typeSpecificDataLength} bytes of opaque data` };
  }
  return {
    streamType,
    streamTypeName: STREAM_TYPE_NAMES[streamType ?? ""] || "Unknown stream",
    errorCorrectionType: guidToString(dv, start + 16),
    timeOffset: numberOrString(readUint64(dv, start + 32)),
    typeSpecificDataLength,
    errorCorrectionDataLength: length >= 48 ? dv.getUint32(start + 44, true) : null,
    flags,
    streamNumber: flags != null ? flags & 0x7f : null,
    encrypted: flags != null ? (flags & 0x8000) !== 0 : null,
    reserved: length >= 54 ? dv.getUint32(start + 50, true) : null,
    typeSpecific,
    truncated
  };
};

export const parseDataObject = (
  dv: DataView,
  start: number,
  length: number,
  offset: number,
  size: number | null,
  issues: string[]
): AsfDataObject | null => {
  if (length < 26) {
    issues.push("Data object is truncated.");
    return null;
  }
  return {
    fileId: guidToString(dv, start),
    totalPackets: numberOrString(readUint64(dv, start + 16)),
    reserved: dv.getUint16(start + 24, true),
    offset,
    size,
    truncated: size == null
  };
};
