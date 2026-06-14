"use strict";

import { readEsds } from "./audio-codecs.js";
import { readAv1C, readAvcC, readHvcC, parsePasp, readVpcc } from "./codecs.js";
import { readBoxHeaderFromView, readFixed1616, toFourCcFromView } from "./boxes.js";
import type { Mp4CodecDetails } from "./types.js";

const isVisualSampleEntry = (handlerType: string | null, format: string): boolean =>
  handlerType === "vide" ||
  format === "avc1" ||
  format === "avc3" ||
  format === "hvc1" ||
  format === "hev1" ||
  format === "vp09" ||
  format === "vp08" ||
  format === "av01";

const isAudioSampleEntry = (handlerType: string | null, format: string): boolean =>
  handlerType === "soun" || format === "mp4a" || format === "ac-3" || format === "ec-3";

const createBareCodecDetails = (format: string): Mp4CodecDetails => ({
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
});

const readCompressorName = (view: DataView, entryStart: number): string | null => {
  const compressorNameLength = view.getUint8(entryStart + 42);
  return compressorNameLength > 0 && compressorNameLength < 31
    ? new TextDecoder().decode(
        new Uint8Array(view.buffer, view.byteOffset + entryStart + 43, compressorNameLength)
      )
    : null;
};

const readVisualCodecDetails = (
  view: DataView,
  entryStart: number,
  entryEnd: number,
  format: string,
  issues: string[]
): Mp4CodecDetails => {
  let codecDetails: Mp4CodecDetails | null = null;
  let pixelAspectRatio: string | null = null;
  let childOffset = entryStart + 78;
  while (childOffset + 8 <= entryEnd) {
    const childHeader = readBoxHeaderFromView(view, childOffset, childOffset + view.byteOffset, issues);
    if (!childHeader || childHeader.start >= childHeader.end) break;
    const payloadOffset = childOffset + childHeader.headerSize;
    const payloadSize = childHeader.size - childHeader.headerSize;
    if (childHeader.type === "avcC") codecDetails = readAvcC(view, payloadOffset, payloadSize, format || "avc1");
    else if (childHeader.type === "hvcC") codecDetails = readHvcC(view, payloadOffset, payloadSize, format || "hvc1");
    else if (childHeader.type === "av1C") codecDetails = readAv1C(view, payloadOffset, payloadSize, format || "av01");
    else if (childHeader.type === "vpcC") codecDetails = readVpcc(view, payloadOffset, payloadSize, format || "vp09");
    else if (childHeader.type === "pasp") pixelAspectRatio = parsePasp(view, payloadOffset, payloadSize) || pixelAspectRatio;
    childOffset += childHeader.size;
  }
  const width = view.getUint16(entryStart + 24, false);
  const height = view.getUint16(entryStart + 26, false);
  const depth = view.getUint16(entryStart + 74, false);
  const compressorName = readCompressorName(view, entryStart);
  const details = codecDetails ?? createBareCodecDetails(format);
  details.width = details.width ?? width;
  details.height = details.height ?? height;
  details.pixelAspectRatio = details.pixelAspectRatio ?? pixelAspectRatio;
  details.description = details.description ?? compressorName;
  details.bitDepth = details.bitDepth ?? (depth || null);
  return details;
};

const readAudioCodecDetails = (
  view: DataView,
  entryStart: number,
  entryEnd: number,
  format: string,
  issues: string[]
): Mp4CodecDetails => {
  const channelCount = view.getUint16(entryStart + 16, false);
  const sampleSize = view.getUint16(entryStart + 18, false);
  const sampleRate = readFixed1616(view.getUint32(entryStart + 24, false));
  let codecDetails: Mp4CodecDetails | null = null;
  let childOffset = entryStart + 28;
  while (childOffset + 8 <= entryEnd) {
    const childHeader = readBoxHeaderFromView(view, childOffset, childOffset + view.byteOffset, issues);
    if (!childHeader || childHeader.start >= childHeader.end) break;
    if (childHeader.type === "esds") {
      codecDetails = readEsds(
        view,
        childOffset + childHeader.headerSize,
        childHeader.size - childHeader.headerSize,
        format || "mp4a",
        sampleRate,
        channelCount
      );
    }
    childOffset += childHeader.size;
  }
  const details = codecDetails ?? createBareCodecDetails(format);
  details.channels = details.channels ?? (channelCount || null);
  details.sampleRate = details.sampleRate ?? (sampleRate || null);
  details.bitDepth = details.bitDepth ?? (sampleSize || null);
  return details;
};

export const parseStsd = (
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
  if (isVisualSampleEntry(handlerType, format)) {
    if (remaining < 70) {
      issues.push("Visual sample entry truncated.");
      return null;
    }
    return readVisualCodecDetails(view, entryStart, entryEnd, format, issues);
  }
  if (isAudioSampleEntry(handlerType, format)) {
    if (remaining < 20) {
      issues.push("Audio sample entry truncated.");
      return null;
    }
    return readAudioCodecDetails(view, entryStart, entryEnd, format, issues);
  }
  return createBareCodecDetails(format);
};
