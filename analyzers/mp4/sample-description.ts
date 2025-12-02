"use strict";

import { readEsds } from "./audio-codecs.js";
import { readAv1C, readAvcC, readHvcC, parsePasp, readVpcc } from "./codecs.js";
import { readBoxHeaderFromView, readFixed1616, toFourCcFromView } from "./boxes.js";
import type { Mp4CodecDetails } from "./types.js";

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

  const isVisual =
    handlerType === "vide" ||
    format === "avc1" ||
    format === "avc3" ||
    format === "hvc1" ||
    format === "hev1" ||
    format === "vp09" ||
    format === "vp08" ||
    format === "av01";
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
      const payloadStart = childOffset + childHeader.headerSize;
      const payloadSize = childHeader.size - childHeader.headerSize;
      if (childHeader.type === "esds") {
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
