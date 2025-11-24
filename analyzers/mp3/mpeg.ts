// @ts-nocheck
"use strict";

import {
  BITRATES,
  CHANNEL_MODE,
  EMPHASIS,
  MAX_FRAME_SCAN,
  MODE_EXTENSION_LAYER_III,
  MPEG_LAYER,
  MPEG_VERSION,
  SAMPLE_RATES,
  XING_FLAG_BYTES,
  XING_FLAG_FRAMES,
  XING_FLAG_QUALITY,
  XING_FLAG_TOC
} from "./constants.js";
import { readAsciiString } from "../../binary-utils.js";

function samplesPerFrame(versionBits, layerBits) {
  if (layerBits === 0x3) return 384;
  if (layerBits === 0x2) return 1152;
  if (layerBits === 0x1) return versionBits === 0x3 ? 1152 : 576;
  return null;
}

function frameLengthBytes(versionBits, layerBits, bitrateKbps, sampleRate, padding) {
  const samples = samplesPerFrame(versionBits, layerBits);
  if (!samples || !bitrateKbps || !sampleRate) return null;
  const base = (samples * bitrateKbps * 1000) / (8 * sampleRate);
  return Math.floor(base + (padding ? 1 : 0));
}

function decodeModeExtension(layerBits, modeExtension) {
  if (layerBits !== 0x1) return null;
  return MODE_EXTENSION_LAYER_III.get(modeExtension) || null;
}

export function parseFrameHeader(dv, offset) {
  if (offset + 4 > dv.byteLength) return null;
  const header = dv.getUint32(offset, false);
  const syncWord = (header >>> 21) & 0x7ff;
  if (syncWord !== 0x7ff) return null;
  const versionBits = (header >> 19) & 0x3;
  const layerBits = (header >> 17) & 0x3;
  if (versionBits === 0x1 || layerBits === 0x0) return null;
  const bitrateIndex = (header >> 12) & 0xf;
  const sampleRateIndex = (header >> 10) & 0x3;
  if (bitrateIndex === 0x0 || bitrateIndex === 0xf || sampleRateIndex === 0x3) return null;
  const padding = ((header >> 9) & 0x1) === 1;
  const channelModeBits = (header >> 6) & 0x3;
  const emphasisCode = header & 0x3;
  const versionKey = versionBits === 0x2 || versionBits === 0x0 ? 0x2 : versionBits;
  const bitrateTable = BITRATES[versionKey][layerBits];
  const bitrateKbps = bitrateTable ? bitrateTable[bitrateIndex] : null;
  const sampleRateTable = SAMPLE_RATES[versionBits];
  const sampleRate = sampleRateTable ? sampleRateTable[sampleRateIndex] : null;
  const length = frameLengthBytes(versionBits, layerBits, bitrateKbps, sampleRate, padding);
  return {
    offset,
    rawHeader: header,
    versionBits,
    versionLabel: MPEG_VERSION.get(versionBits) || "Reserved",
    layerBits,
    layerLabel: MPEG_LAYER.get(layerBits) || "Reserved",
    hasCrc: ((header >> 16) & 0x1) === 0,
    bitrateKbps,
    sampleRate,
    padding,
    privateBit: ((header >> 8) & 0x1) === 1,
    channelModeBits,
    channelMode: CHANNEL_MODE.get(channelModeBits) || "Unknown",
    modeExtension: decodeModeExtension(layerBits, (header >> 4) & 0x3),
    copyright: ((header >> 3) & 0x1) === 1,
    original: ((header >> 2) & 0x1) === 1,
    emphasis: EMPHASIS.get(emphasisCode) || "Unknown",
    frameLengthBytes: length,
    samplesPerFrame: samplesPerFrame(versionBits, layerBits)
  };
}

export function findFirstFrame(dv, startOffset, issues) {
  const limit = Math.min(dv.byteLength - 4, startOffset + MAX_FRAME_SCAN);
  for (let offset = startOffset; offset <= limit; offset += 1) {
    const frame = parseFrameHeader(dv, offset);
    if (frame) {
      if (offset > startOffset + 32768) {
        issues.push("First MPEG frame header found unusually far into the file.");
      }
      return frame;
    }
  }
  return null;
}

export function validateNextFrame(dv, firstFrame, issues) {
  if (!firstFrame || !firstFrame.frameLengthBytes) return false;
  const nextOffset = firstFrame.offset + firstFrame.frameLengthBytes;
  if (nextOffset + 4 > dv.byteLength) {
    issues.push("Second MPEG frame cannot be validated (file too small).");
    return false;
  }
  const second = parseFrameHeader(dv, nextOffset);
  if (!second) {
    issues.push("Expected MPEG frame at next offset but header was invalid.");
    return false;
  }
  if (second.versionBits !== firstFrame.versionBits || second.layerBits !== firstFrame.layerBits) {
    issues.push("Consecutive MPEG frame headers disagree on version/layer.");
    return false;
  }
  return true;
}

function sideInfoSize(versionBits, channelModeBits) {
  const isMono = channelModeBits === 0x3;
  if (versionBits === 0x3) return isMono ? 17 : 32;
  return isMono ? 9 : 17;
}

function parseXingOrInfo(dv, frame) {
  const start = frame.offset + 4 + sideInfoSize(frame.versionBits, frame.channelModeBits);
  if (start + 8 > dv.byteLength) return null;
  const tag = readAsciiString(dv, start, 4);
  if (tag !== "Xing" && tag !== "Info") return null;
  const flags = dv.getUint32(start + 4, false);
  let cursor = start + 8;
  const frames = (flags & XING_FLAG_FRAMES) !== 0 && cursor + 4 <= dv.byteLength
    ? dv.getUint32(cursor, false)
    : null;
  cursor += (flags & XING_FLAG_FRAMES) !== 0 ? 4 : 0;
  const bytes = (flags & XING_FLAG_BYTES) !== 0 && cursor + 4 <= dv.byteLength
    ? dv.getUint32(cursor, false)
    : null;
  cursor += (flags & XING_FLAG_BYTES) !== 0 ? 4 : 0;
  if ((flags & XING_FLAG_TOC) !== 0) cursor += 100;
  const quality = (flags & XING_FLAG_QUALITY) !== 0 && cursor + 4 <= dv.byteLength
    ? dv.getUint32(cursor, false)
    : null;
  const lameTagOffset = start + 120;
  const lameEncoder = lameTagOffset + 9 <= dv.byteLength
    ? readAsciiString(dv, lameTagOffset, 9).trim()
    : null;
  return { type: tag, flags, frames, bytes, quality, lameEncoder, vbrDetected: tag === "Xing" };
}

function parseVbri(dv, frame) {
  const start = frame.offset + 4 + 32;
  if (start + 26 > dv.byteLength) return null;
  const tag = readAsciiString(dv, start, 4);
  if (tag !== "VBRI") return null;
  const quality = dv.getUint16(start + 8, false);
  const bytes = dv.getUint32(start + 10, false);
  const frames = dv.getUint32(start + 14, false);
  return { type: tag, flags: null, frames, bytes, quality, lameEncoder: null, vbrDetected: true };
}

export function parseVbrHeader(dv, frame) {
  return parseXingOrInfo(dv, frame) || parseVbri(dv, frame);
}

export function estimateDuration(firstFrame, vbr, audioBytes, issues) {
  if (vbr && vbr.frames && firstFrame && firstFrame.samplesPerFrame && firstFrame.sampleRate) {
    return (vbr.frames * firstFrame.samplesPerFrame) / firstFrame.sampleRate;
  }
  if (vbr && vbr.bytes && firstFrame && firstFrame.bitrateKbps) {
    const duration = (vbr.bytes * 8) / (firstFrame.bitrateKbps * 1000);
    return duration;
  }
  if (firstFrame && firstFrame.bitrateKbps && audioBytes > 0) {
    const bits = Math.max(0, audioBytes) * 8;
    return bits / (firstFrame.bitrateKbps * 1000);
  }
  issues.push("Duration could not be estimated confidently.");
  return null;
}
