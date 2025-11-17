"use strict";
import { readAsciiString } from "../../binary-utils.js";
import {
  BITRATES,
  CHANNEL_MODE,
  EMPHASIS,
  ID3_HEADER_SIZE,
  ID3V1_SIZE,
  MAX_FRAME_SCAN,
  MAX_ID3V2_FRAMES,
  MPEG_LAYER,
  MPEG_VERSION,
  SAMPLE_RATES,
  XING_FLAG_BYTES,
  XING_FLAG_FRAMES,
  XING_FLAG_QUALITY,
  XING_FLAG_TOC
} from "./constants.js";
function decodeSynchsafeInt(dv, offset) {
  if (offset + 4 > dv.byteLength) return null;
  const b0 = dv.getUint8(offset);
  const b1 = dv.getUint8(offset + 1);
  const b2 = dv.getUint8(offset + 2);
  const b3 = dv.getUint8(offset + 3);
  if ((b0 & 0x80) !== 0 || (b1 & 0x80) !== 0 || (b2 & 0x80) !== 0 || (b3 & 0x80) !== 0) {
    return null;
  }
  return (b0 << 21) | (b1 << 14) | (b2 << 7) | b3;
}
function decodeId3v2FrameSize(versionMajor, dv, offset) {
  if (versionMajor === 2) {
    if (offset + 3 > dv.byteLength) return null;
    return (
      (dv.getUint8(offset) << 16) |
      (dv.getUint8(offset + 1) << 8) |
      dv.getUint8(offset + 2)
    );
  }
  if (offset + 4 > dv.byteLength) return null;
  return versionMajor === 4 ? decodeSynchsafeInt(dv, offset) : dv.getUint32(offset, false);
}
function decodeId3Text(encoding, dv, offset, length) {
  if (length <= 0 || offset + length > dv.byteLength) return "";
  if (encoding === 0) return readAsciiString(dv, offset, length).trim();
  const data = new Uint8Array(dv.buffer, dv.byteOffset + offset, length);
  if (encoding === 1 || encoding === 2) {
    const decoder = new TextDecoder(encoding === 1 ? "utf-16" : "utf-16be");
    return decoder.decode(data).replace(/\0/g, "").trim();
  }
  const decoder = new TextDecoder("utf-8");
  return decoder.decode(data).replace(/\0/g, "").trim();
}
function parseId3v2Frames(versionMajor, dv, offset, endOffset, issues) {
  const frames = [];
  const headerSize = versionMajor === 2 ? 6 : 10;
  const idLength = versionMajor === 2 ? 3 : 4;
  let cursor = offset;
  while (cursor + headerSize <= endOffset && frames.length < MAX_ID3V2_FRAMES) {
    const id = readAsciiString(dv, cursor, idLength);
    const zeroId = id.split("").every(ch => ch === "\0");
    if (!id || zeroId) break;
    const sizeOffset = cursor + idLength;
    const size = decodeId3v2FrameSize(versionMajor, dv, sizeOffset);
    if (!size || size < 1 || cursor + headerSize + size > dv.byteLength) break;
    const frameStart = cursor + headerSize;
    const encoding = dv.getUint8(frameStart);
    let value = "";
    if (id.startsWith("T")) {
      value = decodeId3Text(encoding, dv, frameStart + 1, size - 1);
    } else if (id === "COMM" && size > 4) {
      const lang = readAsciiString(dv, frameStart + 1, 3);
      const text = decodeId3Text(encoding, dv, frameStart + 4, size - 4);
      value = `${lang}: ${text}`;
    } else {
      value = `${size} bytes`;
    }
    frames.push({ id, size, value });
    cursor += headerSize + size;
  }
  if (cursor < endOffset && frames.length >= MAX_ID3V2_FRAMES) {
    issues.push(
      `Stopped after ${MAX_ID3V2_FRAMES} ID3v2 frames to avoid huge tags.`
    );
  }
  return frames;
}
function parseId3v2(dv, issues) {
  if (dv.byteLength < ID3_HEADER_SIZE) return null;
  if (readAsciiString(dv, 0, 3) !== "ID3") return null;
  const versionMajor = dv.getUint8(3);
  const versionRevision = dv.getUint8(4);
  const flagsByte = dv.getUint8(5);
  const tagSize = decodeSynchsafeInt(dv, 6);
  if (tagSize == null) {
    issues.push("Invalid ID3v2 tag size (sync-safe decode failed).");
    return null;
  }
  let contentStart = ID3_HEADER_SIZE;
  let contentEnd = ID3_HEADER_SIZE + tagSize;
  let extendedHeaderSize = 0;
  const hasExtendedHeader = (flagsByte & 0x40) !== 0;
  const footerPresent = (flagsByte & 0x10) !== 0;
  if (hasExtendedHeader) {
    const extSize = decodeId3v2FrameSize(versionMajor, dv, contentStart);
    if (extSize && extSize + contentStart <= dv.byteLength) {
      extendedHeaderSize = versionMajor === 3 ? extSize + 4 : extSize;
      contentStart += extendedHeaderSize;
    } else {
      issues.push("Extended ID3v2 header is truncated or invalid.");
    }
  }
  if (footerPresent) contentEnd += ID3_HEADER_SIZE;
  if (contentEnd > dv.byteLength) {
    issues.push("ID3v2 tag size exceeds file length.");
    contentEnd = dv.byteLength;
  }
  const frames = parseId3v2Frames(versionMajor, dv, contentStart, contentEnd, issues);
  return {
    versionMajor,
    versionRevision,
    flags: {
      unsynchronisation: (flagsByte & 0x80) !== 0,
      extendedHeader: hasExtendedHeader,
      experimental: (flagsByte & 0x20) !== 0,
      footerPresent
    },
    size: tagSize,
    tagSize: contentEnd,
    extendedHeaderSize,
    frames
  };
}
function readId3v1String(dv, offset, length) {
  return readAsciiString(dv, offset, length).trim();
}
function parseId3v1(dv) {
  if (dv.byteLength < ID3V1_SIZE) return null;
  const start = dv.byteLength - ID3V1_SIZE;
  if (readAsciiString(dv, start, 3) !== "TAG") return null;
  return {
    title: readId3v1String(dv, start + 3, 30),
    artist: readId3v1String(dv, start + 33, 30),
    album: readId3v1String(dv, start + 63, 30),
    year: readId3v1String(dv, start + 93, 4),
    comment: readId3v1String(dv, start + 97, 30),
    genreCode: dv.getUint8(start + 127)
  };
}
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
function parseFrameHeader(dv, offset) {
  if (offset + 4 > dv.byteLength) return null;
  const header = dv.getUint32(offset, false);
  if ((header & 0xffe00000) !== 0xffe00000) return null;
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
  const length = frameLengthBytes(
    versionBits,
    layerBits,
    bitrateKbps,
    sampleRate,
    padding
  );
  return {
    offset,
    versionBits,
    versionLabel: MPEG_VERSION.get(versionBits) || "Reserved",
    layerBits,
    layerLabel: MPEG_LAYER.get(layerBits) || "Reserved",
    protectedByCrc: ((header >> 16) & 0x1) === 0,
    bitrateKbps,
    sampleRate,
    padding,
    privateBit: ((header >> 8) & 0x1) === 1,
    channelModeBits,
    channelMode: CHANNEL_MODE.get(channelModeBits) || "Unknown",
    modeExtension: (header >> 4) & 0x3,
    copyright: ((header >> 3) & 0x1) === 1,
    original: ((header >> 2) & 0x1) === 1,
    emphasis: EMPHASIS.get(emphasisCode) || "Unknown",
    frameLength: length,
    samplesPerFrame: samplesPerFrame(versionBits, layerBits)
  };
}
function findFirstFrame(dv, startOffset) {
  const limit = Math.min(dv.byteLength - 4, startOffset + MAX_FRAME_SCAN);
  for (let offset = startOffset; offset <= limit; offset += 1) {
    const frame = parseFrameHeader(dv, offset);
    if (frame) return frame;
  }
  return null;
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
  return { tag, frames, bytes, quality, lameEncoder };
}
function parseVbri(dv, frame) {
  const start = frame.offset + 4 + 32;
  if (start + 26 > dv.byteLength) return null;
  const tag = readAsciiString(dv, start, 4);
  if (tag !== "VBRI") return null;
  const quality = dv.getUint16(start + 8, false);
  const bytes = dv.getUint32(start + 10, false);
  const frames = dv.getUint32(start + 14, false);
  return { tag, frames, bytes, quality, lameEncoder: null };
}
function parseVbrHeader(dv, frame) {
  return parseXingOrInfo(dv, frame) || parseVbri(dv, frame);
}
function estimateDuration(firstFrame, audioBytes, vbr) {
  if (vbr && vbr.frames && firstFrame && firstFrame.samplesPerFrame && firstFrame.sampleRate) {
    return (vbr.frames * firstFrame.samplesPerFrame) / firstFrame.sampleRate;
  }
  if (firstFrame && firstFrame.bitrateKbps && audioBytes > 0) {
    const bits = audioBytes * 8;
    return bits / (firstFrame.bitrateKbps * 1000);
  }
  return null;
}
export function probeMp3(dv) {
  if (dv.byteLength < 2) return false;
  if (dv.byteLength >= 3 && readAsciiString(dv, 0, 3) === "ID3") return true;
  const b0 = dv.getUint8(0);
  const b1 = dv.getUint8(1);
  return b0 === 0xff && (b1 & 0xe0) === 0xe0 && b1 !== 0xfe;
}
export async function parseMp3(file) {
  const buffer = await file.arrayBuffer();
  const dv = new DataView(buffer);
  if (dv.byteLength < 4) return null;
  const issues = [];
  const id3v2 = parseId3v2(dv, issues);
  const id3v1 = parseId3v1(dv);
  const audioStart = id3v2 ? id3v2.tagSize : 0;
  const audioEnd = id3v1 ? dv.byteLength - ID3V1_SIZE : dv.byteLength;
  const firstFrame = findFirstFrame(dv, audioStart);
  if (!firstFrame) issues.push("No MPEG audio frame found near the start of the file.");
  const vbr = firstFrame ? parseVbrHeader(dv, firstFrame) : null;
  const audioBytes = firstFrame ? Math.max(0, audioEnd - firstFrame.offset) : 0;
  const durationSeconds = estimateDuration(firstFrame, audioBytes, vbr);
  return {
    size: dv.byteLength,
    id3v2,
    id3v1,
    firstFrame,
    vbr,
    audioBytes,
    durationSeconds,
    issues
  };
}
