"use strict";

import { readAsciiString } from "../../binary-utils.js";
import {
  ID3_HEADER_SIZE,
  ID3V1_GENRES,
  ID3V1_SIZE,
  MAX_EMBEDDED_IMAGE_BYTES,
  MAX_ID3V2_FRAMES,
  PICTURE_TYPES
} from "./constants.js";
import {
  decodeId3Text,
  decodeId3v2FrameSize,
  decodeSynchsafeInt,
  readZeroTerminatedString,
  safeHexPreview
} from "./utils.js";
import type {
  Id3v1Tag,
  Id3v2Frame,
  Id3v2FrameDetail,
  Id3v2FrameFlagSet,
  Id3v2Tag
} from "./types.js";

function parseId3v2FrameFlags(versionMajor: number, dv: DataView, offset: number): Id3v2FrameFlagSet {
  if (versionMajor === 2) return {};
  if (offset + 2 > dv.byteLength) return {};
  const status = dv.getUint8(offset);
  const format = dv.getUint8(offset + 1);
  return {
    tagAlterPreservation: (status & 0x80) !== 0,
    fileAlterPreservation: (status & 0x40) !== 0,
    readOnly: (status & 0x20) !== 0,
    compression: (format & 0x80) !== 0,
    encryption: (format & 0x40) !== 0,
    groupingIdentity: (format & 0x20) !== 0,
    unsynchronisation: (format & 0x02) !== 0,
    dataLengthIndicator: (format & 0x01) !== 0
  };
}

function parseApicFrame(
  frameStart: number,
  size: number,
  dv: DataView,
  issues: string[],
  encoding: number
): Id3v2FrameDetail | null {
  const mime = readZeroTerminatedString(dv, frameStart + 1, size - 1, 0);
  const mimeEnd = frameStart + 1 + mime.length + 1;
  if (mimeEnd + 1 > dv.byteLength) return null;
  const pictureTypeCode = dv.getUint8(mimeEnd);
  const descOffset = mimeEnd + 1;
  const desc = readZeroTerminatedString(
    dv,
    descOffset,
    size - (descOffset - frameStart),
    encoding
  );
  const descEnd = descOffset + desc.length + 1;
  const imageDataLength = Math.max(0, size - (descEnd - frameStart));
  if (imageDataLength > MAX_EMBEDDED_IMAGE_BYTES) {
    issues.push(`Embedded image is very large (${imageDataLength} bytes).`);
  }
  return {
    type: "apic",
    mimeType: mime || "(unknown)",
    pictureType: PICTURE_TYPES[pictureTypeCode] || `Type ${pictureTypeCode}`,
    description: desc,
    imageSize: imageDataLength
  };
}

function parseTextFrame(
  id: string,
  frameStart: number,
  size: number,
  dv: DataView,
  encoding: number
): Id3v2FrameDetail {
  const value = decodeId3Text(encoding, dv, frameStart + 1, size - 1);
  return { type: "text", id, value };
}

function parseTxxxFrame(
  frameStart: number,
  size: number,
  dv: DataView,
  encoding: number
): Id3v2FrameDetail {
  const description = readZeroTerminatedString(dv, frameStart + 1, size - 1, encoding);
  const descEnd = frameStart + 1 + description.length + 1;
  const value = decodeId3Text(encoding, dv, descEnd, size - (descEnd - frameStart));
  return { type: "text", id: "TXXX", description, value };
}

function parseWxxxFrame(
  frameStart: number,
  size: number,
  dv: DataView,
  encoding: number
): Id3v2FrameDetail {
  const description = readZeroTerminatedString(dv, frameStart + 1, size - 1, encoding);
  const descEnd = frameStart + 1 + description.length + 1;
  const url = decodeId3Text(0, dv, descEnd, size - (descEnd - frameStart));
  return { type: "url", id: "WXXX", description, url };
}

function parseCommentFrame(
  frameStart: number,
  size: number,
  dv: DataView,
  encoding: number
): Id3v2FrameDetail {
  if (size < 4) return { type: "text", id: "COMM", value: "(truncated)" };
  const lang = readAsciiString(dv, frameStart + 1, 3);
  const value = decodeId3Text(encoding, dv, frameStart + 4, size - 4);
  return { type: "text", id: "COMM", value: `${lang}: ${value}` };
}

function parseGenericFrame(id: string, frameStart: number, size: number, dv: DataView): Id3v2FrameDetail {
  return { type: "binary", id, preview: safeHexPreview(dv, frameStart, size) };
}

function parseId3v2Frames(
  versionMajor: number,
  dv: DataView,
  offset: number,
  endOffset: number,
  issues: string[]
): Id3v2Frame[] {
  const frames: Id3v2Frame[] = [];
  const headerSize = versionMajor === 2 ? 6 : 10;
  const idLength = versionMajor === 2 ? 3 : 4;
  let cursor = offset;
  while (cursor + headerSize <= endOffset && frames.length < MAX_ID3V2_FRAMES) {
    const id = readAsciiString(dv, cursor, idLength);
    const zeroId = id.split("").every(ch => ch === "\0");
    if (!id || zeroId) break;
    const sizeOffset = cursor + idLength;
    const size = decodeId3v2FrameSize(versionMajor, dv, sizeOffset);
    const flagsOffset = sizeOffset + (versionMajor === 2 ? 3 : 4);
    if (!size || size < 1 || cursor + headerSize + size > dv.byteLength) {
      issues.push(`Stopped at invalid ID3v2 frame ${id}.`);
      break;
    }
    const frameStart = cursor + headerSize;
    if (frameStart + size > endOffset) {
      issues.push(`ID3v2 frame ${id} is truncated.`);
      break;
    }
    const encoding = dv.getUint8(frameStart);
    const flags = parseId3v2FrameFlags(versionMajor, dv, flagsOffset);
    let detail: Id3v2FrameDetail | null = null;
    if (id === "TXXX") detail = parseTxxxFrame(frameStart, size, dv, encoding);
    else if (id === "WXXX") detail = parseWxxxFrame(frameStart, size, dv, encoding);
    else if (id === "APIC") detail = parseApicFrame(frameStart, size, dv, issues, encoding);
    else if (id.startsWith("T")) detail = parseTextFrame(id, frameStart, size, dv, encoding);
    else if (id === "COMM") detail = parseCommentFrame(frameStart, size, dv, encoding);
    else if (id.startsWith("W")) {
      const url = decodeId3Text(0, dv, frameStart, size);
      detail = { type: "url", id, url };
    }
    const frame = detail || parseGenericFrame(id, frameStart, size, dv);
    frames.push({
      id,
      size,
      flags,
      detail: frame
    });
    cursor += headerSize + size;
  }
  if (cursor < endOffset && frames.length >= MAX_ID3V2_FRAMES) {
    issues.push(`Stopped after ${MAX_ID3V2_FRAMES} ID3v2 frames to avoid huge tags.`);
  }
  return frames;
}

export function parseId3v2(dv: DataView, issues: string[]): Id3v2Tag | null {
  if (dv.byteLength < 10) return null;
  if (readAsciiString(dv, 0, 3) !== "ID3") return null;
  const versionMajor = dv.getUint8(3);
  const versionRevision = dv.getUint8(4);
  const flagsByte = dv.getUint8(5);
  const tagSize = decodeSynchsafeInt(dv, 6);
  const flags = {
    unsynchronisation: (flagsByte & 0x80) !== 0,
    extendedHeader: (flagsByte & 0x40) !== 0,
    experimental: (flagsByte & 0x20) !== 0,
    footerPresent: (flagsByte & 0x10) !== 0
  };
  if (tagSize == null) {
    issues.push("Invalid ID3v2 tag size (sync-safe decode failed).");
    return {
      versionMajor,
      versionRevision,
      flags,
      size: 0,
      tagTotalSize: ID3_HEADER_SIZE,
      frames: [],
      extendedHeaderSize: 0
    };
  }
  const headerSize = 10;
  let contentStart = headerSize;
  let contentEnd = headerSize + tagSize;
  let extendedHeaderSize = 0;
  if (flags.extendedHeader) {
    const extSize = decodeId3v2FrameSize(versionMajor, dv, contentStart);
    if (extSize && extSize + contentStart <= dv.byteLength) {
      extendedHeaderSize = versionMajor === 3 ? extSize + 4 : extSize;
      contentStart += extendedHeaderSize;
    } else {
      issues.push("Extended ID3v2 header is truncated or invalid.");
    }
  }
  if (flags.footerPresent) contentEnd += headerSize;
  const declaredTotal = contentEnd;
  if (contentEnd > dv.byteLength) {
    issues.push("ID3v2 tag size exceeds file length.");
    contentEnd = dv.byteLength;
  }
  const frames = parseId3v2Frames(versionMajor, dv, contentStart, contentEnd, issues);
  if (flags.unsynchronisation) {
    issues.push("ID3v2 unsynchronisation flag is set; payload may be transformed.");
  }
  return {
    versionMajor,
    versionRevision,
    flags,
    size: tagSize,
    tagTotalSize: Math.min(declaredTotal, dv.byteLength),
    extendedHeaderSize,
    frames,
    hasFooter: flags.footerPresent
  };
}

function readId3v1String(dv: DataView, offset: number, length: number): string {
  return readAsciiString(dv, offset, length).replace(/\0/g, "").trim();
}

export function parseId3v1(dv: DataView): Id3v1Tag | null {
  if (dv.byteLength < ID3V1_SIZE) return null;
  const start = dv.byteLength - ID3V1_SIZE;
  if (readAsciiString(dv, start, 3) !== "TAG") return null;
  const trackIndicator = dv.getUint8(start + 125);
  const track = trackIndicator === 0 ? dv.getUint8(start + 126) : null;
  const genreCode = dv.getUint8(start + 127);
  const genreName = ID3V1_GENRES[genreCode] || null;
  const commentLength = track != null ? 28 : 30;
  const comment = readId3v1String(dv, start + 97, commentLength);
  return {
    title: readId3v1String(dv, start + 3, 30),
    artist: readId3v1String(dv, start + 33, 30),
    album: readId3v1String(dv, start + 63, 30),
    year: readId3v1String(dv, start + 93, 4),
    comment,
    trackNumber: track,
    genreCode,
    genreName
  };
}
