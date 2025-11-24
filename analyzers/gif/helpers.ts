"use strict";

import type {
  GifApplicationExtension,
  GifComment,
  GifGraphicControlExtension
} from "./types.js";

export const DISPOSAL_METHODS: string[] = [
  "No disposal specified",
  "Keep previous frame (do not dispose)",
  "Restore to background color",
  "Restore to previous frame",
  "Reserved",
  "Reserved",
  "Reserved",
  "Reserved"
];

export function readAsciiRange(dv: DataView, offset: number, length: number): string {
  let text = "";
  for (let i = 0; i < length && offset + i < dv.byteLength; i += 1) {
    const code = dv.getUint8(offset + i);
    if (code === 0) break;
    text += String.fromCharCode(code);
  }
  return text;
}

export function bytesToAscii(bytes: ArrayLike<number>): string {
  let text = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const code = bytes[i];
    if (code === 0) break;
    text += String.fromCharCode(code);
  }
  return text;
}

export interface GifSubBlocks {
  endOffset: number;
  totalSize: number;
  blockCount: number;
  truncated: boolean;
  previewBytes: number[];
}

export interface GifGraphicControlResult {
  gce: GifGraphicControlExtension | null;
  nextOffset: number;
  warning: string | null;
}

export function readSubBlocks(
  dv: DataView,
  offset: number,
  previewLimit = 0
): GifSubBlocks {
  let cursor = offset;
  let totalSize = 0;
  let blockCount = 0;
  let truncated = false;
  const previewBytes: number[] = [];
  while (true) {
    if (cursor >= dv.byteLength) { truncated = true; break; }
    const size = dv.getUint8(cursor);
    cursor += 1;
    if (size === 0) break;
    const remaining = dv.byteLength - cursor;
    if (remaining < size) {
      const available = Math.max(0, remaining);
      totalSize += available;
      const previewRoom = Math.max(0, previewLimit - previewBytes.length);
      for (let i = 0; i < Math.min(available, previewRoom); i += 1) {
        previewBytes.push(dv.getUint8(cursor + i));
      }
      cursor = dv.byteLength;
      truncated = true;
      break;
    }
    blockCount += 1;
    totalSize += size;
    const previewRoom = Math.max(0, previewLimit - previewBytes.length);
    for (let i = 0; i < Math.min(size, previewRoom); i += 1) {
      previewBytes.push(dv.getUint8(cursor + i));
    }
    cursor += size;
  }
  return { endOffset: cursor, totalSize, blockCount, truncated, previewBytes };
}

export interface GifApplicationExtensionResult {
  nextOffset: number;
  info: GifApplicationExtension | null;
  warning: string | null;
}

export function parseGraphicControl(dv: DataView, offset: number): GifGraphicControlResult {
  if (offset + 6 > dv.byteLength) {
    return {
      gce: null,
      nextOffset: dv.byteLength,
      warning: "Truncated graphic control extension."
    };
  }
  const blockSize = dv.getUint8(offset + 2);
  if (blockSize !== 4 || offset + 3 + blockSize >= dv.byteLength) {
    return {
      gce: null,
      nextOffset: dv.byteLength,
      warning: "Invalid graphic control block."
    };
  }
  const packed = dv.getUint8(offset + 3);
  const delay = dv.getUint16(offset + 4, true);
  const transparentIndex = dv.getUint8(offset + 6);
  const terminatorOffset = offset + 3 + blockSize;
  const hasTerminator =
    terminatorOffset < dv.byteLength && dv.getUint8(terminatorOffset) === 0;
  const disposalIndex = (packed >> 2) & 0x07;
  const gce: GifGraphicControlExtension = {
    disposalMethod:
      DISPOSAL_METHODS[disposalIndex] || `Reserved (${disposalIndex})`,
    delayMs: delay * 10,
    transparentColorIndex: (packed & 0x01) !== 0 ? transparentIndex : null,
    userInputFlag: (packed & 0x02) !== 0
  };
  return {
    gce,
    nextOffset: hasTerminator ? terminatorOffset + 1 : terminatorOffset,
    warning: hasTerminator
      ? null
      : "Graphic control extension missing terminator."
  };
}

export interface GifCommentResult {
  nextOffset: number;
  comment: GifComment;
}

export function parseApplicationExtension(
  dv: DataView,
  offset: number
): GifApplicationExtensionResult {
  const minLength = offset + 14;
  if (minLength > dv.byteLength) {
    return {
      nextOffset: dv.byteLength,
      info: null,
      warning: "Truncated application extension."
    };
  }
  if (dv.getUint8(offset + 2) !== 11) {
    return {
      nextOffset: dv.byteLength,
      info: null,
      warning: "Application extension has invalid block size."
    };
  }
  const id = readAsciiRange(dv, offset + 3, 8);
  const auth = readAsciiRange(dv, offset + 11, 3);
  const subBlocks = readSubBlocks(dv, offset + 14, 8);
  let loopCount = null;
  const preview = subBlocks.previewBytes;
  if (preview.length >= 3 && preview[0] === 1) {
    loopCount = preview[1] | (preview[2] << 8);
  }
  return {
    info: {
      identifier: id,
      authCode: auth,
      loopCount,
      dataSize: subBlocks.totalSize,
      truncated: subBlocks.truncated
    },
    nextOffset: subBlocks.endOffset,
    warning: null
  };
}

export function parseCommentExtension(dv: DataView, offset: number): GifCommentResult {
  const subBlocks = readSubBlocks(dv, offset + 2, 512);
  return {
    nextOffset: subBlocks.endOffset,
    comment: {
      text: bytesToAscii(subBlocks.previewBytes),
      truncated:
        subBlocks.truncated ||
        subBlocks.totalSize > subBlocks.previewBytes.length
    }
  };
}

export interface GifPlainTextResult {
  nextOffset: number;
  warning: string | null;
}

export function parsePlainTextExtension(
  dv: DataView,
  offset: number
): GifPlainTextResult {
  const headerEnd = offset + 2 + 1 + 12;
  if (headerEnd > dv.byteLength) {
    return {
      nextOffset: dv.byteLength,
      warning: "Truncated plain text extension."
    };
  }
  const subBlocks = readSubBlocks(dv, headerEnd, 0);
  return {
    nextOffset: subBlocks.endOffset,
    warning: subBlocks.truncated ? "Plain text extension truncated." : null
  };
}
