"use strict";

import type { Issues, WebmCodecPrivateVorbis } from "./types.js";

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: false });

export const parseVorbisCodecPrivate = (
  dv: DataView,
  offset: number,
  size: number,
  issues: Issues
): WebmCodecPrivateVorbis => {
  const maxLength = Math.min(size, dv.byteLength - offset);
  if (maxLength <= 0) {
    issues.push("Vorbis CodecPrivate is empty.");
    return { headerPacketLengths: null, vendor: null, truncated: true };
  }
  const bytes = new Uint8Array(dv.buffer, dv.byteOffset + offset, maxLength);
  let cursor = 0;
  let truncated = false;

  if (bytes[cursor] !== 0x02) {
    issues.push("Vorbis CodecPrivate has unexpected packet count marker.");
    return { headerPacketLengths: null, vendor: null, truncated: true };
  }
  cursor += 1;

  const readLacedLength = (): number | null => {
    let length = 0;
    while (true) {
      if (cursor >= bytes.length) {
        truncated = true;
        return null;
      }
      const value = bytes[cursor] ?? 0;
      cursor += 1;
      length += value ?? 0;
      if (value !== 0xff) break;
    }
    return length;
  };

  const idLength = readLacedLength();
  const commentLength = readLacedLength();
  if (idLength == null || commentLength == null) {
    issues.push("Vorbis CodecPrivate header lengths are truncated.");
    return { headerPacketLengths: null, vendor: null, truncated: true };
  }

  const idOffset = cursor;
  const commentOffset = idOffset + idLength;
  const setupOffset = commentOffset + commentLength;
  if (setupOffset > bytes.length) {
    truncated = true;
    issues.push("Vorbis CodecPrivate packets exceed available data.");
    return { headerPacketLengths: null, vendor: null, truncated: true };
  }
  const setupLength = bytes.length - setupOffset;
  const headerPacketLengths: [number, number, number] = [idLength, commentLength, setupLength];

  let vendor: string | null = null;
  if (commentLength > 0) {
    const end = commentOffset + commentLength;
    if (end <= bytes.length && commentLength >= 11) {
      let commentCursor = commentOffset;
      const packetType = bytes[commentCursor];
      const magic = UTF8_DECODER.decode(bytes.subarray(commentCursor + 1, commentCursor + 7));
      if (packetType === 0x03 && magic === "vorbis") {
        commentCursor += 7;
        if (commentCursor + 4 <= end) {
          const view = new DataView(bytes.buffer, bytes.byteOffset + commentCursor, 4);
          const vendorLength = view.getUint32(0, true);
          commentCursor += 4;
          const vendorEnd = commentCursor + vendorLength;
          if (vendorEnd <= end) {
            vendor = UTF8_DECODER.decode(bytes.subarray(commentCursor, vendorEnd));
          } else {
            truncated = true;
            issues.push("Vorbis vendor string is truncated inside CodecPrivate.");
          }
        } else {
          truncated = true;
          issues.push("Vorbis CodecPrivate comment header is too short for vendor length.");
        }
      } else {
        issues.push("Vorbis CodecPrivate comment header is missing expected signature.");
      }
    } else {
      truncated = true;
      issues.push("Vorbis CodecPrivate comment header is too short.");
    }
  }

  return { headerPacketLengths, vendor, truncated };
};
