"use strict";

import { readAsciiString } from "../../binary-utils.js";

function findSignatureBackward(dv, signature, searchBackBytes) {
  const start = Math.max(0, dv.byteLength - searchBackBytes);
  for (let i = dv.byteLength - signature.length; i >= start; i -= 1) {
    if (readAsciiString(dv, i, signature.length) === signature) return i;
  }
  return -1;
}

export function parseApeTag(dv, issues) {
  const footerSize = 32;
  if (dv.byteLength < footerSize) return null;
  const offset = findSignatureBackward(dv, "APETAGEX", 1024);
  if (offset === -1) return null;
  if (offset + footerSize > dv.byteLength) return null;
  const version = dv.getUint32(offset + 8, true);
  const size = dv.getUint32(offset + 12, true);
  const itemCount = dv.getUint32(offset + 16, true);
  if (size === 0 || offset + size > dv.byteLength) {
    issues.push("APE tag is truncated or declares an invalid size.");
  }
  return { offset, size, version, itemCount };
}

export function parseLyrics3(dv, issues) {
  const endMarkerOffset = findSignatureBackward(dv, "LYRICS200", 2048);
  if (endMarkerOffset !== -1 && endMarkerOffset >= 6) {
    const sizeString = readAsciiString(dv, endMarkerOffset - 6, 6);
    const parsed = Number.parseInt(sizeString, 10);
    const size = Number.isFinite(parsed) ? parsed : null;
    const startOffset = size != null ? endMarkerOffset - 6 - size : null;
    if (size == null || startOffset == null || startOffset < 0) {
      issues.push("Lyrics3 v2.00 size field is invalid.");
    }
    return { version: "2.00", offset: startOffset, sizeEstimate: size };
  }
  const legacyEnd = findSignatureBackward(dv, "LYRICSEND", 2048);
  const legacyStart = findSignatureBackward(dv, "LYRICSBEGIN", 2048);
  if (legacyEnd !== -1 && legacyStart !== -1 && legacyStart < legacyEnd) {
    return {
      version: "1.x",
      offset: legacyStart,
      sizeEstimate: legacyEnd - legacyStart + "LYRICSEND".length
    };
  }
  if (legacyEnd !== -1 || legacyStart !== -1) {
    issues.push("Possible truncated Lyrics3 tag detected.");
  }
  return null;
}
