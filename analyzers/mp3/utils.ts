// @ts-nocheck
"use strict";

import { readAsciiString } from "../../binary-utils.js";

export function decodeSynchsafeInt(dv, offset) {
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

export function decodeId3v2FrameSize(versionMajor, dv, offset) {
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

export function decodeId3Text(encoding, dv, offset, length) {
  if (length <= 0 || offset + length > dv.byteLength) return "";
  if (encoding === 0) return readAsciiString(dv, offset, length).replace(/\0/g, "").trim();
  const data = new Uint8Array(dv.buffer, dv.byteOffset + offset, length);
  if (encoding === 1 || encoding === 2) {
    const decoder = new TextDecoder(encoding === 1 ? "utf-16" : "utf-16be");
    return decoder.decode(data).replace(/\0/g, "").trim();
  }
  const decoder = new TextDecoder("utf-8");
  return decoder.decode(data).replace(/\0/g, "").trim();
}

export function readZeroTerminatedString(dv, offset, maxLength, encoding) {
  const limit = Math.min(dv.byteLength, offset + maxLength);
  let end = offset;
  while (end < limit && dv.getUint8(end) !== 0) end += 1;
  const length = end - offset;
  return decodeId3Text(encoding, dv, offset, length);
}

export function safeHexPreview(dv, offset, length) {
  const maxPreview = 24;
  const clampedLength = Math.min(length, maxPreview, dv.byteLength - offset);
  const bytes = [];
  for (let i = 0; i < clampedLength; i += 1) {
    const value = dv.getUint8(offset + i);
    bytes.push(value.toString(16).padStart(2, "0"));
  }
  const suffix = length > maxPreview ? "…" : "";
  return `${bytes.join(" ")}${suffix}`;
}
