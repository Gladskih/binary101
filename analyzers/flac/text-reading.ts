"use strict";

import { isPrintableByte } from "../../binary-utils.js";

const clampLength = (total: number, offset: number, length: number): number =>
  Math.max(0, Math.min(length, Math.max(0, total - offset)));

const decodeUtf8 = (dv: DataView, offset: number, length: number, decoder: TextDecoder): string => {
  if (length <= 0 || offset >= dv.byteLength) return "";
  const safeLength = clampLength(dv.byteLength, offset, length);
  const view = new Uint8Array(dv.buffer, dv.byteOffset + offset, safeLength);
  return decoder.decode(view);
};

const decodeAscii = (dv: DataView, offset: number, length: number): string => {
  if (length <= 0 || offset >= dv.byteLength) return "";
  const safeLength = clampLength(dv.byteLength, offset, length);
  let result = "";
  for (let index = 0; index < safeLength; index += 1) {
    result += String.fromCharCode(dv.getUint8(offset + index));
  }
  return result;
};

const isPrintableAscii = (bytes: Uint8Array): boolean => bytes.every(isPrintableByte);

export { clampLength, decodeAscii, decodeUtf8, isPrintableAscii };
