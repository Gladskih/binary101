"use strict";

const formatOffsetHex = (offset: number): string => `0x${offset.toString(16)}`;

export type Mpeg2PackHeaderParse = {
  totalSize: number;
  scrSeconds: number | null;
  muxRate: number | null;
  stuffingLength: number | null;
};

export const parseMpeg2PackHeader = (
  bytes: Uint8Array,
  localOffset: number,
  absoluteOffset: number,
  pushIssue: (message: string) => void
): Mpeg2PackHeaderParse => {
  if (localOffset + 14 > bytes.length) {
    return { totalSize: 0, scrSeconds: null, muxRate: null, stuffingLength: null };
  }
  const b4 = bytes[localOffset + 4] ?? 0;
  const b5 = bytes[localOffset + 5] ?? 0;
  const b6 = bytes[localOffset + 6] ?? 0;
  const b7 = bytes[localOffset + 7] ?? 0;
  const b8 = bytes[localOffset + 8] ?? 0;
  const b9 = bytes[localOffset + 9] ?? 0;
  const b10 = bytes[localOffset + 10] ?? 0;
  const b11 = bytes[localOffset + 11] ?? 0;
  const b12 = bytes[localOffset + 12] ?? 0;
  const b13 = bytes[localOffset + 13] ?? 0;

  const markerOk =
    (b4 & 0x04) !== 0 &&
    (b6 & 0x04) !== 0 &&
    (b8 & 0x04) !== 0 &&
    (b9 & 0x01) !== 0 &&
    (b12 & 0x03) === 0x03 &&
    (b13 & 0xf8) === 0xf8;

  if (!markerOk) {
    pushIssue(`Pack header marker bits look invalid at ${formatOffsetHex(absoluteOffset)}.`);
  }

  const scrPart1 = ((b4 & 0x03) << 13) | (b5 << 5) | ((b6 & 0xf8) >>> 3);
  const scrPart2 = ((b6 & 0x03) << 13) | (b7 << 5) | ((b8 & 0xf8) >>> 3);
  const scrBase = scrPart1 * 2 ** 15 + scrPart2;
  const scrExt = ((b8 & 0x03) << 7) | ((b9 & 0xfe) >>> 1);
  const scr27MHz = scrBase * 300 + scrExt;
  const scrSeconds = scr27MHz / 27000000;

  const muxRate = (b10 << 14) | (b11 << 6) | ((b12 & 0xfc) >>> 2);
  const stuffingLength = b13 & 0x07;
  const totalSize = 14 + stuffingLength;
  return { totalSize, scrSeconds, muxRate, stuffingLength };
};

