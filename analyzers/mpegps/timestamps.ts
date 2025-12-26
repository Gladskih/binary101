"use strict";

export const decodeTimestamp33 = (bytes: Uint8Array, offset: number): number | null => {
  if (offset + 5 > bytes.length) return null;
  const b0 = bytes[offset] ?? 0;
  const b1 = bytes[offset + 1] ?? 0;
  const b2 = bytes[offset + 2] ?? 0;
  const b3 = bytes[offset + 3] ?? 0;
  const b4 = bytes[offset + 4] ?? 0;

  const markerOk = (b0 & 0x01) !== 0 && (b2 & 0x01) !== 0 && (b4 & 0x01) !== 0;
  if (!markerOk) return null;

  const top3 = (b0 >>> 1) & 0x07;
  const mid15 = (b1 << 7) | (b2 >>> 1);
  const low15 = (b3 << 7) | (b4 >>> 1);
  return top3 * 2 ** 30 + mid15 * 2 ** 15 + low15;
};

