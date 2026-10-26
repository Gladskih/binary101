"use strict";

import { decompressLzmaWithPropertiesTracked } from "../../lzma/decoder.js";

const dictionarySize = (unpackedSize: number, level: number): number => {
  // UPX's LZMA defaults and level overrides are defined in compress_lzma.cpp.
  // https://github.com/upx/upx/blob/v5.2.0/src/compress/compress_lzma.cpp
  if (level <= 2) return Math.min(unpackedSize, 256 * 1024);
  if (level === 9) return Math.min(unpackedSize, 8 * 1024 * 1024);
  if (level === 10) return unpackedSize;
  return Math.min(unpackedSize, 4 * 1024 * 1024);
};

export const readUpxLzmaProperties = (
  packed: Uint8Array, unpackedSize: number, level: number
): number[] => {
  if (packed.byteLength < 3) throw new Error("UPX LZMA stream is truncated.");
  const positionBits = (packed[0] ?? 0) & 7;
  const literalPositionBits = (packed[1] ?? 0) >>> 4;
  const literalContextBits = (packed[1] ?? 0) & 15;
  if (positionBits >= 5 || literalPositionBits >= 5 || literalContextBits >= 9) {
    throw new Error("UPX LZMA properties are invalid.");
  }
  if ((packed[0] ?? 0) >>> 3 !== literalContextBits + literalPositionBits) {
    throw new Error("UPX LZMA property redundancy check failed.");
  }
  const dictionary = dictionarySize(unpackedSize, level);
  return [
    (positionBits * 5 + literalPositionBits) * 9 + literalContextBits,
    dictionary & 0xff,
    (dictionary >>> 8) & 0xff,
    (dictionary >>> 16) & 0xff,
    (dictionary >>> 24) & 0xff
  ];
};

export const decompressUpxLzma = async (
  packed: Uint8Array,
  unpackedSize: number,
  level: number
): Promise<Uint8Array> => {
  const result = await decompressLzmaWithPropertiesTracked(
    readUpxLzmaProperties(packed, unpackedSize, level),
    packed.subarray(2),
    BigInt(unpackedSize)
  );
  if (result.consumedPackedBytes !== packed.byteLength - 2) {
    throw new Error("UPX LZMA stream has unconsumed input.");
  }
  return result.bytes;
};
