"use strict";

import { decompress } from "lzma-web/decompress";
import { SEVENZIP_LZMA_PROPERTY_BYTES } from "./method-ids.js";

// Keep bytes unsigned when lzma-web returns a signed/number array.
const BYTE_MASK = 0xffn;
const BITS_PER_BYTE = 8;
const LZMA_ALONE_SIZE_BYTES = BigUint64Array.BYTES_PER_ELEMENT;
const LZMA_ALONE_HEADER_BYTES = SEVENZIP_LZMA_PROPERTY_BYTES + LZMA_ALONE_SIZE_BYTES;

const writeUint64Le = (target: Uint8Array, offset: number, value: bigint): void => {
  for (let index = 0; index < LZMA_ALONE_SIZE_BYTES; index += 1) {
    target[offset + index] = Number((value >> BigInt(index * BITS_PER_BYTE)) & BYTE_MASK);
  }
};

export const decompressLzmaWithProperties = async (
  propertyBytes: number[],
  packedBytes: Uint8Array,
  unpackSize: bigint
): Promise<Uint8Array> => {
  if (propertyBytes.length !== SEVENZIP_LZMA_PROPERTY_BYTES) {
    throw new Error("LZMA coder properties must be exactly 5 bytes.");
  }
  if (unpackSize > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("LZMA unpack size exceeds supported range.");
  }
  // LZMA SDK lzma_alone streams prefix raw LZMA data with 5 property bytes and
  // an 8-byte little-endian uncompressed size; 7z stores those properties separately.
  // https://www.7-zip.org/sdk.html
  const stream = new Uint8Array(LZMA_ALONE_HEADER_BYTES + packedBytes.byteLength);
  stream.set(propertyBytes, 0);
  writeUint64Le(stream, SEVENZIP_LZMA_PROPERTY_BYTES, unpackSize);
  stream.set(packedBytes, LZMA_ALONE_HEADER_BYTES);
  const decoded = decompress(stream);
  if (decoded == null) throw new Error("LZMA decompression returned no data.");
  return typeof decoded === "string"
    ? new TextEncoder().encode(decoded)
    : Uint8Array.from(decoded, value => value & Number(BYTE_MASK));
};
