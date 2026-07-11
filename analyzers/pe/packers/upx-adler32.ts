"use strict";

// Adler-32 is defined over two sums modulo 65521, initialized to 1 and 0.
// RFC 1950 section 8.2: https://www.rfc-editor.org/rfc/rfc1950#section-8.2
const ADLER_MODULUS = 65_521;
// zlib's NMAX keeps the unreduced sums within 32-bit unsigned arithmetic.
// https://github.com/madler/zlib/blob/master/adler32.c
const MAX_ADLER_BLOCK_BYTES = 5_552;

export const upxAdler32 = (bytes: Uint8Array): number => {
  let low = 1;
  let high = 0;
  for (let start = 0; start < bytes.byteLength; start += MAX_ADLER_BLOCK_BYTES) {
    const end = Math.min(start + MAX_ADLER_BLOCK_BYTES, bytes.byteLength);
    for (let index = start; index < end; index += 1) {
      low += bytes[index] ?? 0;
      high += low;
    }
    low %= ADLER_MODULUS;
    high %= ADLER_MODULUS;
  }
  return ((high << 16) | low) >>> 0;
};
