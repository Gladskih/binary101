"use strict";

// Reflected IEEE CRC-32 polynomial used by zlib, 7z and RAR.
// https://github.com/madler/zlib/blob/master/crc32.c
const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

export const updateCrc32 = (state: number, bytes: Uint8Array): number => {
  let crc = state >>> 0;
  for (const byte of bytes) {
    crc = (crc >>> 8) ^ (CRC32_TABLE[(crc ^ byte) & 0xff] ?? 0);
  }
  return crc >>> 0;
};

export const finishCrc32 = (state: number): number => (state ^ 0xffffffff) >>> 0;

export const crc32 = (bytes: Uint8Array): number =>
  finishCrc32(updateCrc32(0xffffffff, bytes));
