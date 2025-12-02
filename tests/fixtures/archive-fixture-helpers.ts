"use strict";

export const encoder = new TextEncoder();

const crc32Table = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let j = 0; j < 8; j += 1) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

export const crc32 = (bytes: Uint8Array): number => {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    const idx = (crc ^ byte) & 0xff;
    const tableValue = crc32Table[idx] ?? 0;
    crc = (crc >>> 8) ^ tableValue;
  }
  return (crc ^ 0xffffffff) >>> 0;
};

export const encodeVint = (value: number | bigint): number[] => {
  let v = BigInt(value);
  const out = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) byte |= 0x80;
    out.push(byte);
  } while (v !== 0n);
  return out;
};

export const u32le = (value: number): number[] => [
  value & 0xff,
  (value >> 8) & 0xff,
  (value >> 16) & 0xff,
  (value >> 24) & 0xff
];

export const formatOffset = (value: number): string => value.toString(8).padStart(7, "0") + "\0";

export const writeString = (buffer: Uint8Array, text: string, offset: number, length: number): void => {
  const bytes = encoder.encode(text);
  const max = Math.min(bytes.length, length);
  buffer.set(bytes.slice(0, max), offset);
};
