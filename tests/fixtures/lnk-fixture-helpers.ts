"use strict";

export const encoder = new TextEncoder();
export const FILETIME_EPOCH_BIAS_MS = 11644473600000n;

export const align4 = (value: number): number => (value + 3) & ~3;

export const encodeUtf16Le = (text: string): Uint8Array => {
  const bytes = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    bytes[i * 2] = code & 0xff;
    bytes[i * 2 + 1] = code >> 8;
  }
  return bytes;
};

export const makeNullTerminatedAscii = (text: string): Uint8Array => {
  const data = encoder.encode(text);
  const out = new Uint8Array(data.length + 1);
  out.set(data, 0);
  out[out.length - 1] = 0;
  return out;
};

export const makeNullTerminatedUnicode = (text: string): Uint8Array => {
  const data = encodeUtf16Le(text);
  const out = new Uint8Array(data.length + 2);
  out.set(data, 0);
  return out;
};

export const concatParts = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  parts.forEach(part => {
    out.set(part, cursor);
    cursor += part.length;
  });
  return out;
};

export const writeGuid = (buffer: Uint8Array, offset: number, guidText: string): void => {
  const parts = guidText.split("-");
  const [data1Text, data2Text, data3Text, tailStart, tailEnd] = parts;
  if (!data1Text || !data2Text || !data3Text || !tailStart || !tailEnd) {
    throw new Error("Invalid GUID text");
  }
  const data1 = Number.parseInt(data1Text, 16);
  const data2 = Number.parseInt(data2Text, 16);
  const data3 = Number.parseInt(data3Text, 16);
  const tail = tailStart + tailEnd;
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  view.setUint32(offset, data1, true);
  view.setUint16(offset + 4, data2, true);
  view.setUint16(offset + 6, data3, true);
  for (let i = 0; i < 8; i += 1) {
    const byte = Number.parseInt(tail.slice(i * 2, i * 2 + 2), 16);
    buffer[offset + 8 + i] = byte;
  }
};

export const encodeDosDateTime = (date: number | string | Date): { dosDate: number; dosTime: number } => {
  const d = new Date(date);
  const year = Math.max(1980, Math.min(2107, d.getUTCFullYear()));
  const dosDate =
    ((year - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate();
  const dosTime =
    (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | Math.floor(d.getUTCSeconds() / 2);
  return { dosDate, dosTime };
};
