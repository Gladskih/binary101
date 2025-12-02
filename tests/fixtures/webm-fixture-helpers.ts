"use strict";

const encoder = new TextEncoder();

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

export const encodeEbmlId = (id: number): Uint8Array => {
  const bytes: number[] = [];
  let value = id >>> 0;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>>= 8;
  }
  if (bytes.length === 0) bytes.push(0);
  return new Uint8Array(bytes);
};

const encodeEbmlVint = (value: number): Uint8Array => {
  let length = 1;
  while (length < 8 && value >= 1 << (7 * length)) {
    length += 1;
  }
  const marker = 1 << (7 * length);
  let remaining = marker | value;
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = remaining & 0xff;
    remaining >>>= 8;
  }
  return out;
};

const encodeEbmlUInt = (value: number, width = 0): Uint8Array => {
  let length = Math.max(1, width);
  while (length < 8 && value >= 1 << (length * 8)) {
    length += 1;
  }
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    const shift = (length - i - 1) * 8;
    out[i] = (value >> shift) & 0xff;
  }
  return out;
};

const encodeEbmlFloat = (value: number, width = 8): Uint8Array => {
  const buffer = new ArrayBuffer(width);
  const view = new DataView(buffer);
  if (width === 4) {
    view.setFloat32(0, value, false);
  } else {
    view.setFloat64(0, value, false);
  }
  return new Uint8Array(buffer);
};

export const ebmlElement = (id: number, payload: Uint8Array): Uint8Array => {
  const idBytes = encodeEbmlId(id);
  const sizeBytes = encodeEbmlVint(payload.length);
  const out = new Uint8Array(idBytes.length + sizeBytes.length + payload.length);
  out.set(idBytes, 0);
  out.set(sizeBytes, idBytes.length);
  out.set(payload, idBytes.length + sizeBytes.length);
  return out;
};

export const ebmlString = (id: number, text: string): Uint8Array =>
  ebmlElement(id, encoder.encode(text));

export const ebmlUInt = (id: number, value: number, width = 0): Uint8Array =>
  ebmlElement(id, encodeEbmlUInt(value, width));

export const ebmlFloat = (id: number, value: number, width = 8): Uint8Array =>
  ebmlElement(id, encodeEbmlFloat(value, width));

export const simpleBlock = (track: number, timecode: number, flags: number, payload: Uint8Array): Uint8Array => {
  const out = new Uint8Array(1 + 2 + 1 + payload.length);
  out[0] = 0x80 | (track & 0x7f);
  const tc = new DataView(out.buffer, out.byteOffset + 1, 2);
  tc.setInt16(0, timecode, false);
  out[3] = flags;
  out.set(payload, 4);
  return ebmlElement(0xa3, out);
};
