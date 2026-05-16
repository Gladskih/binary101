"use strict";

import type { SevenZipContext } from "./types.js";

const UINT64_MAX_ENCODED_BYTES = BigUint64Array.BYTES_PER_ELEMENT;
const UINT64_BYTES = BigUint64Array.BYTES_PER_ELEMENT;
const UINT32_BYTES = Uint32Array.BYTES_PER_ELEMENT;
const BITS_PER_BYTE = 8;
// 7z encoded UInt64 uses the high bits of the first byte to declare extra bytes.
// https://www.7-zip.org/sdk.html
const FIRST_VARINT_MASK = 0x80;

export const toSafeNumber = (value: number | bigint | null | undefined): number | null => {
  if (typeof value === "number") return value;
  if (typeof value === "bigint") {
    if (value <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
    return null;
  }
  return null;
};

export const readByte = (ctx: SevenZipContext, label?: string): number | null => {
  if (ctx.offset >= ctx.dv.byteLength) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    return null;
  }
  const value = ctx.dv.getUint8(ctx.offset);
  ctx.offset += 1;
  return value;
};

export const readEncodedUint64 = (ctx: SevenZipContext, label?: string): bigint | null => {
  const firstByte = readByte(ctx, label);
  if (firstByte == null) return null;
  let mask = FIRST_VARINT_MASK;
  let extraBytes = 0;
  for (; extraBytes < UINT64_MAX_ENCODED_BYTES; extraBytes += 1) {
    if ((firstByte & mask) === 0) break;
    mask >>= 1;
  }
  const highBits = firstByte & (mask - 1);
  let value = BigInt(highBits);
  if (extraBytes === UINT64_MAX_ENCODED_BYTES) {
    value = 0n;
  }
  let low = 0n;
  for (let i = 0; i < extraBytes; i += 1) {
    const next = readByte(ctx, label);
    if (next == null) return null;
    low |= BigInt(next) << BigInt(BITS_PER_BYTE * i);
  }
  if (extraBytes > 0) {
    value = (value << BigInt(BITS_PER_BYTE * extraBytes)) + low;
  }
  return value;
};

export const readBoolVector = (
  ctx: SevenZipContext,
  count: number,
  endOffset: number,
  label?: string
): boolean[] | null => {
  if (ctx.offset >= endOffset) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    return null;
  }
  const allDefined = readByte(ctx, label);
  if (allDefined == null) return null;
  const values = new Array(count).fill(false);
  if (allDefined !== 0) {
    values.fill(true);
    return values;
  }
  return readBitVector(ctx, count, endOffset, label);
};

export const readBitVector = (
  ctx: SevenZipContext,
  count: number,
  endOffset: number,
  label?: string
): boolean[] | null => {
  const values = new Array(count).fill(false);
  const numBytes = Math.ceil(count / BITS_PER_BYTE);
  if (ctx.offset + numBytes > endOffset) {
    ctx.issues.push(`${label || "Bit vector"} extends beyond the available data.`);
    ctx.offset = endOffset;
    return values;
  }
  for (let i = 0; i < count; i += 1) {
    const byteIndex = Math.floor(i / BITS_PER_BYTE);
    const bitIndex = (BITS_PER_BYTE - 1) - (i & (BITS_PER_BYTE - 1));
    const bit = ctx.dv.getUint8(ctx.offset + byteIndex) & (1 << bitIndex);
    values[i] = bit !== 0;
  }
  ctx.offset += numBytes;
  return values;
};

export const readUint64Le = (
  ctx: SevenZipContext,
  endOffset: number,
  label?: string
): bigint | null => {
  if (ctx.offset + UINT64_BYTES > endOffset) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    ctx.offset = endOffset;
    return null;
  }
  const value = ctx.dv.getBigUint64(ctx.offset, true);
  ctx.offset += UINT64_BYTES;
  return value;
};

export const readUint32Le = (
  ctx: SevenZipContext,
  endOffset: number,
  label?: string
): number | null => {
  if (ctx.offset + UINT32_BYTES > endOffset) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    ctx.offset = endOffset;
    return null;
  }
  const value = ctx.dv.getUint32(ctx.offset, true);
  ctx.offset += UINT32_BYTES;
  return value;
};
