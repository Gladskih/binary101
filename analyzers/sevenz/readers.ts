"use strict";

import type { SevenZipContext } from "./types.js";

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
  let mask = 0x80;
  let extraBytes = 0;
  for (; extraBytes < 8; extraBytes += 1) {
    if ((firstByte & mask) === 0) break;
    mask >>= 1;
  }
  const highBits = firstByte & (mask - 1);
  let value = BigInt(highBits);
  if (extraBytes === 8) {
    value = 0n;
  }
  let low = 0n;
  for (let i = 0; i < extraBytes; i += 1) {
    const next = readByte(ctx, label);
    if (next == null) return null;
    low |= BigInt(next) << BigInt(8 * i);
  }
  if (extraBytes > 0) {
    value = (value << BigInt(8 * extraBytes)) + low;
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
  const numBytes = Math.ceil(count / 8);
  if (ctx.offset + numBytes > endOffset) {
    ctx.issues.push(`${label || "Bit vector"} extends beyond the available data.`);
    ctx.offset = endOffset;
    return values;
  }
  for (let i = 0; i < count; i += 1) {
    const byteIndex = Math.floor(i / 8);
    const bitIndex = i & 7;
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
  if (ctx.offset + 8 > endOffset) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    ctx.offset = endOffset;
    return null;
  }
  const value = ctx.dv.getBigUint64(ctx.offset, true);
  ctx.offset += 8;
  return value;
};

export const readUint32Le = (
  ctx: SevenZipContext,
  endOffset: number,
  label?: string
): number | null => {
  if (ctx.offset + 4 > endOffset) {
    if (label) ctx.issues.push(`${label} is truncated.`);
    ctx.offset = endOffset;
    return null;
  }
  const value = ctx.dv.getUint32(ctx.offset, true);
  ctx.offset += 4;
  return value;
};
