"use strict";

import type { PeRichHeader, PeRichHeaderEntry } from "./types.js";

const BYTE_R = 0x52;
const BYTE_I = 0x69;
const BYTE_C = 0x63;
const BYTE_H = 0x68;

const DANS_DWORD = 0x536e6144; // "DanS" as little-endian uint32
const MIN_DECODED_HEADER_DWORDS = 4; // DanS + checksum + 2 reserved dwords

const findRichSignatureOffsets = (bytes: Uint8Array): number[] => {
  const offsets: number[] = [];
  for (let index = 0; index + 4 <= bytes.length; index += 1) {
    if (
      bytes[index] === BYTE_R &&
      bytes[index + 1] === BYTE_I &&
      bytes[index + 2] === BYTE_C &&
      bytes[index + 3] === BYTE_H
    ) {
      offsets.push(index);
    }
  }
  return offsets;
};

const findLastEncodedDanS = (view: DataView, richOffset: number, xorKey: number): number | null => {
  if (richOffset <= 0) return null;
  const encoded = (DANS_DWORD ^ xorKey) >>> 0;
  let found: number | null = null;
  for (let offset = 0; offset + 4 <= richOffset; offset += 1) {
    if (view.getUint32(offset, true) === encoded) found = offset;
  }
  return found;
};

const decodeDwords = (view: DataView, start: number, endExclusive: number, xorKey: number): number[] => {
  const length = Math.max(0, endExclusive - start);
  const dwordCount = Math.floor(length / 4);
  const out = new Array<number>(dwordCount);
  for (let index = 0; index < dwordCount; index += 1) {
    out[index] = (view.getUint32(start + index * 4, true) ^ xorKey) >>> 0;
  }
  return out;
};

export function parseRichHeaderFromDosStub(stubBytes: Uint8Array): PeRichHeader | null {
  const candidates = findRichSignatureOffsets(stubBytes);
  if (candidates.length === 0) return null;

  const view = new DataView(stubBytes.buffer, stubBytes.byteOffset, stubBytes.byteLength);
  const richOffset = candidates[candidates.length - 1]!;
  if (richOffset + 8 > stubBytes.length) return null;

  const xorKey = view.getUint32(richOffset + 4, true) >>> 0;
  const danSOffset = findLastEncodedDanS(view, richOffset, xorKey);
  if (danSOffset == null) return null;

  const warnings: string[] = [];
  const encodedLength = richOffset - danSOffset;
  if (encodedLength < MIN_DECODED_HEADER_DWORDS * 4) {
    warnings.push("Rich header is too small to contain a complete DanS header.");
  }
  if (encodedLength % 4 !== 0) {
    warnings.push("Rich header encoded region is not 4-byte aligned; trailing bytes were ignored.");
  }

  const decoded = decodeDwords(view, danSOffset, richOffset, xorKey);
  if (decoded.length === 0 || decoded[0] !== DANS_DWORD) return null;

  const checksum = decoded.length >= 2 ? decoded[1]! : null;
  const entries: PeRichHeaderEntry[] = [];

  if (decoded.length < MIN_DECODED_HEADER_DWORDS) {
    warnings.push("Rich header does not contain any tool entries.");
  } else {
    const remaining = decoded.length - MIN_DECODED_HEADER_DWORDS;
    if (remaining % 2 !== 0) {
      warnings.push("Rich header tool entry list has an odd number of dwords; the last dword was ignored.");
    }
    const last = decoded.length - (remaining % 2);
    for (let index = MIN_DECODED_HEADER_DWORDS; index + 1 < last; index += 2) {
      const compIdRaw = decoded[index];
      const countRaw = decoded[index + 1];
      if (compIdRaw == null || countRaw == null) break;
      const compId = compIdRaw >>> 0;
      const count = countRaw >>> 0;
      if (!compId && !count) continue;
      entries.push({
        productId: (compId >>> 16) & 0xffff,
        buildNumber: compId & 0xffff,
        count
      });
    }
    if (!entries.length) warnings.push("No non-zero Rich tool entries were decoded.");
  }

  return {
    xorKey,
    checksum,
    entries,
    ...(warnings.length ? { warnings } : {})
  };
}
