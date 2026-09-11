"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";

export type MappedAsciiString = {
  text: string;
  terminated: boolean;
  mappingStopped: boolean;
};

const readableOffset = (offset: number | null, fileSize: number): offset is number =>
  offset != null && Number.isSafeInteger(offset) && offset >= 0 && offset < fileSize;

const contiguousStringBytes = (
  rvaToOff: RvaToOffset, rva: number, offset: number, limit: number
): number => {
  let length = 1;
  while (length < limit && rvaToOff(rva + length) === offset + length) length += 1;
  return length;
};

export const readMappedNullTerminatedAsciiString = async (
  reader: FileRangeReader,
  fileSize: number,
  rvaToOff: RvaToOffset,
  startRva: number,
  maxBytes: number,
  chunkSize = 64
): Promise<MappedAsciiString | null> => {
  if (![startRva, fileSize, maxBytes, chunkSize].every(Number.isSafeInteger) ||
      startRva < 0 || startRva >= PE_RVA_EXCLUSIVE_LIMIT || maxBytes <= 0 ||
      chunkSize <= 0) return null;
  if (!readableOffset(rvaToOff(startRva), fileSize)) return null;
  let text = "";
  let consumed = 0;
  while (consumed < maxBytes) {
    const rva = startRva + consumed;
    const offset = rva < PE_RVA_EXCLUSIVE_LIMIT ? rvaToOff(rva) : null;
    if (!readableOffset(offset, fileSize)) return { text, terminated: false, mappingStopped: true };
    // Bound spread arguments and memory even when a caller supplies a very large chunk size.
    const contiguous = contiguousStringBytes(rvaToOff, rva, offset, Math.min(
      chunkSize, 4096, maxBytes - consumed, fileSize - offset, PE_RVA_EXCLUSIVE_LIMIT - rva
    ));
    const chunkView = await reader.read(offset, contiguous);
    const chunk = new Uint8Array(chunkView.buffer, chunkView.byteOffset, chunkView.byteLength);
    const zeroIndex = chunk.indexOf(0);
    if (zeroIndex !== -1) {
      if (zeroIndex > 0) text += String.fromCharCode(...chunk.slice(0, zeroIndex));
      return { text, terminated: true, mappingStopped: false };
    }
    text += String.fromCharCode(...chunk);
    if (chunk.byteLength < contiguous) return { text, terminated: false, mappingStopped: false };
    consumed += chunk.byteLength;
  }
  return { text, terminated: false, mappingStopped: false };
};
