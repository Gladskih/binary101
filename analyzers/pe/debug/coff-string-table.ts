"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeCoffStringTable } from "./coff-types.js";

const STRING_TABLE_SIZE_FIELD = 4;
const stringDecoder = new TextDecoder("utf-8", { fatal: false });

const decodeChunks = (chunks: Uint8Array[], totalLength: number): string => {
  const bytes = new Uint8Array(totalLength);
  let cursor = 0;
  for (const part of chunks) {
    bytes.set(part, cursor);
    cursor += part.length;
  }
  return stringDecoder.decode(bytes);
};

const readNullTerminatedString = async (
  reader: FileRangeReader,
  start: number,
  endExclusive: number
): Promise<{ value: string; terminated: boolean }> => {
  const chunks: Uint8Array[] = [];
  let totalLength = 0;
  let offset = start;
  while (offset < endExclusive) {
    const chunk = await reader.readBytes(offset, Math.min(endExclusive - offset, 256));
    if (!chunk.length) break;
    const zeroIndex = chunk.indexOf(0);
    const usedChunk = zeroIndex === -1 ? chunk : chunk.subarray(0, zeroIndex);
    chunks.push(usedChunk);
    totalLength += usedChunk.length;
    if (zeroIndex !== -1) return { value: decodeChunks(chunks, totalLength), terminated: true };
    offset += chunk.length;
  }
  return { value: decodeChunks(chunks, totalLength), terminated: false };
};

const readStringTableEntry = async (
  reader: FileRangeReader,
  stringTableOffset: number,
  stringTableEnd: number,
  stringTableEntryOffset: number
): Promise<{ value: string; warning?: string }> => {
  if (
    stringTableEntryOffset < STRING_TABLE_SIZE_FIELD ||
    stringTableOffset + stringTableEntryOffset >= stringTableEnd
  ) {
    return {
      value: `/${stringTableEntryOffset}`,
      warning: `COFF symbol name offset /${stringTableEntryOffset} is outside the string table.`
    };
  }
  const entry = await readNullTerminatedString(
    reader,
    stringTableOffset + stringTableEntryOffset,
    stringTableEnd
  );
  return entry.terminated
    ? { value: entry.value }
    : {
        value: entry.value,
        warning: `COFF symbol name offset /${stringTableEntryOffset} is not NUL-terminated.`
      };
};

export const createCoffDebugStringTable = async (
  reader: FileRangeReader,
  stringTableOffset: number,
  addWarning: (message: string) => void
): Promise<PeCoffStringTable | null> => {
  if (stringTableOffset + STRING_TABLE_SIZE_FIELD > reader.size) return null;
  const sizeView = await reader.read(stringTableOffset, STRING_TABLE_SIZE_FIELD);
  if (sizeView.byteLength < STRING_TABLE_SIZE_FIELD) {
    addWarning("COFF string table size field is truncated.");
    return null;
  }
  const declaredSize = sizeView.getUint32(0, true);
  if (declaredSize < STRING_TABLE_SIZE_FIELD) {
    addWarning("COFF string table is smaller than its 4-byte size field.");
    return null;
  }
  const tableEnd = Math.min(reader.size, stringTableOffset + declaredSize);
  if (tableEnd < stringTableOffset + declaredSize) addWarning("COFF string table is truncated.");
  const cache = new Map<number, Promise<{ value: string; warning?: string }>>();
  return {
    offset: stringTableOffset,
    readableSize: tableEnd - stringTableOffset,
    resolve: stringTableEntryOffset => {
      const cached = cache.get(stringTableEntryOffset);
      if (cached) return cached;
      const pending = readStringTableEntry(reader, stringTableOffset, tableEnd, stringTableEntryOffset);
      cache.set(stringTableEntryOffset, pending);
      return pending;
    }
  };
};
