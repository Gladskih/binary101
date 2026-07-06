"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { CoffStringTable } from "./debug-types.js";
import {
  COFF_STRING_READ_CHUNK_BYTE_LENGTH,
  COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH
} from "./layout.js";

const stringDecoder = new TextDecoder("utf-8");

const decodeChunks = (chunks: Uint8Array[], totalLength: number): string => {
  const bytes = new Uint8Array(totalLength);
  chunks.reduce((cursor, part) => {
    bytes.set(part, cursor);
    return cursor + part.length;
  }, 0);
  return stringDecoder.decode(bytes);
};

const readNullTerminatedStringChunks = async (
  reader: FileRangeReader,
  offset: number,
  endExclusive: number,
  chunks: Uint8Array[],
  totalLength: number
): Promise<{ value: string; terminated: boolean }> => {
  if (offset >= endExclusive) return { value: decodeChunks(chunks, totalLength), terminated: false };
  const chunk = await reader.readBytes(
    offset,
    Math.min(endExclusive - offset, COFF_STRING_READ_CHUNK_BYTE_LENGTH)
  );
  if (!chunk.length) return { value: decodeChunks(chunks, totalLength), terminated: false };
  const zeroIndex = chunk.indexOf(0);
  const usedChunk = zeroIndex === -1 ? chunk : chunk.subarray(0, zeroIndex);
  const nextChunks = [...chunks, usedChunk];
  const nextLength = totalLength + usedChunk.length;
  if (zeroIndex !== -1) return { value: decodeChunks(nextChunks, nextLength), terminated: true };
  return readNullTerminatedStringChunks(reader, offset + chunk.length, endExclusive, nextChunks, nextLength);
};

const readNullTerminatedString = async (
  reader: FileRangeReader,
  start: number,
  endExclusive: number
): Promise<{ value: string; terminated: boolean }> => {
  return readNullTerminatedStringChunks(reader, start, endExclusive, [], 0);
};

const readStringTableEntry = async (
  reader: FileRangeReader,
  stringTableOffset: number,
  stringTableEnd: number,
  stringTableEntryOffset: number
): Promise<{ value: string; warning?: string }> => {
  if (
    stringTableEntryOffset < COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH ||
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
): Promise<CoffStringTable | null> => {
  if (stringTableOffset + COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH > reader.size) return null;
  const sizeView = await reader.read(stringTableOffset, COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);
  if (sizeView.byteLength < COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH) {
    addWarning("COFF string table size field is truncated.");
    return null;
  }
  const declaredSize = sizeView.getUint32(0, true);
  if (declaredSize < COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH) {
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
