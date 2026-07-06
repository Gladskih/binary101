"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import {
  coffStringTableSectionName,
  inlineCoffSectionName
} from "./section-name.js";
import {
  COFF_STRING_READ_CHUNK_BYTE_LENGTH,
  COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH,
  COFF_SYMBOL_RECORD_BYTE_LENGTH
} from "./layout.js";
import type { CoffSectionName } from "./types.js";

const LONG_SECTION_NAME_TRUNCATED_WARNING =
  "COFF string table does not fit within the file; long section names may stay unresolved.";
const LONG_SECTION_NAME_UNDERSIZED_WARNING =
  "COFF string table is smaller than its 4-byte size field; long section names may stay unresolved.";
const stringDecoder = new TextDecoder("utf-8");

export interface CoffStringTableResolver {
  resolveOffset(stringTableOffset: number): Promise<{ value: string; warning?: string }>;
}

export interface CoffStringTableResolution {
  resolver: CoffStringTableResolver | null;
  readableSize?: number;
  warning?: string;
}

const getStringTableOffset = (
  fileSize: number,
  pointerToSymbolTable: number,
  numberOfSymbols: number
): number | null => {
  if (pointerToSymbolTable <= 0 || numberOfSymbols <= 0) return null;
  const symbolTableEnd = pointerToSymbolTable + numberOfSymbols * COFF_SYMBOL_RECORD_BYTE_LENGTH;
  if (
    !Number.isSafeInteger(symbolTableEnd) ||
    symbolTableEnd + COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH > fileSize
  ) {
    return null;
  }
  return symbolTableEnd;
};

const readStringTableSize = async (
  reader: FileRangeReader,
  stringTableOffset: number
): Promise<number | null> => {
  const sizeView = await reader.read(stringTableOffset, COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH);
  return sizeView.byteLength < COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH ? null : sizeView.getUint32(0, true);
};

const decodeChunks = (chunks: Uint8Array[], totalLength: number): string => {
  const bytes = new Uint8Array(totalLength);
  chunks.reduce((offset, chunk) => {
    bytes.set(chunk, offset);
    return offset + chunk.length;
  }, 0);
  return stringDecoder.decode(bytes);
};

const readNullTerminatedUtf8Chunks = async (
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
  const finalChunk = zeroIndex === -1 ? chunk : chunk.subarray(0, zeroIndex);
  const nextChunks = [...chunks, finalChunk];
  const nextLength = totalLength + finalChunk.length;
  if (zeroIndex !== -1) return { value: decodeChunks(nextChunks, nextLength), terminated: true };
  return readNullTerminatedUtf8Chunks(reader, offset + chunk.length, endExclusive, nextChunks, nextLength);
};

const readNullTerminatedUtf8 = async (
  reader: FileRangeReader,
  start: number,
  endExclusive: number
): Promise<{ value: string; terminated: boolean }> => {
  return readNullTerminatedUtf8Chunks(reader, start, endExclusive, [], 0);
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
      warning: `Section name string-table offset /${stringTableEntryOffset} is outside the COFF string table.`
    };
  }
  const entry = await readNullTerminatedUtf8(
    reader,
    stringTableOffset + stringTableEntryOffset,
    stringTableEnd
  );
  return entry.terminated
    ? { value: entry.value }
    : {
        value: entry.value,
        warning: `Section name string-table entry /${stringTableEntryOffset} is not NUL-terminated within the COFF string table.`
      };
};

export const createCoffStringTableResolver = async (
  reader: FileRangeReader,
  pointerToSymbolTable: number,
  numberOfSymbols: number
): Promise<CoffStringTableResolution> => {
  const stringTableOffset = getStringTableOffset(reader.size, pointerToSymbolTable, numberOfSymbols);
  if (stringTableOffset == null) {
    return pointerToSymbolTable && numberOfSymbols
      ? { resolver: null, warning: LONG_SECTION_NAME_TRUNCATED_WARNING }
      : { resolver: null };
  }
  const declaredSize = await readStringTableSize(reader, stringTableOffset);
  if (declaredSize == null) return { resolver: null, warning: LONG_SECTION_NAME_TRUNCATED_WARNING };
  if (declaredSize < COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH) {
    return { resolver: null, warning: LONG_SECTION_NAME_UNDERSIZED_WARNING };
  }
  const stringTableEnd = Math.max(
    stringTableOffset,
    Math.min(reader.size, stringTableOffset + declaredSize)
  );
  const entryCache = new Map<number, Promise<{ value: string; warning?: string }>>();
  return {
    readableSize: stringTableEnd - stringTableOffset,
    resolver: {
      resolveOffset: stringTableEntryOffset => {
        const cached = entryCache.get(stringTableEntryOffset);
        if (cached) return cached;
        const pending = readStringTableEntry(
          reader,
          stringTableOffset,
          stringTableEnd,
          stringTableEntryOffset
        );
        entryCache.set(stringTableEntryOffset, pending);
        return pending;
      }
    },
    ...(stringTableEnd < stringTableOffset + declaredSize
      ? { warning: LONG_SECTION_NAME_TRUNCATED_WARNING }
      : {})
  };
};

const getLongSectionNameOffset = (rawName: string): number | null => {
  if (!rawName.startsWith("/")) return null;
  return /^\d+$/.test(rawName.slice(1)) ? Number.parseInt(rawName.slice(1), 10) : null;
};

export const resolveCoffSectionName = async (
  rawName: string,
  stringTableResolver: CoffStringTableResolver | null
): Promise<{ name: CoffSectionName; warning?: string }> => {
  const stringTableOffset = getLongSectionNameOffset(rawName);
  if (stringTableOffset == null) return { name: inlineCoffSectionName(rawName) };
  if (!stringTableResolver) return { name: coffStringTableSectionName(rawName, stringTableOffset) };
  const resolved = await stringTableResolver.resolveOffset(stringTableOffset);
  return {
    name: coffStringTableSectionName(resolved.value, stringTableOffset),
    ...(resolved.warning ? { warning: resolved.warning } : {})
  };
};
