"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import {
  coffStringTablePeSectionName,
  inlinePeSectionName,
  type PeSectionName
} from "./section-name.js";

// Microsoft PE/COFF symbol-table records are 18 bytes each.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table
const IMAGE_SYMBOL_SIZE = 18;
// Microsoft PE/COFF string tables start with a 4-byte size field.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#string-table
const COFF_STRING_TABLE_MIN_SIZE = Uint32Array.BYTES_PER_ELEMENT;
const LONG_SECTION_NAME_TRUNCATED_WARNING =
  "COFF string table does not fit within the file; long section names may stay unresolved.";
const LONG_SECTION_NAME_UNDERSIZED_WARNING =
  "COFF string table is smaller than its 4-byte size field; long section names may stay unresolved.";
const stringDecoder = new TextDecoder("utf-8", { fatal: false });

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
  if (!pointerToSymbolTable || !numberOfSymbols) return null;
  const symbolTableEnd = pointerToSymbolTable + numberOfSymbols * IMAGE_SYMBOL_SIZE;
  if (
    !Number.isSafeInteger(symbolTableEnd) ||
    symbolTableEnd < 0 ||
    symbolTableEnd + COFF_STRING_TABLE_MIN_SIZE > fileSize
  ) {
    return null;
  }
  return symbolTableEnd;
};

const readStringTableSize = async (
  reader: FileRangeReader,
  stringTableOffset: number
): Promise<number | null> => {
  const sizeView = await reader.read(stringTableOffset, COFF_STRING_TABLE_MIN_SIZE);
  return sizeView.byteLength < COFF_STRING_TABLE_MIN_SIZE ? null : sizeView.getUint32(0, true);
};

const decodeChunks = (chunks: Uint8Array[], totalLength: number): string => {
  const bytes = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return stringDecoder.decode(bytes);
};

const readNullTerminatedUtf8 = async (
  reader: FileRangeReader,
  start: number,
  endExclusive: number
): Promise<{ value: string; terminated: boolean }> => {
  const chunks: Uint8Array[] = [];
  let totalLength = 0;
  let offset = start;
  while (offset < endExclusive) {
    // Read bounded chunks so malformed images do not force the parser to materialize the whole table.
    const chunk = await reader.readBytes(offset, Math.min(endExclusive, offset + 256) - offset);
    if (!chunk.length) break;
    const zeroIndex = chunk.indexOf(0);
    if (zeroIndex !== -1) {
      const finalChunk = chunk.subarray(0, zeroIndex);
      chunks.push(finalChunk);
      totalLength += finalChunk.length;
      return { value: decodeChunks(chunks, totalLength), terminated: true };
    }
    chunks.push(chunk);
    totalLength += chunk.length;
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
    stringTableEntryOffset < COFF_STRING_TABLE_MIN_SIZE ||
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
  if (declaredSize == null) {
    return { resolver: null, warning: LONG_SECTION_NAME_TRUNCATED_WARNING };
  }
  if (declaredSize < COFF_STRING_TABLE_MIN_SIZE) {
    return { resolver: null, warning: LONG_SECTION_NAME_UNDERSIZED_WARNING };
  }
  const stringTableEnd = Math.max(
    stringTableOffset,
    Math.min(reader.size, stringTableOffset + declaredSize)
  );
  const warnings = stringTableEnd < stringTableOffset + declaredSize
    ? { warning: LONG_SECTION_NAME_TRUNCATED_WARNING }
    : {};
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
    ...warnings
  };
};

const getLongSectionNameOffset = (rawName: string): number | null => {
  if (!rawName.startsWith("/") || rawName.length < 2) return null;
  const digits = rawName.slice(1);
  return /^\d+$/.test(digits) ? Number.parseInt(digits, 10) : null;
};

export const resolveSectionName = async (
  rawName: string,
  stringTableResolver: CoffStringTableResolver | null
): Promise<{ name: PeSectionName; warning?: string }> => {
  const stringTableOffset = getLongSectionNameOffset(rawName);
  if (stringTableOffset == null) {
    return { name: inlinePeSectionName(rawName) };
  }
  if (!stringTableResolver) {
    return { name: coffStringTablePeSectionName(rawName, stringTableOffset) };
  }
  const resolved = await stringTableResolver.resolveOffset(stringTableOffset);
  return {
    name: coffStringTablePeSectionName(resolved.value, stringTableOffset),
    ...(resolved.warning ? { warning: resolved.warning } : {})
  };
};
