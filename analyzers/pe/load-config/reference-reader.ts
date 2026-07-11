"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import type { PeSection, RvaToOffset } from "../types.js";
import { readLoadConfigPointerRva } from "./index.js";
import type { PeLoadConfigPointerValue } from "./reference-types.js";

// Microsoft PE format, "Optional Header (Image Only)": PE32 uses 32-bit image
// pointers and PE32+ uses 64-bit image pointers.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
export const PE32_POINTER_BYTES = 4 as const;
export const PE32_PLUS_POINTER_BYTES = 8 as const;
export type PePointerBytes = typeof PE32_POINTER_BYTES | typeof PE32_PLUS_POINTER_BYTES;
export type RvaToRawSpan = (rva: number) => readonly [offset: number, byteLength: number] | null;
export type PeRvaMapping = Readonly<{
  offset: RvaToOffset;
  rawSpan: RvaToRawSpan;
  rawChunks: (
    rva: number,
    byteLength: number
  ) => readonly (readonly [offset: number, byteLength: number])[] | null;
}>;

export const addReferenceMessage = (messages: string[], message: string): void => {
  if (!messages.includes(message)) messages.push(message);
};

export const readMappedReferenceView = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  name: string,
  rva: number,
  byteLength: number
): Promise<DataView | null> => {
  if (!Number.isSafeInteger(rva) || rva < 0 ||
      !Number.isSafeInteger(byteLength) || byteLength <= 0 ||
      byteLength > PE_RVA_EXCLUSIVE_LIMIT - rva) {
    addReferenceMessage(warnings, `LOAD_CONFIG: ${name} has an invalid RVA or byte length.`);
    return null;
  }
  if (!mapping.rawSpan(rva)) {
    addReferenceMessage(notes, `LOAD_CONFIG: ${name} RVA 0x${rva.toString(16)} is not backed by raw file data.`);
    return null;
  }
  const chunks = mapping.rawChunks(rva, byteLength);
  if (!chunks) {
    addReferenceMessage(warnings, `LOAD_CONFIG: ${name} is truncated or maps outside file data.`);
    return null;
  }
  const views = await Promise.all(chunks.map(chunk => reader.read(chunk[0], chunk[1])));
  if (views.some((view, index) => view.byteLength < (chunks[index]?.[1] ?? 0))) {
    addReferenceMessage(warnings, `LOAD_CONFIG: ${name} is truncated.`);
    return null;
  }
  const bytes = new Uint8Array(byteLength);
  let destinationOffset = 0;
  for (const view of views) {
    bytes.set(new Uint8Array(view.buffer, view.byteOffset, view.byteLength), destinationOffset);
    destinationOffset += view.byteLength;
  }
  return new DataView(bytes.buffer);
};

export const referencePointerRva = (
  imageBase: bigint,
  warnings: string[],
  name: string,
  pointerVa: bigint
): number | null => {
  const rva = readLoadConfigPointerRva(imageBase, pointerVa);
  if (pointerVa !== 0n && rva == null) {
    addReferenceMessage(warnings, `LOAD_CONFIG: ${name} pointer 0x${pointerVa.toString(16)} is not a valid VA.`);
  }
  return rva;
};

export const referencedTableByteLength = (
  warnings: string[],
  name: string,
  tableRva: number,
  count: number,
  entrySize: number
): number | null => {
  if (!Number.isSafeInteger(count) || count < 0 ||
      !Number.isSafeInteger(entrySize) || entrySize <= 0) {
    addReferenceMessage(warnings, `LOAD_CONFIG: ${name} has an invalid count or entry size.`);
    return null;
  }
  if (count === 0) return 0;
  if (!Number.isSafeInteger(tableRva) || tableRva <= 0) {
    addReferenceMessage(warnings, `LOAD_CONFIG: ${name} has entries but no valid table RVA.`);
    return null;
  }
  if (count > Math.floor((PE_RVA_EXCLUSIVE_LIMIT - tableRva) / entrySize)) {
    addReferenceMessage(warnings, `LOAD_CONFIG: ${name} exceeds the 32-bit RVA address space.`);
    return null;
  }
  return count * entrySize;
};

export const readMappedReferenceTable = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  warnings: string[],
  notes: string[],
  name: string,
  tableRva: number,
  count: number,
  entrySize: number
): Promise<DataView | null> => {
  const byteLength = referencedTableByteLength(warnings, name, tableRva, count, entrySize);
  if (!byteLength) return null;
  return readMappedReferenceView(reader, mapping, warnings, notes, name, tableRva, byteLength);
};

export const readReferencePointer = (view: DataView, pointerBytes: PePointerBytes): bigint =>
  pointerBytes === PE32_POINTER_BYTES ? BigInt(view.getUint32(0, true)) : view.getBigUint64(0, true);

export const readReferencePointerValue = async (
  reader: FileRangeReader,
  mapping: PeRvaMapping,
  imageBase: bigint,
  pointerBytes: PePointerBytes,
  warnings: string[],
  notes: string[],
  name: string,
  pointerVa: bigint
): Promise<PeLoadConfigPointerValue | null> => {
  const rva = referencePointerRva(imageBase, warnings, name, pointerVa);
  if (rva == null) return null;
  const view = await readMappedReferenceView(reader, mapping, warnings, notes, name, rva, pointerBytes);
  return view ? { rva, value: readReferencePointer(view, pointerBytes) } : null;
};

const mappedSectionBytesAvailable = (
  readerSize: number,
  sections: PeSection[],
  rva: number,
  offset: number
): number | null => {
  for (const section of sections) {
    const sectionRva = section.virtualAddress >>> 0;
    const mappedSize = (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);
    const delta = rva - sectionRva;
    if (delta < 0 || delta >= mappedSize || delta >= (section.sizeOfRawData >>> 0)) continue;
    return Math.max(0, Math.min((section.sizeOfRawData >>> 0) - delta, readerSize - offset));
  }
  return null;
};

export const mappedRawSpan = (
  readerSize: number,
  sections: PeSection[],
  sizeOfHeaders: number,
  rvaToOff: RvaToOffset,
  rva: number
): readonly [offset: number, byteLength: number] | null => {
  const offset = rvaToOff(rva);
  if (offset == null || !Number.isSafeInteger(offset) || offset < 0 || offset >= readerSize) return null;
  const headerEnd = Math.max(0, Math.min(sizeOfHeaders >>> 0, readerSize));
  if (rva < headerEnd && offset === rva) return [offset, headerEnd - rva];
  const byteLength = mappedSectionBytesAvailable(readerSize, sections, rva, offset);
  return byteLength == null ? null : [offset, byteLength];
};

const rawChunks = (
  rawSpan: RvaToRawSpan,
  rva: number,
  byteLength: number
): readonly (readonly [offset: number, byteLength: number])[] | null => {
  const chunks: (readonly [number, number])[] = [];
  let consumed = 0;
  while (consumed < byteLength) {
    const span = rawSpan(rva + consumed);
    if (!span) return null;
    const chunkLength = Math.min(span[1], byteLength - consumed);
    chunks.push([span[0], chunkLength]);
    consumed += chunkLength;
  }
  return chunks;
};

export const createPeRvaMapping = (
  readerSize: number,
  sections: PeSection[],
  sizeOfHeaders: number,
  rvaToOff: RvaToOffset
): PeRvaMapping => {
  const rawSpan = (rva: number) => mappedRawSpan(readerSize, sections, sizeOfHeaders, rvaToOff, rva);
  return { offset: rvaToOff, rawSpan, rawChunks: (rva, size) => rawChunks(rawSpan, rva, size) };
};
