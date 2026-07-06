"use strict";

import { readAsciiString } from "../../../binary-utils.js";
import {
  COFF_FILE_HEADER_BYTE_LENGTH,
  COFF_FILE_HEADER_FIELDS,
  COFF_SECTION_HEADER_BYTE_LENGTH,
  COFF_SECTION_HEADER_FIELDS,
  COFF_SHORT_NAME_BYTE_LENGTH,
  readCoffField
} from "../../coff/layout.js";
import type { PeDosStubMleHeader, PeDosStubNestedPe, PeDosStubNestedPeSection } from "../types.js";

const DOS_SIGNATURE_MZ = 0x5a4d;
const PE_SIGNATURE = 0x0000_4550;
const PE_SIGNATURE_BYTE_LENGTH = 4;
const OPTIONAL_HEADER_STANDARD_FIELDS_SIZE = 24;
const PE32_OPTIONAL_HEADER_MAGIC = 0x10b;
const PE32_PLUS_OPTIONAL_HEADER_MAGIC = 0x20b;
const MAX_NESTED_SECTIONS_PREVIEW = 8;
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
const RSDS_SIGNATURE = 0x5344_5352;
// Intel TXT Software Development Guide: MLE header UUID, encoded as four little-endian dwords.
const MLE_HEADER_UUID = [0x9082_ac5a, 0x74a7_476f, 0xa255_5c0f, 0x42b6_51cb];

const readU16 = (view: DataView, offset: number): number | null =>
  offset >= 0 && offset + 2 <= view.byteLength ? view.getUint16(offset, true) : null;

const readU32 = (view: DataView, offset: number): number | null =>
  offset >= 0 && offset + 4 <= view.byteLength ? view.getUint32(offset, true) : null;

const readCString = (bytes: Uint8Array, offset: number): string | null => {
  if (offset < 0 || offset >= bytes.length) return null;
  let text = "";
  for (let index = offset; index < bytes.length; index += 1) {
    const value = bytes[index];
    if (value === 0) return text || null;
    if (value == null || value < 0x20 || value > 0x7e) return null;
    text += String.fromCharCode(value);
  }
  return null;
};

const parseSections = (
  view: DataView,
  offset: number,
  count: number,
  warnings: string[]
): PeDosStubNestedPeSection[] => {
  const sections: PeDosStubNestedPeSection[] = [];
  const available = Math.max(0, Math.floor((view.byteLength - offset) / COFF_SECTION_HEADER_BYTE_LENGTH));
  if (count > available) warnings.push("Nested PE section table is truncated.");
  for (let index = 0; index < Math.min(count, available, MAX_NESTED_SECTIONS_PREVIEW); index += 1) {
    const sectionOffset = offset + index * COFF_SECTION_HEADER_BYTE_LENGTH;
    sections.push({
      name: readAsciiString(view, sectionOffset, COFF_SHORT_NAME_BYTE_LENGTH).replace(/\0+$/u, ""),
      virtualSize: readCoffField(view, sectionOffset, COFF_SECTION_HEADER_FIELDS.VirtualSize),
      virtualAddress: readCoffField(view, sectionOffset, COFF_SECTION_HEADER_FIELDS.VirtualAddress),
      sizeOfRawData: readCoffField(view, sectionOffset, COFF_SECTION_HEADER_FIELDS.SizeOfRawData),
      pointerToRawData: readCoffField(view, sectionOffset, COFF_SECTION_HEADER_FIELDS.PointerToRawData)
    });
  }
  if (count > MAX_NESTED_SECTIONS_PREVIEW) warnings.push("Nested PE section list is abbreviated.");
  return sections;
};

const rvaToOffset = (sections: PeDosStubNestedPeSection[], rva: number): number | null => {
  for (const section of sections) {
    const start = section.virtualAddress >>> 0;
    const size = Math.max(section.virtualSize >>> 0, section.sizeOfRawData >>> 0);
    if (rva >= start && rva < start + size) return (section.pointerToRawData >>> 0) + rva - start;
  }
  return null;
};

const parseCodeViewPath = (
  view: DataView,
  bytes: Uint8Array,
  sections: PeDosStubNestedPeSection[],
  dataDirectoryOffset: number,
  directoryCount: number
): string | null => {
  if (directoryCount <= 6 || dataDirectoryOffset + 7 * 8 > view.byteLength) return null;
  const debugRva = readU32(view, dataDirectoryOffset + 6 * 8);
  const debugSize = readU32(view, dataDirectoryOffset + 6 * 8 + 4);
  if (!debugRva || !debugSize) return null;
  const debugOffset = rvaToOffset(sections, debugRva);
  if (debugOffset == null || debugOffset + 28 > view.byteLength) return null;
  const debugEntries = Math.floor(Math.min(debugSize, view.byteLength - debugOffset) / 28);
  for (let index = 0; index < debugEntries; index += 1) {
    const entryOffset = debugOffset + index * 28;
    if (readU32(view, entryOffset + 12) !== IMAGE_DEBUG_TYPE_CODEVIEW) continue;
    const sizeOfData = readU32(view, entryOffset + 16) ?? 0;
    const pointerToRawData = readU32(view, entryOffset + 24) ?? 0;
    if (pointerToRawData + Math.min(sizeOfData, 24) > view.byteLength) continue;
    if (readU32(view, pointerToRawData) !== RSDS_SIGNATURE) continue;
    return readCString(bytes, pointerToRawData + 24);
  }
  return null;
};

const parseMleHeader = (view: DataView): PeDosStubMleHeader | undefined => {
  for (let offset = 0; offset + 52 <= view.byteLength; offset += 4) {
    if (!MLE_HEADER_UUID.every((value, index) => readU32(view, offset + index * 4) === value)) continue;
    return {
      offset,
      version: readU32(view, offset + 20) ?? 0,
      entryPoint: readU32(view, offset + 24) ?? 0,
      firstValidPage: readU32(view, offset + 28) ?? 0,
      mleStart: readU32(view, offset + 32) ?? 0,
      mleEnd: readU32(view, offset + 36) ?? 0,
      capabilities: readU32(view, offset + 40) ?? 0
    };
  }
  return undefined;
};

export const parseNestedPeAtDosEntrypoint = (
  bytes: Uint8Array,
  entryOffset: number
): PeDosStubNestedPe | null => {
  if (entryOffset < 0 || entryOffset + 0x40 > bytes.length) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset + entryOffset, bytes.length - entryOffset);
  if (readU16(view, 0) !== DOS_SIGNATURE_MZ) return null;
  const eLfanew = readU32(view, 0x3c);
  if (eLfanew == null || eLfanew + PE_SIGNATURE_BYTE_LENGTH + COFF_FILE_HEADER_BYTE_LENGTH > view.byteLength) {
    return null;
  }
  if (readU32(view, eLfanew) !== PE_SIGNATURE) return null;
  const warnings: string[] = [];
  const coffOffset = eLfanew + PE_SIGNATURE_BYTE_LENGTH;
  const sectionCount = readCoffField(view, coffOffset, COFF_FILE_HEADER_FIELDS.NumberOfSections);
  const optionalHeaderSize = readCoffField(view, coffOffset, COFF_FILE_HEADER_FIELDS.SizeOfOptionalHeader);
  const optionalHeaderOffset = coffOffset + COFF_FILE_HEADER_BYTE_LENGTH;
  const optionalMagic = readU16(view, optionalHeaderOffset);
  const isPe32 = optionalMagic === PE32_OPTIONAL_HEADER_MAGIC;
  const isPe32Plus = optionalMagic === PE32_PLUS_OPTIONAL_HEADER_MAGIC;
  const dataDirectoryOffset = optionalHeaderOffset + (isPe32 ? 96 : isPe32Plus ? 112 : optionalHeaderSize);
  const directoryCount = isPe32 || isPe32Plus ? readU32(view, dataDirectoryOffset - 4) ?? 0 : 0;
  const sections = parseSections(view, optionalHeaderOffset + optionalHeaderSize, sectionCount, warnings);
  const nestedBytes = bytes.subarray(entryOffset);
  const codeViewPath = parseCodeViewPath(view, nestedBytes, sections, dataDirectoryOffset, directoryCount);
  const mle = parseMleHeader(view);
  const rawEnd = sections.reduce(
    (max, section) => Math.max(max, (section.pointerToRawData >>> 0) + (section.sizeOfRawData >>> 0)),
    0
  );
  const declaredEnd = isPe32 || isPe32Plus ? readU32(view, optionalHeaderOffset + 60) ?? 0 : 0;
  const endOffset = Math.min(
    bytes.length,
    entryOffset + Math.max(rawEnd, declaredEnd, eLfanew + PE_SIGNATURE_BYTE_LENGTH)
  );
  return {
    offset: entryOffset,
    endOffset,
    peHeaderOffset: entryOffset + eLfanew,
    machine: readCoffField(view, coffOffset, COFF_FILE_HEADER_FIELDS.Machine),
    optionalMagic,
    entrypointRva: optionalHeaderSize >= OPTIONAL_HEADER_STANDARD_FIELDS_SIZE
      ? readU32(view, optionalHeaderOffset + 16)
      : null,
    subsystem: isPe32 || isPe32Plus ? readU16(view, optionalHeaderOffset + 68) : null,
    sizeOfImage: isPe32 || isPe32Plus ? readU32(view, optionalHeaderOffset + 56) : null,
    sizeOfHeaders: isPe32 || isPe32Plus ? readU32(view, optionalHeaderOffset + 60) : null,
    sections,
    ...(codeViewPath ? { codeViewPath } : {}),
    ...(mle ? { mle } : {}),
    ...(warnings.length ? { warnings } : {})
  };
};
