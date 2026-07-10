"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import {
  DWARF_ENCODING,
  DWARF_FORMAT,
  DWARF_INITIAL_LENGTH,
  DWARF_LIMIT,
  DWARF_SECTION,
  DWARF_SENTINEL,
  DWARF_UNIT_TYPE,
  DWARF_VERSION
} from "./constants.js";
import { DwarfCursor } from "./cursor.js";
import type { DwarfSectionInput } from "./types.js";

export type DwarfUnitHeader = {
  offset: number;
  end: number;
  length: bigint;
  format: 32 | 64;
  version: number;
  unitType: number | null;
  addressSize: number;
  abbreviationOffset: bigint;
  dataOffset: number;
};

// Initial-length and unit-header layouts follow DWARF 5, sections 7.4 and 7.5.1:
// https://dwarfstd.org/doc/DWARF5.pdf

const readInitialLength = async (
  cursor: DwarfCursor,
  section: DwarfSectionInput,
  issues: string[]
): Promise<{ length: bigint; format: 32 | 64; end: number } | null> => {
  const initialLength = await cursor.uint32();
  if (initialLength == null) return null;
  let length = BigInt(initialLength);
  let format: 32 | 64 = DWARF_FORMAT.dwarf32;
  if (initialLength === DWARF_INITIAL_LENGTH.format64Escape) {
    const value64 = await cursor.uint64();
    if (value64 == null) return null;
    length = value64;
    format = DWARF_FORMAT.dwarf64;
  } else if (initialLength >= DWARF_INITIAL_LENGTH.reservedMinimum) {
    issues.push(
      `${section.name} at 0x${(cursor.position - Uint32Array.BYTES_PER_ELEMENT).toString(16)}: ` +
      `reserved initial length 0x${initialLength.toString(16)}.`
    );
    return null;
  }
  const numericLength = Number(length);
  if (!Number.isSafeInteger(numericLength)) {
    issues.push(`${section.name}: unit length ${length.toString()} is too large to index.`);
    return null;
  }
  const declaredEnd = cursor.position + numericLength;
  if (declaredEnd > section.size) {
    issues.push(
      `${section.name} at 0x${(
        cursor.position - format / DWARF_ENCODING.bitsPerByte
      ).toString(16)}: ` +
      `unit extends beyond the section (${declaredEnd} > ${section.size}).`
    );
  }
  return { length, format, end: Math.min(declaredEnd, section.size) };
};

const skipTypedUnitFields = async (
  cursor: DwarfCursor,
  unitType: number,
  format: 32 | 64
): Promise<void> => {
  if (unitType === DWARF_UNIT_TYPE.type || unitType === DWARF_UNIT_TYPE.splitType) {
    await cursor.uint64();
    await cursor.unsigned(format / DWARF_ENCODING.bitsPerByte);
  } else if (unitType === DWARF_UNIT_TYPE.skeleton ||
             unitType === DWARF_UNIT_TYPE.splitCompile) {
    await cursor.uint64();
  }
};

const readVersionFiveHeader = async (
  cursor: DwarfCursor,
  format: 32 | 64
): Promise<{ unitType: number; addressSize: number; abbreviationOffset: bigint } | null> => {
  const unitType = await cursor.uint8();
  const addressSize = await cursor.uint8();
  const abbreviationOffset = await cursor.unsigned(format / DWARF_ENCODING.bitsPerByte);
  if (unitType == null || addressSize == null || abbreviationOffset == null) return null;
  await skipTypedUnitFields(cursor, unitType, format);
  return { unitType, addressSize, abbreviationOffset };
};

const readLegacyHeader = async (
  cursor: DwarfCursor,
  section: DwarfSectionInput,
  format: 32 | 64
): Promise<{ unitType: number | null; addressSize: number; abbreviationOffset: bigint } | null> => {
  const abbreviationOffset = await cursor.unsigned(format / DWARF_ENCODING.bitsPerByte);
  const addressSize = await cursor.uint8();
  if (addressSize == null || abbreviationOffset == null) return null;
  const unitType = section.name === DWARF_SECTION.types ? DWARF_UNIT_TYPE.type : null;
  if (unitType != null) {
    await cursor.uint64();
    await cursor.unsigned(format / DWARF_ENCODING.bitsPerByte);
  }
  return { unitType, addressSize, abbreviationOffset };
};

export const parseDwarfUnitHeader = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  offset: number,
  littleEndian: boolean,
  issues: string[]
): Promise<DwarfUnitHeader | null> => {
  const lengthCursor = new DwarfCursor(
    reader,
    section,
    offset,
    section.size,
    littleEndian,
    issues
  );
  const initial = await readInitialLength(lengthCursor, section, issues);
  if (!initial || initial.length === DWARF_SENTINEL.zeroUnitLength) {
    if (initial?.length === DWARF_SENTINEL.zeroUnitLength) {
      issues.push(`${section.name} at 0x${offset.toString(16)}: zero-length unit.`);
    }
    return null;
  }
  const cursor = new DwarfCursor(
    reader,
    section,
    lengthCursor.position,
    initial.end,
    littleEndian,
    issues
  );
  const version = await cursor.uint16();
  if (version == null) return null;
  if (version < DWARF_VERSION.minimumSupported ||
      version > DWARF_VERSION.maximumSupported) {
    issues.push(`${section.name} at 0x${offset.toString(16)}: unsupported DWARF version ${version}.`);
    return null;
  }
  const fields = version === DWARF_VERSION.maximumSupported
    ? await readVersionFiveHeader(cursor, initial.format)
    : await readLegacyHeader(cursor, section, initial.format);
  if (!fields || cursor.failed) return null;
  if (version === DWARF_VERSION.maximumSupported && fields.unitType != null &&
      (fields.unitType < DWARF_UNIT_TYPE.compile ||
       fields.unitType > DWARF_UNIT_TYPE.splitType)) {
    issues.push(
      `${section.name} at 0x${offset.toString(16)}: unsupported unit type ` +
      `0x${fields.unitType.toString(16)}.`
    );
    return null;
  }
  if (fields.addressSize < Uint8Array.BYTES_PER_ELEMENT ||
      fields.addressSize > DWARF_LIMIT.maximumAddressBytes) {
    issues.push(
      `${section.name} at 0x${offset.toString(16)}: unsupported address size ` +
      `${fields.addressSize}.`
    );
    return null;
  }
  return {
    offset,
    end: initial.end,
    length: initial.length,
    format: initial.format,
    version,
    unitType: fields.unitType,
    addressSize: fields.addressSize,
    abbreviationOffset: fields.abbreviationOffset,
    dataOffset: cursor.position
  };
};
