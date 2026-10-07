"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import {
  DWARF_ENCODING,
  DWARF_SECTION,
  DWARF_SENTINEL,
  DWARF_UNIT_TYPE,
  DWARF_VERSION
} from "./constants.js";
import { readDwarfInitialLength } from "./initial-length.js";
import { DwarfCursor } from "./cursor.js";
import type { DwarfSectionInput } from "./types.js";
import { dwarfSplitBaseName } from "./package-sections.js";

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
  typeSignature?: bigint;
  typeOffset?: bigint;
  dwoId?: bigint;
};

// Initial-length and unit-header layouts follow DWARF 5, sections 7.4 and 7.5.1:
// https://dwarfstd.org/doc/DWARF5.pdf

const readTypedUnitFields = async (
  cursor: DwarfCursor,
  unitType: number,
  format: 32 | 64
): Promise<{ typeSignature?: bigint; typeOffset?: bigint; dwoId?: bigint }> => {
  if (unitType === DWARF_UNIT_TYPE.type || unitType === DWARF_UNIT_TYPE.splitType) {
    const typeSignature = await cursor.uint64();
    const typeOffset = await cursor.unsigned(format / DWARF_ENCODING.bitsPerByte);
    return typeSignature == null || typeOffset == null ? {} : { typeSignature, typeOffset };
  } else if (unitType === DWARF_UNIT_TYPE.skeleton ||
             unitType === DWARF_UNIT_TYPE.splitCompile) {
    const dwoId = await cursor.uint64();
    return dwoId == null ? {} : { dwoId };
  }
  return {};
};

const readVersionFiveHeader = async (
  cursor: DwarfCursor,
  format: 32 | 64
): Promise<Omit<DwarfUnitHeader, "offset" | "end" | "length" | "format" | "version" | "dataOffset"> | null> => {
  const unitType = await cursor.uint8();
  const addressSize = await cursor.uint8();
  const abbreviationOffset = await cursor.unsigned(format / DWARF_ENCODING.bitsPerByte);
  if (unitType == null || addressSize == null || abbreviationOffset == null) return null;
  return { unitType, addressSize, abbreviationOffset,
    ...await readTypedUnitFields(cursor, unitType, format) };
};

const readLegacyHeader = async (
  cursor: DwarfCursor,
  section: DwarfSectionInput,
  format: 32 | 64
): Promise<Omit<DwarfUnitHeader, "offset" | "end" | "length" | "format" | "version" | "dataOffset"> | null> => {
  const abbreviationOffset = await cursor.unsigned(format / DWARF_ENCODING.bitsPerByte);
  const addressSize = await cursor.uint8();
  if (addressSize == null || abbreviationOffset == null) return null;
  const unitType = dwarfSplitBaseName(section.name) === DWARF_SECTION.types ? DWARF_UNIT_TYPE.type : null;
  return { unitType, addressSize, abbreviationOffset,
    ...await readTypedUnitFields(cursor, unitType ?? DWARF_UNIT_TYPE.compile, format) };
};

type UnitFields = Omit<DwarfUnitHeader, "offset" | "end" | "length" | "format" | "version" | "dataOffset">;

const validUnitFields = (fields: UnitFields, version: number, section: DwarfSectionInput,
  offset: number, issues: string[]): boolean => {
  if (version === DWARF_VERSION.maximumSupported && fields.unitType != null &&
      (fields.unitType < DWARF_UNIT_TYPE.compile ||
       fields.unitType > DWARF_UNIT_TYPE.splitType)) {
    issues.push(
      `${section.name} at 0x${offset.toString(16)}: unsupported unit type ` +
      `0x${fields.unitType.toString(16)}.`
    );
    return false;
  }
  if (fields.addressSize < Uint8Array.BYTES_PER_ELEMENT) {
    issues.push(
      `${section.name} at 0x${offset.toString(16)}: unsupported address size ` +
      `${fields.addressSize}.`
    );
    return false;
  }
  return true;
};

const readVersion = async (cursor: DwarfCursor): Promise<number | null> => {
  const version = await cursor.uint16();
  if (version == null) return null;
  if (version >= DWARF_VERSION.minimumSupported && version <= DWARF_VERSION.maximumSupported) return version;
  cursor.fail("unsupported DWARF version " + version);
  return null;
};

export const parseDwarfUnitHeader = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  offset: number,
  littleEndian: boolean,
  issues: string[]
): Promise<DwarfUnitHeader | null> => {
  const lengthCursor = new DwarfCursor(reader, section, offset, section.size, littleEndian, issues);
  const initial = await readDwarfInitialLength(lengthCursor);
  if (!initial || initial.length === DWARF_SENTINEL.zeroUnitLength) return null;
  const cursor = new DwarfCursor(reader, section, lengthCursor.position,
    initial.end, littleEndian, issues);
  const version = await readVersion(cursor);
  if (version == null) return null;
  const fields = version === DWARF_VERSION.maximumSupported
    ? await readVersionFiveHeader(cursor, initial.format)
    : await readLegacyHeader(cursor, section, initial.format);
  if (!fields || cursor.failed) return null;
  if (!validUnitFields(fields, version, section, offset, issues)) return null;
  return {
    offset,
    end: initial.end,
    length: initial.length,
    format: initial.format,
    version,
    ...fields,
    dataOffset: cursor.position
  };
};
