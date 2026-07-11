"use strict";

import {
  DWARF_ENCODING,
  DWARF_FORMAT,
  DWARF_INITIAL_LENGTH,
  DWARF_LIMIT,
  DWARF_LINE_ENCODING,
  DWARF_SENTINEL,
  DWARF_VERSION
} from "./constants.js";
import { DwarfCursor } from "./cursor.js";
import { readDwarfLineTables } from "./line-tables.js";
import type {
  DwarfSectionInput,
  DwarfSectionSource
} from "./types.js";
import type { DwarfLineFile } from "./types.js";

export type DwarfLineHeader = {
  offset: number;
  end: number;
  programOffset: number;
  length: bigint;
  format: 32 | 64;
  version: number;
  addressSize: number;
  minimumInstructionLength: number;
  maximumOperationsPerInstruction: number;
  lineRange: number;
  opcodeBase: number;
  standardOperandCounts: number[];
  directoryCount: number;
  fileCount: number;
  files: DwarfLineFile[];
};

// Initial length and line header layouts follow DWARF 5 sections 6.2.4 and 7.4:
// https://dwarfstd.org/doc/DWARF5.pdf
const readInitialLength = async (
  cursor: DwarfCursor,
  section: DwarfSectionInput,
  offset: number,
  issues: string[]
): Promise<{ length: bigint; format: 32 | 64; end: number } | null> => {
  const initial = await cursor.uint32();
  if (initial == null) return null;
  let length = BigInt(initial);
  let format: 32 | 64 = DWARF_FORMAT.dwarf32;
  if (initial === DWARF_INITIAL_LENGTH.format64Escape) {
    const extended = await cursor.uint64();
    if (extended == null) return null;
    length = extended;
    format = DWARF_FORMAT.dwarf64;
  } else if (initial >= DWARF_INITIAL_LENGTH.reservedMinimum) {
    issues.push(`${section.name} at 0x${offset.toString(16)}: reserved initial length.`);
    return null;
  }
  const numericLength = Number(length);
  if (!Number.isSafeInteger(numericLength)) {
    issues.push(`${section.name}: line program length ${length.toString()} is too large to index.`);
    return null;
  }
  const declaredEnd = cursor.position + numericLength;
  if (declaredEnd > section.size) {
    issues.push(
      `${section.name} at 0x${offset.toString(16)}: line program extends beyond the section.`
    );
  }
  return { length, format, end: Math.min(declaredEnd, section.size) };
};

export const parseDwarfLineHeader = async (
  source: DwarfSectionSource,
  sections: Map<string, DwarfSectionSource>,
  offset: number,
  littleEndian: boolean,
  issues: string[]
): Promise<DwarfLineHeader | null> => {
  const { reader, section } = source;
  const lengthCursor = new DwarfCursor(reader, section, offset, section.size, littleEndian, issues);
  const initial = await readInitialLength(lengthCursor, section, offset, issues);
  if (!initial || initial.length === DWARF_SENTINEL.zeroUnitLength) return null;
  const cursor = new DwarfCursor(
    reader, section, lengthCursor.position, initial.end, littleEndian, issues
  );
  const version = await cursor.uint16();
  if (version == null || version < DWARF_VERSION.minimumSupported ||
      version > DWARF_VERSION.maximumSupported) {
    if (version != null) cursor.fail(`Unsupported DWARF line version ${version}`);
    return null;
  }
  const addressSize = version === DWARF_VERSION.maximumSupported
    ? await cursor.uint8()
    : DWARF_LINE_ENCODING.unknownLegacyAddressSize;
  const segmentSelectorSize = version === DWARF_VERSION.maximumSupported
    ? await cursor.uint8()
    : DWARF_LINE_ENCODING.noSegmentSelectorBytes;
  if (addressSize == null || segmentSelectorSize == null) return null;
  if (segmentSelectorSize !== DWARF_LINE_ENCODING.noSegmentSelectorBytes) {
    cursor.fail(`Segmented line addresses are unsupported (selector size ${segmentSelectorSize})`);
    return null;
  }
  if (version === DWARF_VERSION.maximumSupported &&
      (addressSize < Uint8Array.BYTES_PER_ELEMENT ||
       addressSize > DWARF_LIMIT.maximumAddressBytes)) {
    cursor.fail(`Unsupported line address size ${addressSize}`);
    return null;
  }
  const headerLength = await cursor.unsigned(initial.format / DWARF_ENCODING.bitsPerByte);
  if (headerLength == null || headerLength > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  const headerEnd = cursor.position + Number(headerLength);
  if (headerEnd > initial.end) {
    cursor.fail("Line header extends beyond its program");
    return null;
  }
  const headerCursor = new DwarfCursor(reader, section, cursor.position, headerEnd, littleEndian, issues);
  const minimumInstructionLength = await headerCursor.uint8();
  const maximumOperationsPerInstruction =
    version >= DWARF_VERSION.maximumOperationsPerInstructionIntroduced
      ? await headerCursor.uint8()
      : DWARF_LINE_ENCODING.firstStandardOpcode;
  const defaultIsStatement = await headerCursor.uint8();
  const lineBase = await headerCursor.uint8();
  const lineRange = await headerCursor.uint8();
  const opcodeBase = await headerCursor.uint8();
  if (minimumInstructionLength == null || maximumOperationsPerInstruction == null ||
      defaultIsStatement == null || lineBase == null || lineRange == null ||
      opcodeBase == null) return null;
  if (minimumInstructionLength === 0 || maximumOperationsPerInstruction === 0 ||
      lineRange === 0 || opcodeBase === 0) {
    headerCursor.fail("Line header contains a zero divisor or opcode base");
    return null;
  }
  const standardOperandCounts: number[] = [];
  for (
    let opcode = DWARF_LINE_ENCODING.firstStandardOpcode;
    opcode < opcodeBase;
    opcode += 1
  ) {
    const count = await headerCursor.uint8();
    if (count == null) return null;
    standardOperandCounts.push(count);
  }
  const tables = await readDwarfLineTables(headerCursor, version, {
    sections,
    littleEndian,
    issues,
    dwarfFormat: initial.format
  });
  if (!tables || headerCursor.failed) return null;
  if (headerCursor.position !== headerEnd) {
    headerCursor.notice(`${headerEnd - headerCursor.position} unparsed line header bytes`);
  }
  return {
    offset,
    end: initial.end,
    programOffset: headerEnd,
    length: initial.length,
    format: initial.format,
    version,
    addressSize,
    minimumInstructionLength,
    maximumOperationsPerInstruction,
    lineRange,
    opcodeBase,
    standardOperandCounts,
    ...tables
  };
};
