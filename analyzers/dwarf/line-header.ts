import { DwarfStringReader } from "./strings.js";
"use strict";

import { DWARF_SENTINEL, DWARF_VERSION } from "./constants.js";
import { DwarfCursor } from "./cursor.js";
import { readDwarfInitialLength } from "./initial-length.js";
import { readDwarfLinePrologue } from "./line-prologue.js";
import type {
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
  lineBase: number;
  defaultIsStatement: boolean;
  opcodeBase: number;
  standardOperandCounts: number[];
  directories: string[];
  files: DwarfLineFile[];
};

// Initial length and line header layouts follow DWARF 5 sections 6.2.4 and 7.4:
// https://dwarfstd.org/doc/DWARF5.pdf
const readLineAddressParameters = async (cursor: DwarfCursor, version: number) => {
  if (version < 5) return { addressSize: 0 };
  const addressSize = await cursor.uint8();
  const selectorSize = await cursor.uint8();
  if (addressSize == null || selectorSize == null) return null;
  if (selectorSize !== 0) {
    cursor.fail(`Segmented line addresses are unsupported (selector size ${selectorSize})`);
    return null;
  }
  if (addressSize === 0) { cursor.fail("Unsupported line address size 0"); return null; }
  return { addressSize };
};

const readVersion = async (cursor: DwarfCursor): Promise<number | null> => {
  const version = await cursor.uint16();
  if (version == null) return null;
  if (version >= DWARF_VERSION.minimumSupported && version <= DWARF_VERSION.maximumSupported) return version;
  cursor.fail("Unsupported DWARF line version " + version);
  return null;
};

export const parseDwarfLineHeader = async (
  source: DwarfSectionSource,
  sections: Map<string, DwarfSectionSource>,
  offset: number,
  littleEndian: boolean,
  issues: string[], strings = new DwarfStringReader(sections, littleEndian ? "little" : "big", issues)
): Promise<DwarfLineHeader | null> => {
  const { reader, section } = source;
  const lengthCursor = new DwarfCursor(reader, section, offset, section.size, littleEndian, issues);
  const initial = await readDwarfInitialLength(lengthCursor);
  if (!initial || initial.length === DWARF_SENTINEL.zeroUnitLength) return null;
  const cursor = new DwarfCursor(
    reader, section, lengthCursor.position, initial.end, littleEndian, issues
  );
  const version = await readVersion(cursor);
  if (version == null) return null;
  const addresses = await readLineAddressParameters(cursor, version);
  if (!addresses) return null;
  const prologue = await readDwarfLinePrologue(source, cursor, version, initial.format,
    sections, littleEndian ? "little" : "big", issues, strings);
  if (!prologue) return null;
  return {
    offset,
    end: initial.end,
    length: initial.length,
    format: initial.format,
    version,
    ...addresses,
    ...prologue
  };
};
