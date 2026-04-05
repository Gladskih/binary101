"use strict";

import type {
  PeCodeViewEntry,
  PeDebugDirectoryEntry
} from "../../analyzers/pe/debug-directory.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type { PeSection } from "../../analyzers/pe/types.js";
import {
  createBasePe,
  createPeSection
} from "./pe-renderer-headers-fixture.js";

const createDebugRawRange = (entry: PeDebugDirectoryEntry) => ({
  start: entry.pointerToRawData,
  end: entry.pointerToRawData + entry.sizeOfData
});

export const createDebugViewEntry = (
  type: number,
  addressOfRawData: number,
  pointerToRawData: number,
  sizeOfData = 0x20
): PeDebugDirectoryEntry => ({
  type,
  typeName: `TYPE_${type}`,
  sizeOfData,
  addressOfRawData,
  pointerToRawData
});

export const createDebugViewCodeView = (id: number): PeCodeViewEntry => ({
  guid: `fixture-guid-${id}`,
  age: id,
  path: `fixture-${id}.pdb`
});

export const createPeWithDebugViewSection = (): PeWindowsParseResult => {
  const pe = createBasePe();
  pe.sections = [createPeSection("S0", {
    virtualAddress: 0x1000,
    pointerToRawData: 0x400,
    sizeOfRawData: 0x200
  })];
  pe.coff.NumberOfSections = pe.sections.length;
  return pe;
};

export const createMappedDebugViewEntry = (
  section: PeSection,
  type: number,
  rawOffset: number,
  sizeOfData = 0x20
): PeDebugDirectoryEntry => createDebugViewEntry(
  type,
  section.virtualAddress + rawOffset,
  section.pointerToRawData + rawOffset,
  sizeOfData
);

export const createSectionCoveredRawOnlyDebugViewEntry = (
  section: PeSection,
  type: number,
  rawOffset: number,
  sizeOfData = 0x20
): PeDebugDirectoryEntry => createDebugViewEntry(
  type,
  0,
  section.pointerToRawData + rawOffset,
  sizeOfData
);

export const createDebugViewSection = (
  entries: PeDebugDirectoryEntry[],
  codeViewEntry: PeCodeViewEntry | null = null,
  warning: string | null = null
): NonNullable<PeWindowsParseResult["debug"]> => ({
  entry: codeViewEntry,
  entries,
  rawDataRanges: entries.map(createDebugRawRange),
  ...(warning ? { warning } : {})
});

export const createSequentialDebugViewSection = (types: number[]) =>
  createDebugViewSection(
    types.map((type, index) => createDebugViewEntry(type, 0, 0x200 + index * 0x20))
  );

export const createRepeatedDebugViewSection = (type: number, count: number) =>
  createSequentialDebugViewSection(Array.from({ length: count }, () => type));
