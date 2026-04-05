"use strict";

import type {
  PeHeaderParseResult,
  PeWindowsParseResult
} from "../../analyzers/pe/index.js";
import { inlinePeSectionName } from "../../analyzers/pe/section-name.js";
import type { PeSection } from "../../analyzers/pe/types.js";

// Microsoft PE/COFF: the PE signature occupies 4 bytes and IMAGE_FILE_HEADER is 20 bytes.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#overview
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
const PE_SIGNATURE_SIZE = 4;
const COFF_HEADER_SIZE = 20;
// Microsoft PE/COFF: IMAGE_FILE_MACHINE_I386.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
const IMAGE_FILE_MACHINE_I386 = 0x014c;
// Microsoft PE/COFF: each IMAGE_SECTION_HEADER entry is 40 bytes.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
const SECTION_HEADER_SIZE = 40;
// Microsoft PE/COFF: IMAGE_DEBUG_TYPE_CODEVIEW.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
// These fixtures use a conventional PE32 layout so only the anomaly under test changes:
// PE32 optional header size 0xe0 bytes, Magic 0x10b, FileAlignment 0x200, SectionAlignment 0x1000.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
const PE32_OPTIONAL_HEADER_SIZE = 0xe0;
const PE32_OPTIONAL_HEADER_MAGIC = 0x10b;
export const DEFAULT_FILE_ALIGNMENT = 0x200;
export const DEFAULT_SECTION_ALIGNMENT = 0x1000;
// Any aligned PE header offset beyond the DOS header would work; 0x80 keeps header-span math readable.
export const DEFAULT_PE_HEADER_OFFSET = 0x80;
// Microsoft PE/COFF: IMAGE_SCN_CNT_UNINITIALIZED_DATA marks sections that contain only
// uninitialized data.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
export const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;

const createDebugEntry = (
  pointerToRawData: number,
  sizeOfData: number,
  addressOfRawData: number
) => ({
  type: IMAGE_DEBUG_TYPE_CODEVIEW,
  typeName: "CODEVIEW",
  sizeOfData,
  addressOfRawData,
  pointerToRawData
});

export const createSection = (
  name: string,
  virtualAddress: number,
  pointerToRawData: number,
  virtualSize = DEFAULT_FILE_ALIGNMENT,
  sizeOfRawData = DEFAULT_FILE_ALIGNMENT,
  characteristics = 0
): PeSection => ({
  name: inlinePeSectionName(name),
  virtualAddress,
  pointerToRawData,
  virtualSize,
  sizeOfRawData,
  characteristics
});

export const getDeclaredHeaderSpan = (sectionCount: number): number =>
  DEFAULT_PE_HEADER_OFFSET +
  PE_SIGNATURE_SIZE +
  COFF_HEADER_SIZE +
  PE32_OPTIONAL_HEADER_SIZE +
  sectionCount * SECTION_HEADER_SIZE;

export const getHeaderSpanSmallerThanDeclared = (sectionCount: number): number =>
  getDeclaredHeaderSpan(sectionCount) - COFF_HEADER_SIZE;

export const getSectionRawEnd = (section: PeSection): number =>
  section.pointerToRawData + section.sizeOfRawData;

export const createMappedDebugEntry = (
  section: PeSection,
  rawOffsetInSection: number,
  sizeOfData: number
) => createDebugEntry(
  section.pointerToRawData + rawOffsetInSection,
  sizeOfData,
  section.virtualAddress + rawOffsetInSection
);

export const createUnmappedDebugEntry = (pointerToRawData: number, sizeOfData: number) =>
  createDebugEntry(pointerToRawData, sizeOfData, 0);

export const createDebugSection = (
  ...entries: Array<ReturnType<typeof createDebugEntry>>
): NonNullable<PeWindowsParseResult["debug"]> => ({
  entry: null,
  entries,
  rawDataRanges: entries.map(entry => ({
    start: entry.pointerToRawData,
    end: entry.pointerToRawData + entry.sizeOfData
  }))
});

export const createWindowsLayoutSubject = (...sections: PeSection[]): PeWindowsParseResult =>
  // This unit exercises layout analysis only. Populate only the fields collectPeLayoutWarnings reads.
  ({
    dos: { e_lfanew: DEFAULT_PE_HEADER_OFFSET },
    signature: "PE",
    coff: {
      Machine: IMAGE_FILE_MACHINE_I386,
      NumberOfSections: sections.length,
      SizeOfOptionalHeader: PE32_OPTIONAL_HEADER_SIZE
    },
    opt: {
      Magic: PE32_OPTIONAL_HEADER_MAGIC,
      FileAlignment: DEFAULT_FILE_ALIGNMENT,
      SectionAlignment: DEFAULT_SECTION_ALIGNMENT,
      SizeOfHeaders: DEFAULT_FILE_ALIGNMENT
    },
    dirs: [],
    sections,
    overlaySize: 0,
    debug: null
  } as unknown as PeWindowsParseResult);

export const createHeaderOnlyLayoutSubject = (
  e_lfanew: number,
  ...sections: PeSection[]
): PeHeaderParseResult =>
  // This unit exercises layout analysis only. Populate only the fields collectPeLayoutWarnings reads.
  ({
    dos: { e_lfanew },
    signature: "PE",
    coff: {
      Machine: IMAGE_FILE_MACHINE_I386,
      NumberOfSections: sections.length,
      SizeOfOptionalHeader: 0
    },
    opt: null,
    dirs: [],
    sections,
    overlaySize: 0
  } as unknown as PeHeaderParseResult);
