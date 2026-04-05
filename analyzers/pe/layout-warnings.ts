"use strict";
import { getMappedImageRanges, getUnmappedFileRanges } from "./layout-file-ranges.js";
import {
  isPeWindowsParseResult,
  type PeParseResult,
  type PeWindowsParseResult
} from "./parse-result.js";
import { peSectionNameValue } from "./section-name.js";
import type { PeSection } from "./types.js";
// Microsoft PE/COFF: IMAGE_FILE_HEADER is 20 bytes. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
const IMAGE_FILE_HEADER_SIZE = 20;
// Microsoft PE/COFF: each IMAGE_SECTION_HEADER entry is 40 bytes. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
const IMAGE_SECTION_HEADER_SIZE = 40;
// Microsoft PE format overview: the PE header is aligned on an 8-byte boundary. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#overview
const PE_HEADER_ALIGNMENT = 8;
// Microsoft PE/COFF section-data rules call out 4 KiB pages for x86/MIPS and 8 KiB pages for Itanium when applying the low-SectionAlignment special case. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-data
const COMMON_ARCH_PAGE_SIZE = 0x1000;
const ITANIUM_PAGE_SIZE = 0x2000;
// Microsoft PE/COFF: IMAGE_FILE_MACHINE_IA64. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
const IMAGE_FILE_MACHINE_IA64 = 0x0200;
// Microsoft PE/COFF section characteristic bits. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
const IMAGE_SCN_CNT_CODE = 0x00000020, IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
type NamedSectionRange = {
  index: number; label: string; virtualAddress: number; virtualEndAligned: number | null;
  rawStart: number; rawEnd: number
};
const formatHex = (value: number): string => `0x${Math.max(0, Math.trunc(value)).toString(16).padStart(8, "0")}`;
const alignUp = (value: number, alignment: number): number =>
  !alignment ? value : value % alignment === 0 ? value : value + alignment - (value % alignment);
const getSectionLabel = (section: PeSection, index: number): string =>
  peSectionNameValue(section.name) || `(unnamed #${index + 1})`;
const getActualHeaderEnd = (pe: PeParseResult): number =>
  pe.dos.e_lfanew + 4 + IMAGE_FILE_HEADER_SIZE + pe.coff.SizeOfOptionalHeader +
  (pe.coff.NumberOfSections >>> 0) * IMAGE_SECTION_HEADER_SIZE;
const getHeaderSpanEnd = (pe: PeParseResult): number =>
  !isPeWindowsParseResult(pe)
    ? getActualHeaderEnd(pe)
    : Math.max(getActualHeaderEnd(pe), pe.opt.SizeOfHeaders >>> 0);
const getKnownFileSize = (fileSize?: number): number | null =>
  Number.isSafeInteger(fileSize) && fileSize != null && fileSize >= 0 ? fileSize : null;
const getArchitecturePageSize = (machine: number): number =>
  machine === IMAGE_FILE_MACHINE_IA64 ? ITANIUM_PAGE_SIZE : COMMON_ARCH_PAGE_SIZE;
const usesLowSectionAlignmentLayout = (pe: PeParseResult): boolean =>
  isPeWindowsParseResult(pe) && (pe.opt.SectionAlignment >>> 0) > 0 &&
  (pe.opt.SectionAlignment >>> 0) < getArchitecturePageSize(pe.coff.Machine >>> 0);
const isUninitializedDataOnlySection = (section: PeSection): boolean =>
  ((section.characteristics >>> 0) & IMAGE_SCN_CNT_UNINITIALIZED_DATA) !== 0 &&
  ((section.characteristics >>> 0) & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA)) === 0;
const getUnmappedDebugRanges = (pe: PeWindowsParseResult, mappedRanges: ReturnType<typeof getMappedImageRanges>) =>
  getUnmappedFileRanges(pe.debug?.rawDataRanges ?? [], mappedRanges);
const getMappedSectionSpan = (section: PeSection): number =>
  (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);
const getVirtualEndAligned = (section: PeSection, sectionAlignment: number): number | null =>
  getMappedSectionSpan(section)
    ? alignUp((section.virtualAddress >>> 0) + getMappedSectionSpan(section), sectionAlignment)
    : null;
const getNamedSectionRanges = (pe: PeParseResult): NamedSectionRange[] =>
  pe.sections.map((section, index) => ({
    index, label: getSectionLabel(section, index), virtualAddress: section.virtualAddress >>> 0,
    virtualEndAligned: getVirtualEndAligned(
      section,
      isPeWindowsParseResult(pe) ? pe.opt.SectionAlignment >>> 0 : 0
    ),
    rawStart: section.pointerToRawData >>> 0, rawEnd: (section.pointerToRawData >>> 0) + (section.sizeOfRawData >>> 0)
  }));
const addSectionHeaderWarnings = (pe: PeParseResult, warnings: Set<string>): void => {
  if ((pe.dos.e_lfanew & (PE_HEADER_ALIGNMENT - 1)) !== 0) {
    warnings.add(
      `PE header offset e_lfanew ${formatHex(pe.dos.e_lfanew)} is not ${PE_HEADER_ALIGNMENT}-byte aligned.`
    );
  }
  if (!isPeWindowsParseResult(pe)) return;
  const actualHeaderEnd = getActualHeaderEnd(pe);
  if ((pe.opt.SizeOfHeaders >>> 0) !== 0 && (pe.opt.SizeOfHeaders >>> 0) < actualHeaderEnd) {
    warnings.add(
      `SizeOfHeaders ${formatHex(pe.opt.SizeOfHeaders)} is smaller than the actual header span ` +
        `ending at ${formatHex(actualHeaderEnd)}.`
    );
  }
  if ((pe.opt.FileAlignment >>> 0) !== 0 && (pe.opt.SizeOfHeaders >>> 0) % (pe.opt.FileAlignment >>> 0) !== 0) {
    warnings.add(
      `SizeOfHeaders ${formatHex(pe.opt.SizeOfHeaders)} is not a multiple of FileAlignment ` +
        `${formatHex(pe.opt.FileAlignment)}.`
    );
  }
  if (usesLowSectionAlignmentLayout(pe) && (pe.opt.FileAlignment >>> 0) !== (pe.opt.SectionAlignment >>> 0)) {
    warnings.add(
      `FileAlignment ${formatHex(pe.opt.FileAlignment)} must match SectionAlignment ` +
        `${formatHex(pe.opt.SectionAlignment)} when SectionAlignment is below the architecture page size.`
    );
  }
};
const addSectionVirtualLayoutWarnings = (pe: PeParseResult, warnings: Set<string>): void => {
  if (!isPeWindowsParseResult(pe)) return;
  const sectionAlignment = pe.opt.SectionAlignment >>> 0;
  const ranges = getNamedSectionRanges(pe);
  for (const range of ranges) {
    if (sectionAlignment !== 0 && range.virtualAddress % sectionAlignment !== 0) {
      warnings.add(
        `Section ${range.label} VirtualAddress ${formatHex(range.virtualAddress)} is not a multiple ` +
          `of SectionAlignment ${formatHex(sectionAlignment)}.`
      );
    }
  }
  for (let index = 1; index < ranges.length; index += 1) {
    const previous = ranges[index - 1];
    const current = ranges[index];
    if (previous && current && current.virtualAddress < previous.virtualAddress) {
      warnings.add(
        `Section headers are not in ascending VirtualAddress order: ${previous.label} at ` +
          `${formatHex(previous.virtualAddress)} appears before ${current.label} at ` +
          `${formatHex(current.virtualAddress)}.`
      );
      break;
    }
  }
  const sortedRanges = ranges
    .filter(range => range.virtualEndAligned != null)
    .sort((left, right) => left.virtualAddress - right.virtualAddress || left.index - right.index);
  for (let index = 1; index < sortedRanges.length; index += 1) {
    const previous = sortedRanges[index - 1];
    const current = sortedRanges[index];
    if (!previous || !current || previous.virtualEndAligned == null) continue;
    if (current.virtualAddress < previous.virtualEndAligned) {
      warnings.add(
        `Sections ${previous.label} and ${current.label} overlap in the loaded image RVA layout ` +
          `(${formatHex(current.virtualAddress)} < ${formatHex(previous.virtualEndAligned)}).`
      );
      continue;
    }
    if (current.virtualAddress > previous.virtualEndAligned) {
      warnings.add(
        `Sections ${previous.label} and ${current.label} are not adjacent in RVA order; expected ` +
          `${formatHex(previous.virtualEndAligned)} but found ${formatHex(current.virtualAddress)}.`
      );
    }
  }
};
const addSectionRawLayoutWarnings = (pe: PeParseResult, warnings: Set<string>): void => {
  const ranges = getNamedSectionRanges(pe).filter(range => range.rawEnd > range.rawStart);
  const headerSpanEnd = getHeaderSpanEnd(pe);
  const fileAlignment = isPeWindowsParseResult(pe) ? pe.opt.FileAlignment >>> 0 : 0;
  for (const range of ranges) {
    if (fileAlignment !== 0 && range.rawStart % fileAlignment !== 0) {
      warnings.add(
        `Section ${range.label} PointerToRawData ${formatHex(range.rawStart)} is not a multiple of ` +
          `FileAlignment ${formatHex(fileAlignment)}.`
      );
    }
    if (
      fileAlignment !== 0 &&
      (pe.sections[range.index]?.sizeOfRawData ?? 0) !== 0 &&
      (pe.sections[range.index]?.sizeOfRawData ?? 0) % fileAlignment !== 0
    ) {
      warnings.add(
        `Section ${range.label} SizeOfRawData ${formatHex(pe.sections[range.index]!.sizeOfRawData)} is not ` +
          `a multiple of FileAlignment ${formatHex(fileAlignment)}.`
      );
    }
    if (range.rawStart < headerSpanEnd) {
      warnings.add(
        `Section ${range.label} raw data starts at ${formatHex(range.rawStart)}, which overlaps the ` +
          `headers ending at ${formatHex(headerSpanEnd)}.`
      );
    }
  }
  const sortedRanges = ranges
    .slice()
    .sort((left, right) => left.virtualAddress - right.virtualAddress || left.index - right.index);
  for (let index = 1; index < sortedRanges.length; index += 1) {
    const previous = sortedRanges[index - 1];
    const current = sortedRanges[index];
    if (!previous || !current) continue;
    if (current.rawStart < previous.rawStart) {
      warnings.add(
        `Section raw data is not ordered by RVA: ${current.label} starts at ${formatHex(current.rawStart)} ` +
          `after ${previous.label} at ${formatHex(previous.virtualAddress)} starts at ` +
          `${formatHex(previous.rawStart)}.`
      );
    }
    if (current.rawStart < previous.rawEnd) {
      warnings.add(
        `Sections ${previous.label} and ${current.label} overlap in file data ` +
          `(${formatHex(current.rawStart)} < ${formatHex(previous.rawEnd)}).`
      );
    }
  }
};
const addSectionConsistencyWarnings = (pe: PeParseResult, warnings: Set<string>): void => {
  const lowSectionAlignmentLayout = usesLowSectionAlignmentLayout(pe);
  const ranges = getNamedSectionRanges(pe);
  for (const range of ranges) {
    const section = pe.sections[range.index];
    if (!section) continue;
    if (lowSectionAlignmentLayout && range.rawEnd > range.rawStart && range.rawStart !== range.virtualAddress) {
      warnings.add(
        `Section ${range.label} raw data offset ${formatHex(range.rawStart)} must match its VirtualAddress ` +
          `${formatHex(range.virtualAddress)} when SectionAlignment is below the architecture page size.`
      );
    }
    if (!isUninitializedDataOnlySection(section)) continue;
    if ((section.sizeOfRawData >>> 0) !== 0) warnings.add(
      `Section ${range.label} contains only uninitialized data but SizeOfRawData is ` +
        `${formatHex(section.sizeOfRawData)} instead of zero.`
    );
    if ((section.pointerToRawData >>> 0) !== 0) warnings.add(
      `Section ${range.label} contains only uninitialized data but PointerToRawData is ` +
        `${formatHex(section.pointerToRawData)} instead of zero.`
    );
  }
};
const addSecurityAndDebugTailWarnings = (pe: PeParseResult, warnings: Set<string>, fileSize?: number): void => {
  if (!isPeWindowsParseResult(pe)) return;
  const knownFileSize = getKnownFileSize(fileSize);
  const mappedRanges = getMappedImageRanges(getHeaderSpanEnd(pe), pe.sections, knownFileSize);
  const rawMappedEnd = mappedRanges.length ? mappedRanges[mappedRanges.length - 1]!.end : 0;
  const fileEnd = knownFileSize ?? rawMappedEnd + (pe.overlaySize >>> 0);
  const securityDir = pe.dirs.find(directory => directory.name === "SECURITY");
  const securityStart = securityDir?.size ? securityDir.rva >>> 0 : null;
  const securityEnd =
    securityDir?.size && securityStart != null ? securityStart + (securityDir.size >>> 0) : null;
  if (securityStart != null && securityEnd != null && securityStart < rawMappedEnd) {
    warnings.add(
      `Attribute certificate table starts at ${formatHex(securityStart)}, which overlaps mapped image ` +
        `bytes ending at ${formatHex(rawMappedEnd)}.`
    );
  }
  const debugRanges = getUnmappedDebugRanges(pe, mappedRanges);
  if (!debugRanges.length) {
    if (securityEnd != null && securityEnd !== fileEnd) warnings.add(
      `Attribute certificate table is not placed at the end of the file tail ` +
        `(${formatHex(securityEnd)} != ${formatHex(fileEnd)}).`
    );
    return;
  }
  const firstDebugStart = debugRanges[0]!.start;
  const lastDebugEnd = debugRanges[debugRanges.length - 1]!.end;
  if (firstDebugStart < rawMappedEnd) {
    warnings.add(
      `Debug raw data begins at ${formatHex(firstDebugStart)}, which overlaps mapped image bytes ` +
        `ending at ${formatHex(rawMappedEnd)}.`
    );
  }
  if (
    securityStart != null &&
    securityEnd != null &&
    debugRanges.some(range => range.start < securityEnd && range.end > securityStart)
  ) {
    warnings.add("Attribute certificate table and debug raw data overlap in the file tail.");
  }
  if (securityEnd != null && firstDebugStart !== securityEnd) {
    warnings.add(
      `Attribute certificate table does not immediately precede debug raw data ` +
        `(${formatHex(securityEnd)} -> ${formatHex(firstDebugStart)}).`
    );
  }
  for (let index = 1; index < debugRanges.length; index += 1) {
    const previous = debugRanges[index - 1];
    const current = debugRanges[index];
    if (!previous || !current || current.start <= previous.end) continue;
    warnings.add(
      `Debug raw data has a gap in the file tail ` +
        `(${formatHex(previous.end)} -> ${formatHex(current.start)}).`
    );
  }
  if (lastDebugEnd !== fileEnd) {
    warnings.add(
      `Debug raw data is not placed at the end of the file tail ` +
        `(${formatHex(lastDebugEnd)} != ${formatHex(fileEnd)}).`
    );
  }
};

export const collectPeLayoutWarnings = (pe: PeParseResult, fileSize?: number): string[] => {
  const warnings = new Set<string>();
  addSectionHeaderWarnings(pe, warnings);
  addSectionVirtualLayoutWarnings(pe, warnings);
  addSectionRawLayoutWarnings(pe, warnings);
  addSectionConsistencyWarnings(pe, warnings);
  addSecurityAndDebugTailWarnings(pe, warnings, fileSize);
  return [...warnings];
};
