import type { PeSection } from "../types.js";
import type { PeLegacyCodeViewInfo } from "./legacy-codeview.js";
import type { LegacyCodeViewSegmentMap } from "./legacy-codeview-modules.js";
import type { LegacyCodeViewProcedure } from "./legacy-codeview-procedure-symbols.js";
import { IMAGE_DEBUG_TYPE_OMAP_FROM_SRC, IMAGE_DEBUG_TYPE_OMAP_TO_SRC } from "./types.js";

export type CodeViewProcedureAddress = { rva: number; section: number; reason?: never }
  | { reason: string; rva?: never; section?: never };
type SegmentMapping = { map?: LegacyCodeViewSegmentMap; reason?: string };
type SectionPlacement = { section: number; offset: number } | { reason: string };

const unsigned32 = (value: number): boolean => Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;

// TIS CodeView 7.3/7.4: directory generations update earlier records; sstSegMap
// maps one-based logical indices. A failed map must never become a direct-section fallback.
// https://openwatcom.org/ftp/devel/docs/CodeView.pdf
const directoryMappings = (info: PeLegacyCodeViewInfo): SegmentMapping[] => {
  let current: SegmentMapping = {};
  return info.directories.map(directory => {
    const entries = directory.subsections.filter(section => section.type === 0x12d);
    const maps = new Set(entries.flatMap(section => section.data?.kind === "segmentMap" ? [section.data] : []));
    if (entries.length) {
      current = maps.size === 1 && entries.every(section => section.data?.kind === "segmentMap")
        ? { map: [...maps][0]! } : { reason: "Segment map is not decoded or multiple maps are ambiguous." };
    }
    if (directory.subsections.some(section => section.type === 0x12c)) {
      current = { reason: "Legacy frame map requires a separate address interpretation." };
    }
    return current;
  });
};

const descriptorIssue = (descriptor: LegacyCodeViewSegmentMap["segments"][number]): string | undefined => {
  // OMFSegDescFlags: 32-bit=0x8, selector=0x100, absolute=0x200, group=0x1000.
  // LLVM DbiStreamBuilder::createSectionMap uses Frame=section+1 and Offset=0
  // for PE selector descriptors; other addressing modes are not PE section indices.
  // https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/lib/DebugInfo/PDB/Native/DbiStreamBuilder.cpp#L351
  if (descriptor.flags & 0x200) return "Absolute segment frame is not a PE section selector.";
  if (descriptor.flags & 0x1000 || descriptor.group) return "Segment group addressing is not resolved.";
  if (descriptor.overlay) return "Overlay segment addressing is not resolved.";
  if (!(descriptor.flags & 0x100)) return "Segment frame is not a PE section selector.";
  if (!(descriptor.flags & 8)) return "Segment descriptor is not 32-bit linear addressing.";
  if (descriptor.flags & ~0x10f) return "Segment descriptor contains unsupported flags.";
  return undefined;
};

const mapIssue = (map: LegacyCodeViewSegmentMap, segment: number): string | undefined => {
  if (!Number.isInteger(map.logicalCount) || map.logicalCount < 0 || map.logicalCount > map.segments.length) {
    return "Invalid logical segment count in CodeView map.";
  }
  if (segment > map.logicalCount) return "Stored logical segment index is outside the segment map.";
  return descriptorIssue(map.segments[segment - 1]!);
};

const placeInSection = (mapping: SegmentMapping, procedure: LegacyCodeViewProcedure): SectionPlacement => {
  const { segment, offset } = procedure.storedLocation!;
  if (!mapping.map) return { section: segment, offset };
  const issue = mapIssue(mapping.map, segment);
  if (issue) return { reason: issue };
  const descriptor = mapping.map.segments[segment - 1]!;
  if (!unsigned32(descriptor.size) || offset >= descriptor.size || procedure.codeLength! > descriptor.size - offset) {
    return { reason: "Procedure exceeds logical segment bounds." };
  }
  if (!unsigned32(descriptor.offset)) return { reason: "Invalid logical segment displacement." };
  return { section: descriptor.frame, offset: descriptor.offset + offset };
};

const sectionExtent = (section: PeSection): number => section.virtualSize || section.sizeOfRawData;

const sectionIssue = (section: PeSection): string | undefined => {
  if (![section.virtualAddress, section.virtualSize, section.sizeOfRawData].every(unsigned32)) {
    return "CodeView address refers to an invalid PE section.";
  }
  if (section.virtualAddress + sectionExtent(section) > 0x100000000) return "PE section exceeds 32-bit RVA space.";
  return undefined;
};

const overlappingSection = (sections: readonly PeSection[], index: number, rva: number, length: number): boolean =>
  sections.some((other, position) => position !== index - 1 &&
    sectionExtent(other) > 0 && other.virtualAddress < rva + Math.max(length, 1) &&
    rva < other.virtualAddress + sectionExtent(other));

const resolveSection = (sections: readonly PeSection[], placement: SectionPlacement,
  length: number): CodeViewProcedureAddress => {
  if ("reason" in placement) return placement;
  const { section: index, offset } = placement;
  if (!Number.isInteger(index) || index < 1 || index > sections.length) {
    return { reason: "Stored PE section index is outside the image section table." };
  }
  const section = sections[index - 1]!;
  const extent = sectionExtent(section);
  const issue = sectionIssue(section);
  if (issue) return { reason: issue };
  if (offset >= extent || length > extent - offset) return { reason: "Procedure exceeds PE section bounds." };
  const rva = section.virtualAddress + offset;
  if (overlappingSection(sections, index, rva, length)) {
    return { reason: "Procedure overlaps another PE section; image mapping is ambiguous." };
  }
  return { rva, section: index };
};

const procedureIssue = (procedure: LegacyCodeViewProcedure): string | undefined => {
  const location = procedure.storedLocation;
  if (!location || procedure.codeLength === undefined) return "Stored location or code length is unavailable.";
  if (!unsigned32(location.segment) || location.segment < 1 || location.segment > 0xffff ||
      !unsigned32(location.offset) || !unsigned32(procedure.codeLength)) return "Stored procedure address or length is invalid.";
  return undefined;
};

/** Resolve image addresses on demand without duplicating derived fields in parsed records. */
export const createCodeViewProcedureResolver = (info: PeLegacyCodeViewInfo, sections: readonly PeSection[],
  debugEntries: readonly { type: number }[] = []
): ((directory: number, procedure: LegacyCodeViewProcedure) => CodeViewProcedureAddress) => {
  const mappings = directoryMappings(info);
  // OMAP may require original section headers and may split/delete code ranges.
  // Current image sections alone cannot establish a valid source-to-image mapping.
  // https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-omap
  const transformed = debugEntries.some(entry => entry.type === IMAGE_DEBUG_TYPE_OMAP_TO_SRC ||
    entry.type === IMAGE_DEBUG_TYPE_OMAP_FROM_SRC);
  return (directory, procedure) => {
    if (!/^NB0[5-9]$|^NB11$/.test(info.signature)) return { reason: "Address resolution requires PE C7 CodeView records." };
    if (transformed) return { reason: "OMAP requires validated original section headers and range translation." };
    const issue = procedureIssue(procedure);
    if (issue) return { reason: issue };
    const mapping = mappings[directory];
    if (!mapping) return { reason: "CodeView directory generation is unavailable." };
    if (mapping.reason) return { reason: mapping.reason };
    // Wine codeview_get_address uses one-based PE section indices when no map is present.
    // https://github.com/wine-mirror/wine/blob/wine-10.0/dlls/dbghelp/msc.c#L1740
    return resolveSection(sections, placeInSection(mapping, procedure), procedure.codeLength!);
  };
};
