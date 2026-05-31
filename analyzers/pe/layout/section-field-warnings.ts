"use strict";

import type { PeParseResult } from "../core/parse-result.js";
import { peSectionNameValue } from "../sections/name.js";
import type { PeSection } from "../types.js";
import { formatSectionCharacteristicFlags } from "../constants.js";

// Microsoft PE/COFF, "Section Flags": TYPE_NO_PAD, LNK_* contribution flags,
// and IMAGE_SCN_ALIGN_* flags are object-file-only or obsolete object syntax.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
const OBJECT_ONLY_SECTION_FLAGS_MASK = 0x00000008 | 0x00000200 | 0x00000800 | 0x00001000;
const SECTION_ALIGNMENT_FLAGS_MASK = 0x00f00000;
const VALID_SECTION_ALIGNMENT_FLAGS_MASK = 0x00e00000;

const getSectionLabel = (section: PeSection, index: number): string =>
  peSectionNameValue(section.name) || `(unnamed #${index + 1})`;

// Microsoft PE/COFF, "Section Table": COFF relocation and line-number fields are
// zero for executable images, with line numbers deprecated.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
const hasObjectRelocationOrLineNumberFields = (section: PeSection): boolean =>
  (section.pointerToRelocations >>> 0) !== 0 ||
  (section.pointerToLinenumbers >>> 0) !== 0 ||
  (section.numberOfRelocations >>> 0) !== 0 ||
  (section.numberOfLinenumbers >>> 0) !== 0;

const addObjectFieldWarning = (section: PeSection, index: number, warnings: string[]): void => {
  if (!hasObjectRelocationOrLineNumberFields(section)) return;
  warnings.push(
    `Section ${getSectionLabel(section, index)} has COFF object relocation/line-number fields set; ` +
    "these fields should be zero in executable images."
  );
};

// Microsoft PE/COFF, "Grouped Sections": "$" is object-file syntax, never image syntax.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#grouped-sections-object-only
const addGroupedNameWarning = (section: PeSection, warnings: string[]): void => {
  if (!peSectionNameValue(section.name).includes("$")) return;
  warnings.push(
    "Section name contains \"$\"; grouped section names are object-file syntax and image section names never " +
    "contain \"$\"."
  );
};

const getObjectOnlySectionFlags = (section: PeSection): number => {
  const alignmentFlags = (section.characteristics >>> 0) & SECTION_ALIGNMENT_FLAGS_MASK;
  const validAlignmentFlags = alignmentFlags <= VALID_SECTION_ALIGNMENT_FLAGS_MASK ? alignmentFlags : 0;
  return ((section.characteristics >>> 0) & OBJECT_ONLY_SECTION_FLAGS_MASK) | validAlignmentFlags;
};

const addObjectOnlyFlagWarning = (section: PeSection, index: number, warnings: string[]): void => {
  const flags = getObjectOnlySectionFlags(section);
  if (!flags) return;
  warnings.push(
    `Section ${getSectionLabel(section, index)} has object-only section flags set: ` +
    `${formatSectionCharacteristicFlags(flags).join(", ")}.`
  );
};

export const collectPeSectionFieldWarnings = (pe: PeParseResult): string[] => {
  const warnings: string[] = [];
  pe.sections.forEach((section, index) => {
    addObjectFieldWarning(section, index, warnings);
    addGroupedNameWarning(section, warnings);
    addObjectOnlyFlagWarning(section, index, warnings);
  });
  return warnings;
};
