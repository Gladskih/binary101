"use strict";

import type { PeParseResult } from "../core/parse-result.js";
import { peSectionNameValue } from "../sections/name.js";
import type { PeSection } from "../types.js";

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

export const collectPeSectionFieldWarnings = (pe: PeParseResult): string[] =>
  pe.sections
    .map((section, index) => ({ section, index }))
    .filter(({ section }) => hasObjectRelocationOrLineNumberFields(section))
    .map(({ section, index }) =>
      `Section ${getSectionLabel(section, index)} has COFF object relocation/line-number fields set; ` +
      "these fields should be zero in executable images."
    );
