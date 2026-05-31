"use strict";

import type { PeParseResult } from "../core/parse-result.js";
import { isPeWindowsParseResult } from "../core/parse-result.js";

// Microsoft PE/COFF, "COFF File Header": the Windows loader limits images to 96 sections.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
const WINDOWS_LOADER_SECTION_LIMIT = 96;

export const collectPeHeaderFieldWarnings = (pe: PeParseResult): string[] => {
  const warnings: string[] = [];
  if ((pe.coff.NumberOfSections >>> 0) > WINDOWS_LOADER_SECTION_LIMIT) {
    warnings.push(
      "NumberOfSections is greater than 96; the Windows loader limits image section count to 96."
    );
  }
  if (
    isPeWindowsParseResult(pe) &&
    (pe.opt.SectionAlignment >>> 0) < (pe.opt.FileAlignment >>> 0)
  ) {
    warnings.push(
      "SectionAlignment is smaller than FileAlignment; PE images require SectionAlignment >= FileAlignment."
    );
  }
  return warnings;
};
