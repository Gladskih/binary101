"use strict";

import type { PeParseResult } from "../core/parse-result.js";
import { isPeWindowsParseResult } from "../core/parse-result.js";

// Microsoft PE/COFF, "COFF File Header": the Windows loader limits images to 96 sections.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
const WINDOWS_LOADER_SECTION_LIMIT = 96;
// Microsoft PE/COFF, "Optional Header Windows-Specific Fields": FileAlignment should be
// a power of two between 512 and 64 K inclusive.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-windows-specific-fields-image-only
const MINIMUM_FILE_ALIGNMENT = 0x200;
const MAXIMUM_FILE_ALIGNMENT = 0x10000;
// Microsoft PE/COFF, "Optional Header Windows-Specific Fields": ImageBase must be 64 K aligned.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-windows-specific-fields-image-only
const IMAGE_BASE_ALIGNMENT = 0x10000n;

const isPowerOfTwo = (value: number): boolean => value > 0 && (value & (value - 1)) === 0;

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
  if (
    isPeWindowsParseResult(pe) &&
    (
      !isPowerOfTwo(pe.opt.FileAlignment >>> 0) ||
      (pe.opt.FileAlignment >>> 0) < MINIMUM_FILE_ALIGNMENT ||
      (pe.opt.FileAlignment >>> 0) > MAXIMUM_FILE_ALIGNMENT
    )
  ) {
    warnings.push("FileAlignment is not a power of two between 512 and 64K inclusive.");
  }
  if (
    isPeWindowsParseResult(pe) &&
    typeof pe.opt.ImageBase === "bigint" &&
    pe.opt.ImageBase % IMAGE_BASE_ALIGNMENT !== 0n
  ) {
    warnings.push("ImageBase is not a multiple of 64K.");
  }
  return warnings;
};
