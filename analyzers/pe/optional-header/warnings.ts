"use strict";

import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "./magic.js";

// Microsoft PE/COFF, "Optional Header": PE32 data directories start at 96 bytes,
// and PE32+ data directories start at 112 bytes.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
const PE32_DATA_DIRECTORY_START = 0x60;
const PE32_PLUS_DATA_DIRECTORY_START = 0x70;

const addWindowsOptionalHeaderSizeWarning = (
  sizeOfOptionalHeader: number,
  magic: number,
  warnings: string[]
): void => {
  const minimumSize =
    magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC
      ? PE32_PLUS_DATA_DIRECTORY_START
      : PE32_DATA_DIRECTORY_START;
  if (sizeOfOptionalHeader >= minimumSize) return;
  warnings.push(
    "SizeOfOptionalHeader is too small to contain the complete PE32/PE32+ optional header before data directories."
  );
};

const addDataDirectoryFitWarning = (
  numberOfRvaAndSizes: number,
  sizeOfOptionalHeader: number,
  ddStartRel: number,
  warnings: string[]
): void => {
  const fitCount = Math.max(0, Math.floor((sizeOfOptionalHeader - ddStartRel) / 8));
  if ((numberOfRvaAndSizes >>> 0) <= fitCount) return;
  warnings.push(
    `NumberOfRvaAndSizes declares ${numberOfRvaAndSizes} data directories, but only ` +
      `${fitCount} fit in SizeOfOptionalHeader.`
  );
};

export const collectWindowsOptionalHeaderWarnings = (
  sizeOfOptionalHeader: number,
  magic: number,
  numberOfRvaAndSizes: number,
  ddStartRel: number
): string[] => {
  const warnings: string[] = [];
  addWindowsOptionalHeaderSizeWarning(sizeOfOptionalHeader, magic, warnings);
  addDataDirectoryFitWarning(numberOfRvaAndSizes, sizeOfOptionalHeader, ddStartRel, warnings);
  return warnings;
};
