"use strict";

const addWindowsOptionalHeaderSizeWarning = (
  sizeOfOptionalHeader: number,
  dataDirectoryStartOffset: number,
  warnings: string[]
): void => {
  if (sizeOfOptionalHeader >= dataDirectoryStartOffset) return;
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
  numberOfRvaAndSizes: number,
  ddStartRel: number
): string[] => {
  const warnings: string[] = [];
  addWindowsOptionalHeaderSizeWarning(sizeOfOptionalHeader, ddStartRel, warnings);
  addDataDirectoryFitWarning(numberOfRvaAndSizes, sizeOfOptionalHeader, ddStartRel, warnings);
  return warnings;
};
