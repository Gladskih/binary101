import type { PeWindowsParseResult } from "../core/parse-result.js";
import { mappedRvaSize } from "../rva-mapping.js";
import type { PeDataDirectory } from "../types.js";

const rvaCoverageIssue = (pe: PeWindowsParseResult, rva: number, size: number): string | null => {
  const mapped = mappedRvaSize(pe.rvaToOff, rva, size, pe.fileSize);
  if (!mapped) return "RVA does not map to file data";
  return mapped === size ? null : "Declared range is only partly backed by file data";
};

// The Certificate Table address is a file offset, unlike ordinary directory RVAs.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
const certificateCoverageIssue = (fileSize: number, offset: number, size: number): string | null => {
  if (!offset) return "File offset is zero";
  if (!size) return "Declared size is zero";
  return size <= fileSize - offset ? null : "Declared range extends beyond the file";
};

export const peDirectoryCoverageIssue = (
  directory: PeDataDirectory, pe: PeWindowsParseResult
): string | null => {
  const { name, rva, size } = directory;
  // GLOBALPTR is a register value with a reserved size field, rather than a byte range.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
  if (name === "GLOBALPTR") return pe.globalPtr?.warnings?.[0] ?? null;
  if (name === "SECURITY") return certificateCoverageIssue(pe.fileSize, rva, size);
  if (!rva) return "RVA is zero";
  if (!size) return "Declared size is zero";
  return rvaCoverageIssue(pe, rva, size);
};
