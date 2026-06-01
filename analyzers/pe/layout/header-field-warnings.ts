"use strict";

import type { PeParseResult } from "../core/parse-result.js";
import { isPeWindowsParseResult } from "../core/parse-result.js";
import { PE32_OPTIONAL_HEADER_MAGIC, PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../optional-header/magic.js";

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
// Microsoft PE/COFF, "Optional Header": PE32+ permits a 64-bit address space
// but still limits the image size to 2 GB.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
const MAXIMUM_PE32_PLUS_IMAGE_SIZE = 0x80000000;
// Microsoft PE/COFF, "DLL Characteristics": bits 0x0001 through 0x0008 are reserved.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics
const RESERVED_DLL_CHARACTERISTICS_MASK = 0x000f;
const IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020;
const IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800;
// Microsoft PE/COFF, "Characteristics": these COFF file flags are deprecated, obsolete,
// or reserved and should be zero in current images.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
const NON_STANDARD_COFF_CHARACTERISTICS = [
  [0x0004, "LINE_NUMS_STRIPPED"],
  [0x0008, "LOCAL_SYMS_STRIPPED"],
  [0x0010, "AGGRESSIVE_WS_TRIM"],
  [0x0040, "RESERVED_0040"],
  [0x0080, "BYTES_REVERSED_LO"],
  [0x8000, "BYTES_REVERSED_HI"]
] as const;

const isPowerOfTwo = (value: number): boolean => value > 0 && (value & (value - 1)) === 0;
const formatHex16 = (value: number): string => `0x${(value & 0xffff).toString(16).padStart(4, "0")}`;
const formatNamedBits = (bits: readonly (readonly [number, string])[], value: number): string =>
  bits
    .filter(([bit]) => ((value >>> 0) & bit) !== 0)
    .map(([bit, name]) => `${name} (${formatHex16(bit)})`)
    .join(", ");
const isNonZeroDataDirectory = (rva: number, size: number): boolean =>
  (rva >>> 0) !== 0 || (size >>> 0) !== 0;
const hasDataDirectory = (pe: PeParseResult, name: string): boolean =>
  pe.dirs.some(directory => directory.name === name && isNonZeroDataDirectory(directory.rva, directory.size));

const addCoffWarnings = (pe: PeParseResult, warnings: string[]): void => {
  if ((pe.coff.NumberOfSections >>> 0) > WINDOWS_LOADER_SECTION_LIMIT) {
    warnings.push(
      "NumberOfSections is greater than 96; the Windows loader limits image section count to 96."
    );
  }
  if (((pe.coff.Characteristics >>> 0) & IMAGE_FILE_EXECUTABLE_IMAGE) === 0) {
    warnings.push(
      "COFF Characteristics does not set IMAGE_FILE_EXECUTABLE_IMAGE; the PE spec says this indicates a linker error."
    );
  }
  const nonStandardCoffCharacteristics = formatNamedBits(
    NON_STANDARD_COFF_CHARACTERISTICS,
    pe.coff.Characteristics
  );
  if (nonStandardCoffCharacteristics.length) {
    warnings.push(
      `COFF Characteristics contains deprecated or reserved bits: ${nonStandardCoffCharacteristics}.`
    );
  }
};

const addReservedDataDirectoryWarnings = (pe: PeParseResult, warnings: string[]): void => {
  for (const directory of pe.dirs) {
    if (directory.name === "ARCHITECTURE" && isNonZeroDataDirectory(directory.rva, directory.size)) {
      warnings.push("ARCHITECTURE data directory is reserved and must be zero.");
    }
    if (directory.name === "GLOBALPTR" && (directory.size >>> 0) !== 0) {
      warnings.push("GLOBALPTR data directory Size must be zero.");
    }
    if (directory.name === "RESERVED" && isNonZeroDataDirectory(directory.rva, directory.size)) {
      warnings.push("Reserved data directory is reserved and must be zero.");
    }
  }
};

const addAlignmentWarnings = (pe: PeParseResult, warnings: string[]): void => {
  if (!isPeWindowsParseResult(pe)) return;
  if ((pe.opt.SectionAlignment >>> 0) < (pe.opt.FileAlignment >>> 0)) {
    warnings.push(
      "SectionAlignment is smaller than FileAlignment; PE images require SectionAlignment >= FileAlignment."
    );
  }
  if (
    !isPowerOfTwo(pe.opt.FileAlignment >>> 0) ||
    (pe.opt.FileAlignment >>> 0) < MINIMUM_FILE_ALIGNMENT ||
    (pe.opt.FileAlignment >>> 0) > MAXIMUM_FILE_ALIGNMENT
  ) {
    warnings.push("FileAlignment is not a power of two between 512 and 64K inclusive.");
  }
  if (typeof pe.opt.ImageBase === "bigint" && pe.opt.ImageBase % IMAGE_BASE_ALIGNMENT !== 0n) {
    warnings.push("ImageBase is not a multiple of 64K.");
  }
};

const addOptionalFieldWarnings = (pe: PeParseResult, warnings: string[]): void => {
  if (!isPeWindowsParseResult(pe)) return;
  if (pe.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC && (pe.opt.SizeOfImage >>> 0) > MAXIMUM_PE32_PLUS_IMAGE_SIZE) {
    warnings.push(
      "PE32+ SizeOfImage exceeds 2 GiB; PE32+ images are documented as limited to a 2 GiB image size."
    );
  }
  if ((pe.opt.Win32VersionValue >>> 0) !== 0) {
    warnings.push("Win32VersionValue is reserved and must be zero.");
  }
  if ((pe.opt.LoaderFlags >>> 0) !== 0) {
    warnings.push("LoaderFlags is reserved and must be zero.");
  }
  if (
    typeof pe.opt.SizeOfStackCommit === "bigint" &&
    typeof pe.opt.SizeOfStackReserve === "bigint" &&
    pe.opt.SizeOfStackCommit > pe.opt.SizeOfStackReserve
  ) {
    warnings.push("Stack/heap commit size exceeds reserve size.");
  }
  if (
    typeof pe.opt.SizeOfHeapCommit === "bigint" &&
    typeof pe.opt.SizeOfHeapReserve === "bigint" &&
    pe.opt.SizeOfHeapCommit > pe.opt.SizeOfHeapReserve &&
    !warnings.includes("Stack/heap commit size exceeds reserve size.")
  ) {
    warnings.push("Stack/heap commit size exceeds reserve size.");
  }
};

const addDllCharacteristicWarnings = (pe: PeParseResult, warnings: string[]): void => {
  if (!isPeWindowsParseResult(pe)) return;
  if (((pe.opt.DllCharacteristics >>> 0) & RESERVED_DLL_CHARACTERISTICS_MASK) !== 0) {
    warnings.push(
      `DllCharacteristics has reserved bits set: ${formatHex16(pe.opt.DllCharacteristics)}. ` +
        "Reserved bits 0x0001, 0x0002, 0x0004, and 0x0008 must be zero."
    );
  }
  if (
    pe.opt.Magic === PE32_OPTIONAL_HEADER_MAGIC &&
    ((pe.opt.DllCharacteristics >>> 0) & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) !== 0
  ) {
    warnings.push(
      "HIGH_ENTROPY_VA is set on PE32, but the flag describes support for high-entropy 64-bit virtual address space."
    );
  }
};

const addDirectoryConflictWarnings = (pe: PeParseResult, warnings: string[]): void => {
  if (!isPeWindowsParseResult(pe)) return;
  if (
    ((pe.coff.Characteristics >>> 0) & IMAGE_FILE_RELOCS_STRIPPED) !== 0 &&
    (hasDataDirectory(pe, "BASERELOC") || (pe.reloc?.totalEntries ?? 0) > 0)
  ) {
    warnings.push("RELOCS_STRIPPED is set, but the image declares base relocations.");
  }
  if (
    ((pe.opt.DllCharacteristics >>> 0) & IMAGE_DLLCHARACTERISTICS_NO_BIND) !== 0 &&
    (hasDataDirectory(pe, "BOUND_IMPORT") || (pe.boundImports?.entries.length ?? 0) > 0)
  ) {
    warnings.push("NO_BIND is set, but the image contains bound import metadata.");
  }
};

export const collectPeHeaderFieldWarnings = (pe: PeParseResult): string[] => {
  const warnings: string[] = [];
  addCoffWarnings(pe, warnings);
  addAlignmentWarnings(pe, warnings);
  addOptionalFieldWarnings(pe, warnings);
  addDllCharacteristicWarnings(pe, warnings);
  addReservedDataDirectoryWarnings(pe, warnings);
  addDirectoryConflictWarnings(pe, warnings);
  return warnings;
};
