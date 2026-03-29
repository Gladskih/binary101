"use strict";

import type {
  Pe32OptionalHeader,
  PeOptionalHeader,
  PeOptionalHeaderKind,
  PePlusOptionalHeader,
  PeRomOptionalHeader,
  PeWindowsOptionalHeader
} from "./types.js";

export const PE32_OPTIONAL_HEADER_MAGIC = 0x10b;
export const PE32_PLUS_OPTIONAL_HEADER_MAGIC = 0x20b;
// Microsoft PE format + ntimage.h define 0x107 as IMAGE_ROM_OPTIONAL_HDR_MAGIC.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only
// https://doxygen.reactos.org/d5/d44/ntimage_8h_source.html#l730
export const ROM_OPTIONAL_HEADER_MAGIC = 0x107;

export const getOptionalHeaderKind = (magic: number): PeOptionalHeaderKind => {
  if (magic === PE32_OPTIONAL_HEADER_MAGIC) return "pe32";
  if (magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC) return "pe32+";
  if (magic === ROM_OPTIONAL_HEADER_MAGIC) return "rom";
  return "unknown";
};

export const isPe32OptionalHeader = (opt: PeOptionalHeader): opt is Pe32OptionalHeader =>
  opt.Magic === PE32_OPTIONAL_HEADER_MAGIC;

export const isPePlusOptionalHeader = (opt: PeOptionalHeader): opt is PePlusOptionalHeader =>
  opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC;

export const isPeRomOptionalHeader = (opt: PeOptionalHeader): opt is PeRomOptionalHeader =>
  opt.Magic === ROM_OPTIONAL_HEADER_MAGIC;

export const isPeWindowsOptionalHeader = (opt: PeOptionalHeader): opt is PeWindowsOptionalHeader =>
  opt.Magic === PE32_OPTIONAL_HEADER_MAGIC || opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC;
