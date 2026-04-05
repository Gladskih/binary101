"use strict";

export const PE32_OPTIONAL_HEADER_MAGIC = 0x10b;
export const PE32_PLUS_OPTIONAL_HEADER_MAGIC = 0x20b;
// Microsoft PE format + ntimage.h define 0x107 as IMAGE_ROM_OPTIONAL_HDR_MAGIC.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only
// https://doxygen.reactos.org/d5/d44/ntimage_8h_source.html#l730
export const ROM_OPTIONAL_HEADER_MAGIC = 0x107;
