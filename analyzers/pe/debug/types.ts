"use strict";

// Microsoft PE format documents the IMAGE_DEBUG_DIRECTORY.Type field layout.
// Windows SDK winnt.h defines the MSVC/debug type constants used here.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
export const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
export const IMAGE_DEBUG_TYPE_FPO = 3;
export const IMAGE_DEBUG_TYPE_MISC = 4;
export const IMAGE_DEBUG_TYPE_VC_FEATURE = 12;
export const IMAGE_DEBUG_TYPE_POGO = 13;
export const IMAGE_DEBUG_TYPE_REPRO = 16;
export const IMAGE_DEBUG_TYPE_EMBEDDED_PORTABLE_PDB = 17;
export const IMAGE_DEBUG_TYPE_SPGO = 18;
export const IMAGE_DEBUG_TYPE_PDB_CHECKSUM = 19;
export const IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20;
export const IMAGE_DEBUG_TYPE_R2R_PERFMAP = 21;

export const DEBUG_TYPE_NAMES: Record<number, string> = {
  0: "UNKNOWN",
  1: "COFF",
  [IMAGE_DEBUG_TYPE_CODEVIEW]: "CODEVIEW",
  [IMAGE_DEBUG_TYPE_FPO]: "FPO",
  [IMAGE_DEBUG_TYPE_MISC]: "MISC",
  5: "EXCEPTION",
  6: "FIXUP",
  7: "OMAP_TO_SRC",
  8: "OMAP_FROM_SRC",
  9: "BORLAND",
  10: "RESERVED10",
  11: "CLSID",
  [IMAGE_DEBUG_TYPE_VC_FEATURE]: "VC_FEATURE",
  [IMAGE_DEBUG_TYPE_POGO]: "POGO",
  14: "ILTCG",
  15: "MPX",
  [IMAGE_DEBUG_TYPE_REPRO]: "REPRO",
  [IMAGE_DEBUG_TYPE_EMBEDDED_PORTABLE_PDB]: "EMBEDDED DEBUG",
  [IMAGE_DEBUG_TYPE_SPGO]: "SPGO",
  [IMAGE_DEBUG_TYPE_PDB_CHECKSUM]: "SYMBOL HASH",
  [IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS]: "EX_DLLCHARACTERISTICS",
  [IMAGE_DEBUG_TYPE_R2R_PERFMAP]: "R2R_PERFMAP"
};
