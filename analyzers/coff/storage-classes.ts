"use strict";

// Microsoft PE/COFF, "Storage Class" values in IMAGE_SYMBOL records.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#storage-class
export const COFF_STORAGE_CLASS = {
  END_OF_FUNCTION: 0xff,
  NULL: 0,
  AUTOMATIC: 1,
  EXTERNAL: 2,
  STATIC: 3,
  REGISTER: 4,
  EXTERNAL_DEF: 5,
  LABEL: 6,
  UNDEFINED_LABEL: 7,
  MEMBER_OF_STRUCT: 8,
  ARGUMENT: 9,
  STRUCT_TAG: 10,
  MEMBER_OF_UNION: 11,
  UNION_TAG: 12,
  TYPE_DEFINITION: 13,
  UNDEFINED_STATIC: 14,
  ENUM_TAG: 15,
  MEMBER_OF_ENUM: 16,
  REGISTER_PARAM: 17,
  BIT_FIELD: 18,
  BLOCK: 100,
  FUNCTION: 101,
  END_OF_STRUCT: 102,
  FILE: 103,
  SECTION: 104,
  WEAK_EXTERNAL: 105,
  CLR_TOKEN: 107
} as const;

export const COFF_STORAGE_CLASS_NAMES: Record<number, string> = Object.fromEntries(
  Object.entries(COFF_STORAGE_CLASS).map(([name, value]) => [value, name])
);
