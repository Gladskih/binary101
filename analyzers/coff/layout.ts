"use strict";

type CoffFieldWidth = "u8" | "u16" | "i16" | "u32";

export type CoffNumericField = {
  offset: number;
  width: CoffFieldWidth;
};

// Microsoft PE/COFF: IMAGE_FILE_HEADER, IMAGE_SECTION_HEADER, IMAGE_SYMBOL,
// IMAGE_RELOCATION, and IMAGE_LINENUMBER layouts.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
export const COFF_FILE_HEADER_BYTE_LENGTH = 20;
export const COFF_SECTION_HEADER_BYTE_LENGTH = 40;
export const COFF_SYMBOL_RECORD_BYTE_LENGTH = 18;
export const COFF_RELOCATION_RECORD_BYTE_LENGTH = 10;
export const COFF_LINE_NUMBER_RECORD_BYTE_LENGTH = 6;
export const COFF_DEBUG_SYMBOLS_HEADER_BYTE_LENGTH = 32;
export const COFF_SHORT_NAME_BYTE_LENGTH = 8;
export const COFF_PRINTABLE_SECTION_NAME_MIN_BYTE = 0x20;
export const COFF_PRINTABLE_SECTION_NAME_MAX_BYTE = 0x7e;

// Microsoft PE/COFF string tables start with a 4-byte total-size field.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#string-table
export const COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH = 4;
export const COFF_STRING_READ_CHUNK_BYTE_LENGTH = 256;

// Microsoft PE/COFF, IMAGE_FILE_HEADER.Characteristics.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
export const COFF_FILE_CHARACTERISTICS = {
  RELOCS_STRIPPED: 0x0001,
  EXECUTABLE_IMAGE: 0x0002,
  MACHINE_32BIT: 0x0100,
  DLL: 0x2000
} as const;

// Microsoft PE/COFF, IMAGE_SECTION_HEADER.Characteristics.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
export const COFF_SECTION_CHARACTERISTICS = {
  CNT_CODE: 0x00000020,
  CNT_INITIALIZED_DATA: 0x00000040,
  CNT_UNINITIALIZED_DATA: 0x00000080,
  LNK_NRELOC_OVFL: 0x01000000,
  MEM_EXECUTE: 0x20000000,
  MEM_READ: 0x40000000
} as const;

export const COFF_RELOCATION_EXTENDED_COUNT_SENTINEL = 0xffff;

export const COFF_FILE_HEADER_FIELDS = {
  Machine: { offset: 0, width: "u16" },
  NumberOfSections: { offset: 2, width: "u16" },
  TimeDateStamp: { offset: 4, width: "u32" },
  PointerToSymbolTable: { offset: 8, width: "u32" },
  NumberOfSymbols: { offset: 12, width: "u32" },
  SizeOfOptionalHeader: { offset: 16, width: "u16" },
  Characteristics: { offset: 18, width: "u16" }
} as const satisfies Record<string, CoffNumericField>;

export const COFF_SECTION_HEADER_FIELDS = {
  Name: { offset: 0, width: "u8" },
  VirtualSize: { offset: 8, width: "u32" },
  VirtualAddress: { offset: 12, width: "u32" },
  SizeOfRawData: { offset: 16, width: "u32" },
  PointerToRawData: { offset: 20, width: "u32" },
  PointerToRelocations: { offset: 24, width: "u32" },
  PointerToLinenumbers: { offset: 28, width: "u32" },
  NumberOfRelocations: { offset: 32, width: "u16" },
  NumberOfLinenumbers: { offset: 34, width: "u16" },
  Characteristics: { offset: 36, width: "u32" }
} as const satisfies Record<string, CoffNumericField>;

export const COFF_SYMBOL_FIELDS = {
  Name: { offset: 0, width: "u8" },
  Value: { offset: 8, width: "u32" },
  SectionNumber: { offset: 12, width: "i16" },
  Type: { offset: 14, width: "u16" },
  StorageClass: { offset: 16, width: "u8" },
  NumberOfAuxSymbols: { offset: 17, width: "u8" }
} as const satisfies Record<string, CoffNumericField>;

export const COFF_SYMBOL_NAME_FIELDS = {
  ShortNameOrZeroes: { offset: 0, width: "u32" },
  StringTableOffset: { offset: 4, width: "u32" }
} as const satisfies Record<string, CoffNumericField>;

export const COFF_AUX_FUNCTION_DEFINITION_FIELDS = {
  TagIndex: { offset: 0, width: "u32" },
  TotalSize: { offset: 4, width: "u32" },
  PointerToLineNumber: { offset: 8, width: "u32" },
  PointerToNextFunction: { offset: 12, width: "u32" }
} as const satisfies Record<string, CoffNumericField>;

export const COFF_AUX_BEGIN_END_FUNCTION_FIELDS = {
  LineNumber: { offset: 4, width: "u16" },
  PointerToNextFunction: { offset: 12, width: "u32" }
} as const satisfies Record<string, CoffNumericField>;

export const COFF_AUX_WEAK_EXTERNAL_FIELDS = {
  TagIndex: { offset: 0, width: "u32" },
  Characteristics: { offset: 4, width: "u32" }
} as const satisfies Record<string, CoffNumericField>;

export const COFF_AUX_SECTION_DEFINITION_FIELDS = {
  Length: { offset: 0, width: "u32" },
  NumberOfRelocations: { offset: 4, width: "u16" },
  NumberOfLineNumbers: { offset: 6, width: "u16" },
  CheckSum: { offset: 8, width: "u32" },
  Number: { offset: 12, width: "u16" },
  Selection: { offset: 14, width: "u8" }
} as const satisfies Record<string, CoffNumericField>;

export const COFF_RELOCATION_FIELDS = {
  VirtualAddress: { offset: 0, width: "u32" },
  SymbolTableIndex: { offset: 4, width: "u32" },
  Type: { offset: 8, width: "u16" }
} as const satisfies Record<string, CoffNumericField>;

export const COFF_LINE_NUMBER_FIELDS = {
  SymbolTableIndexOrVirtualAddress: { offset: 0, width: "u32" },
  LineNumber: { offset: 4, width: "u16" }
} as const satisfies Record<string, CoffNumericField>;

export const COFF_DEBUG_SYMBOLS_HEADER_FIELDS = {
  NumberOfSymbols: { offset: 0, width: "u32" },
  LvaToFirstSymbol: { offset: 4, width: "u32" },
  NumberOfLineNumbers: { offset: 8, width: "u32" },
  LvaToFirstLineNumber: { offset: 12, width: "u32" },
  RvaToFirstByteOfCode: { offset: 16, width: "u32" },
  RvaToLastByteOfCode: { offset: 20, width: "u32" },
  RvaToFirstByteOfData: { offset: 24, width: "u32" },
  RvaToLastByteOfData: { offset: 28, width: "u32" }
} as const satisfies Record<string, CoffNumericField>;

export const readCoffField = (
  view: DataView,
  recordOffset: number,
  field: CoffNumericField
): number => {
  const offset = recordOffset + field.offset;
  if (field.width === "u8") return view.getUint8(offset);
  if (field.width === "u16") return view.getUint16(offset, true);
  if (field.width === "i16") return view.getInt16(offset, true);
  return view.getUint32(offset, true);
};
