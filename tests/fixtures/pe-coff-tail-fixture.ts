"use strict";

// Microsoft PE/COFF: each COFF symbol-table record is 18 bytes.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table
export const COFF_SYMBOL_RECORD_SIZE = 18;

// Microsoft PE/COFF: the string table starts with a 4-byte size field.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-string-table
const COFF_STRING_TABLE_SIZE_FIELD_BYTES = 4;

type CoffStringTableEntry = {
  name: string;
  offset: number;
};

const createSyntheticLongSectionName = (index: number): string =>
  `sect_${String(index).padStart(4, "0")}`;

export const createLegacyCoffStringTableFixture = (
  ...names: string[]
): { entries: CoffStringTableEntry[]; size: number } => {
  let offset = COFF_STRING_TABLE_SIZE_FIELD_BYTES;
  const entries = names.map(name => {
    const entry = { name, offset };
    offset += name.length + 1;
    return entry;
  });
  return { entries, size: offset };
};

export const createSyntheticLegacyCoffStringTableFixture = (
  count: number
): { entries: CoffStringTableEntry[]; size: number } =>
  createLegacyCoffStringTableFixture(
    ...Array.from({ length: count }, (_, index) => createSyntheticLongSectionName(index))
  );
