"use strict";

import { COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH } from "../../analyzers/coff/layout.js";

type CoffStringTableEntry = {
  name: string;
  offset: number;
};

const createSyntheticLongSectionName = (index: number): string =>
  `sect_${String(index).padStart(4, "0")}`;

export const createLegacyCoffStringTableFixture = (
  ...names: string[]
): { entries: CoffStringTableEntry[]; size: number } => {
  let offset = COFF_STRING_TABLE_SIZE_FIELD_BYTE_LENGTH;
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
