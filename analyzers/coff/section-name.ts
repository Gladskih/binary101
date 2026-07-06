"use strict";

import type { CoffSectionName } from "./types.js";

export const inlineCoffSectionName = (value: string): CoffSectionName => ({
  kind: "inline",
  value
});

export const coffStringTableSectionName = (value: string, offset: number): CoffSectionName => ({
  kind: "coff-string-table",
  value,
  offset
});

export const coffSectionNameValue = (sectionName: CoffSectionName): string => sectionName.value;

export const coffSectionNameOffset = (sectionName: CoffSectionName): number | null =>
  sectionName.kind === "coff-string-table" ? sectionName.offset : null;
