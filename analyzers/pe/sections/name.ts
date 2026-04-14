"use strict";

export type PeSectionName =
  | { kind: "inline"; value: string }
  | { kind: "coff-string-table"; value: string; offset: number };

export const inlinePeSectionName = (value: string): PeSectionName => ({
  kind: "inline",
  value
});

export const coffStringTablePeSectionName = (value: string, offset: number): PeSectionName => ({
  kind: "coff-string-table",
  value,
  offset
});

export const peSectionNameValue = (sectionName: PeSectionName): string => sectionName.value;

export const peSectionNameOffset = (sectionName: PeSectionName): number | null =>
  sectionName.kind === "coff-string-table" ? sectionName.offset : null;
