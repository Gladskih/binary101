"use strict";

import {
  resolveCoffSectionName,
  type CoffStringTableResolver
} from "../../coff/section-string-table.js";
import { coffSectionNameOffset, coffSectionNameValue } from "../../coff/section-name.js";
import {
  inlinePeSectionName,
  peSectionNameFromStringTable,
  type PeSectionName
} from "./name.js";

const toPeSectionName = (sectionName: Awaited<ReturnType<typeof resolveCoffSectionName>>["name"]): PeSectionName => {
  const offset = coffSectionNameOffset(sectionName);
  return offset == null
    ? inlinePeSectionName(coffSectionNameValue(sectionName))
    : peSectionNameFromStringTable(coffSectionNameValue(sectionName), offset);
};

export const resolvePeSectionName = async (
  rawName: string,
  stringTableResolver: CoffStringTableResolver | null
): Promise<{ name: PeSectionName; warning?: string }> => {
  const resolved = await resolveCoffSectionName(rawName, stringTableResolver);
  return {
    name: toPeSectionName(resolved.name),
    ...(resolved.warning ? { warning: resolved.warning } : {})
  };
};
