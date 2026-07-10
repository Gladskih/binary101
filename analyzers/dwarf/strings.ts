"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { DWARF_ENCODING, DWARF_SECTION } from "./constants.js";
import { DwarfCursor } from "./cursor.js";
import type {
  DwarfFormValue,
  DwarfSectionInput,
  DwarfSectionSource,
  DwarfUnitContext
} from "./types.js";

const findSection = (
  sections: Map<string, DwarfSectionSource>,
  name: string,
  issues: string[]
): DwarfSectionSource | null => {
  const source = sections.get(name);
  if (!source) issues.push(`${name}: section is required to resolve a DWARF string.`);
  return source ?? null;
};

const safeSectionOffset = (
  value: bigint,
  section: DwarfSectionInput,
  issues: string[]
): number | null => {
  const offset = Number(value);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= section.size) {
    issues.push(`${section.name}: string offset ${value.toString()} falls outside the section.`);
    return null;
  }
  return offset;
};

const readStringAt = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  offsetValue: bigint,
  littleEndian: boolean,
  issues: string[]
): Promise<string | null> => {
  const offset = safeSectionOffset(offsetValue, section, issues);
  if (offset == null) return null;
  return new DwarfCursor(
    reader,
    section,
    offset,
    section.size,
    littleEndian,
    issues
  ).cstring();
};

const indexedStringOffset = async (
  sections: Map<string, DwarfSectionSource>,
  index: bigint,
  context: DwarfUnitContext,
  littleEndian: boolean,
  issues: string[]
): Promise<bigint | null> => {
  const source = findSection(sections, DWARF_SECTION.stringOffsets, issues);
  if (!source || context.stringOffsetsBase == null) {
    if (context.stringOffsetsBase == null) {
      issues.push("DW_FORM_strx requires DW_AT_str_offsets_base in the unit root.");
    }
    return null;
  }
  const entryByteLength = context.format / DWARF_ENCODING.bitsPerByte;
  const offsetValue = context.stringOffsetsBase + index * BigInt(entryByteLength);
  const offset = safeSectionOffset(offsetValue, source.section, issues);
  if (offset == null) return null;
  const cursor = new DwarfCursor(
    source.reader,
    source.section,
    offset,
    source.section.size,
    littleEndian,
    issues
  );
  return cursor.unsigned(entryByteLength);
};

export const resolveDwarfString = async (
  sections: Map<string, DwarfSectionSource>,
  value: DwarfFormValue | undefined,
  context: DwarfUnitContext,
  littleEndian: boolean,
  issues: string[]
): Promise<string | null> => {
  if (!value) return null;
  if (value.kind === "string") return value.value;
  if (value.kind === "string-offset") {
    const source = findSection(sections, value.sectionName, issues);
    return source
      ? readStringAt(source.reader, source.section, value.value, littleEndian, issues)
      : null;
  }
  if (value.kind !== "string-index") return null;
  const offset = await indexedStringOffset(
    sections,
    value.value,
    context,
    littleEndian,
    issues
  );
  const strings = findSection(sections, DWARF_SECTION.strings, issues);
  return offset != null && strings
    ? readStringAt(strings.reader, strings.section, offset, littleEndian, issues)
    : null;
};
