"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import {
  DWARF_ATTRIBUTE,
  DWARF_SENTINEL
} from "./constants.js";
import { DwarfCursor } from "./cursor.js";
import { readDwarfForm } from "./forms.js";
import { resolveDwarfString } from "./strings.js";
import type {
  DwarfAbbreviation,
  DwarfFormValue,
  DwarfSectionInput,
  DwarfTagCount,
  DwarfUnitContext,
  DwarfUnitRoot
} from "./types.js";
import type { DwarfUnitHeader } from "./unit-header.js";

const ROOT_DIE_DEPTH = 0;

const numericValue = (value: DwarfFormValue | undefined): bigint | null => {
  if (value?.kind === "unsigned" || value?.kind === "signed") return value.value;
  return null;
};

const safeLanguage = (value: DwarfFormValue | undefined): number | null => {
  const numeric = numericValue(value);
  if (numeric == null || numeric < 0n || numeric > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(numeric);
};

const optionalString = (key: string, value: string | null): Record<string, string> =>
  value == null ? {} : { [key]: value };

const buildRoot = async (
  reader: FileRangeReader,
  sections: Map<string, DwarfSectionInput>,
  tag: number,
  values: Map<number, DwarfFormValue>,
  context: DwarfUnitContext,
  littleEndian: boolean,
  issues: string[]
): Promise<DwarfUnitRoot> => {
  const language = safeLanguage(values.get(DWARF_ATTRIBUTE.language));
  const [name, producer, compilationDirectory] = await Promise.all([
    resolveDwarfString(
      reader,
      sections,
      values.get(DWARF_ATTRIBUTE.name),
      context,
      littleEndian,
      issues
    ),
    resolveDwarfString(
      reader,
      sections,
      values.get(DWARF_ATTRIBUTE.producer),
      context,
      littleEndian,
      issues
    ),
    resolveDwarfString(
      reader,
      sections,
      values.get(DWARF_ATTRIBUTE.compilationDirectory),
      context,
      littleEndian,
      issues
    )
  ]);
  return {
    tag,
    ...optionalString("name", name),
    ...optionalString("producer", producer),
    ...(language == null
      ? {}
      : { language }),
    ...optionalString("compilationDirectory", compilationDirectory)
  };
};

const readAttributes = async (
  cursor: DwarfCursor,
  abbreviation: DwarfAbbreviation,
  context: DwarfUnitContext,
  capture: boolean
): Promise<Map<number, DwarfFormValue>> => {
  const values = new Map<number, DwarfFormValue>();
  for (const attribute of abbreviation.attributes) {
    const value = await readDwarfForm(cursor, attribute, context);
    if (value == null) break;
    if (capture) values.set(attribute.name, value);
    if (attribute.name === DWARF_ATTRIBUTE.stringOffsetsBase) {
      context.stringOffsetsBase = numericValue(value);
    }
  }
  return values;
};

const incrementTag = (counts: Map<number, number>, tag: number): void => {
  counts.set(tag, (counts.get(tag) ?? 0) + 1);
};

const toTagCounts = (counts: Map<number, number>): DwarfTagCount[] =>
  [...counts.entries()].map(([tag, count]) => ({ tag, count }));

export const parseDwarfDies = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  sections: Map<string, DwarfSectionInput>,
  header: DwarfUnitHeader,
  abbreviations: Map<bigint, DwarfAbbreviation>,
  littleEndian: boolean,
  issues: string[]
): Promise<{ root: DwarfUnitRoot | null; tagCounts: DwarfTagCount[]; maxDepth: number }> => {
  const cursor = new DwarfCursor(
    reader,
    section,
    header.dataOffset,
    header.end,
    littleEndian,
    issues
  );
  const context: DwarfUnitContext = {
    version: header.version,
    format: header.format,
    addressSize: header.addressSize,
    stringOffsetsBase: null
  };
  const counts = new Map<number, number>();
  let depth = 0;
  let maxDepth = 0;
  let root: DwarfUnitRoot | null = null;
  while (!cursor.failed && cursor.position < cursor.end) {
    const code = await cursor.uleb();
    if (code == null) break;
    if (code === DWARF_SENTINEL.nullDie) {
      if (depth === ROOT_DIE_DEPTH) break;
      depth -= 1;
      continue;
    }
    const abbreviation = abbreviations.get(code);
    if (!abbreviation) {
      cursor.fail(`Unknown abbreviation code ${code.toString()}`);
      break;
    }
    incrementTag(counts, abbreviation.tag);
    maxDepth = Math.max(maxDepth, depth);
    const captureRoot = root == null && depth === ROOT_DIE_DEPTH;
    const values = await readAttributes(cursor, abbreviation, context, captureRoot);
    if (captureRoot && !cursor.failed) {
      root = await buildRoot(
        reader,
        sections,
        abbreviation.tag,
        values,
        context,
        littleEndian,
        issues
      );
    }
    if (abbreviation.hasChildren) depth += 1;
  }
  return { root, tagCounts: toTagCounts(counts), maxDepth };
};
