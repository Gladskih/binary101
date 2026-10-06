"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { DWARF_ATTRIBUTE, DWARF_SENTINEL } from "./constants.js";
import { DwarfCursor } from "./cursor.js";
import { readDwarfAttribute } from "./forms.js";
import type { DwarfStringReader } from "./strings.js";
import type {
  DwarfAbbreviation, DwarfAttribute, DwarfDie,
  DwarfSectionInput, DwarfUnitContext
} from "./types.js";
import type { DwarfUnitHeader } from "./unit-header.js";

const readAttributes = async (
  cursor: DwarfCursor,
  abbreviation: DwarfAbbreviation,
  context: DwarfUnitContext
): Promise<DwarfAttribute[]> => {
  const attributes: DwarfAttribute[] = [];
  for (const specification of abbreviation.attributes) {
    const attribute = await readDwarfAttribute(cursor, specification, context);
    if (!attribute) break;
    if (attributes.some(existing => existing.name === attribute.name)) {
      cursor.notice(`Duplicate DIE attribute 0x${attribute.name.toString(16)}`);
    }
    attributes.push(attribute);
  }
  return attributes;
};

const stringBase = (dies: DwarfDie[]): bigint | null => {
  const base = dies[0]?.attributes.find(item => item.name === DWARF_ATTRIBUTE.stringOffsetsBase);
  return base?.value.kind === "unsigned" ? base.value.value : null;
};

export const resolveDwarfDieStrings = async (
  dies: DwarfDie[],
  context: DwarfUnitContext,
  strings: DwarfStringReader
): Promise<DwarfDie[]> => {
  context.stringOffsetsBase = stringBase(dies);
  const resolved: DwarfDie[] = [];
  for (const die of dies) {
    const attributes: DwarfAttribute[] = [];
    for (const attribute of die.attributes) {
      const text = await strings.resolve(attribute.value, context);
      attributes.push(text == null ? attribute : {
        ...attribute, value: { kind: "string", value: text }
      });
    }
    resolved.push({ ...die, attributes });
  }
  return resolved;
};

// DIE hierarchy uses an explicit stack, so nesting is limited only by the input.
// DWARF 5 section 7.5.3: https://dwarfstd.org/doc/DWARF5.pdf
const readDie = async (cursor: DwarfCursor, abbreviations: Map<bigint, DwarfAbbreviation>,
  context: DwarfUnitContext, dies: DwarfDie[], parents: number[]): Promise<boolean> => {
  const offset = cursor.position;
  const code = await cursor.uleb();
  if (code == null) return false;
  if (code === DWARF_SENTINEL.nullDie) {
    if (!parents.length) {
      cursor.notice("Unexpected null DIE outside a child list");
      return false;
    }
    parents.pop();
    return true;
  }
  const abbreviation = abbreviations.get(code);
  if (!abbreviation) {
    cursor.fail(`Unknown abbreviation code ${code.toString()}`);
    return false;
  }
  if (dies.length && !parents.length) cursor.notice("Multiple root DIEs in one unit");
  const attributes = await readAttributes(cursor, abbreviation, context);
  dies.push({ offset, tag: abbreviation.tag,
    parentOffset: parents.at(-1) ?? null, attributes });
  if (abbreviation.hasChildren) parents.push(offset);
  return true;
};

export const parseDwarfDies = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  header: DwarfUnitHeader,
  abbreviations: Map<bigint, DwarfAbbreviation>,
  littleEndian: boolean,
  issues: string[]
): Promise<DwarfDie[]> => {
  const cursor = new DwarfCursor(
    reader, section, header.dataOffset, header.end, littleEndian, issues
  );
  const context: DwarfUnitContext = {
    version: header.version, format: header.format,
    addressSize: header.addressSize, stringOffsetsBase: null
  };
  const dies: DwarfDie[] = [];
  const parents: number[] = [];
  while (!cursor.failed && cursor.position < cursor.end) {
    if (!await readDie(cursor, abbreviations, context, dies, parents)) break;
  }
  if (parents.length) cursor.notice("Unterminated DIE child list");
  return dies;
};
