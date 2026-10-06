"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { DWARF_CHILDREN, DWARF_FORM, DWARF_SENTINEL } from "./constants.js";
import { DwarfCursor } from "./cursor.js";
import type {
  DwarfAbbreviation,
  DwarfAbbreviationAttribute,
  DwarfSectionInput
} from "./types.js";

const toSafeOffset = (value: bigint, section: DwarfSectionInput, issues: string[]): number | null => {
  const offset = Number(value);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= section.size) {
    issues.push(
      `${section.name}: abbreviation offset ${value.toString()} falls outside the section.`
    );
    return null;
  }
  return offset;
};

const isAttributeTerminator = (name: bigint, form: bigint): boolean =>
  name === DWARF_SENTINEL.attributeListEnd && form === DWARF_SENTINEL.attributeListEnd;

const validAttributePair = (cursor: DwarfCursor, name: bigint, form: bigint): boolean => {
  if (name === 0n || form === 0n) {
    cursor.fail("Invalid abbreviation attribute/form pair");
    return false;
  }
  if ([name, form].some(value => value > BigInt(Number.MAX_SAFE_INTEGER))) {
    cursor.fail("Abbreviation attribute or form exceeds the safe integer range");
    return false;
  }
  return true;
};

const readAttribute = async (cursor: DwarfCursor): Promise<DwarfAbbreviationAttribute | null> => {
  const name = await cursor.uleb();
  const form = await cursor.uleb();
  if (name == null || form == null) return null;
  if (isAttributeTerminator(name, form)) return null;
  if (!validAttributePair(cursor, name, form)) return null;
  // DW_FORM_implicit_const is followed by an SLEB128 value in .debug_abbrev.
  // DWARF 5, section 7.5.3: https://dwarfstd.org/doc/DWARF5.pdf
  const implicitConstant = form === BigInt(DWARF_FORM.implicitConstant)
    ? await cursor.sleb()
    : null;
  if (form === BigInt(DWARF_FORM.implicitConstant) && implicitConstant == null) return null;
  return { name: Number(name), form: Number(form), implicitConstant };
};

const readAttributes = async (cursor: DwarfCursor): Promise<DwarfAbbreviationAttribute[]> => {
  const attributes: DwarfAbbreviationAttribute[] = [];
  while (!cursor.failed && cursor.position < cursor.end) {
    const start = cursor.position;
    const attribute = await readAttribute(cursor);
    if (!attribute) return attributes;
    attributes.push(attribute);
    if (cursor.position === start) break;
  }
  cursor.fail("Unterminated abbreviation attribute list");
  return attributes;
};

const readEntry = async (cursor: DwarfCursor): Promise<DwarfAbbreviation | null> => {
  const tag = await cursor.uleb();
  const children = await cursor.uint8();
  if (tag == null || children == null) return null;
  if (children > DWARF_CHILDREN.yes) {
    cursor.fail(`Invalid DW_CHILDREN value ${children}`);
    return null;
  }
  if (tag > BigInt(Number.MAX_SAFE_INTEGER)) {
    cursor.fail("Abbreviation tag exceeds the safe integer range");
    return null;
  }
  return { tag: Number(tag), hasChildren: children !== DWARF_CHILDREN.no,
    attributes: await readAttributes(cursor) };
};

export const parseAbbreviationTable = async (
  reader: FileRangeReader,
  section: DwarfSectionInput,
  offsetValue: bigint,
  littleEndian: boolean,
  issues: string[]
): Promise<Map<bigint, DwarfAbbreviation> | null> => {
  const offset = toSafeOffset(offsetValue, section, issues);
  if (offset == null) return null;
  const cursor = new DwarfCursor(reader, section, offset, section.size, littleEndian, issues);
  const entries = new Map<bigint, DwarfAbbreviation>();
  while (cursor.position < cursor.end) {
    const code = await cursor.uleb();
    if (code == null) break;
    if (code === DWARF_SENTINEL.abbreviationTableEnd) return entries;
    if (entries.has(code)) {
      cursor.fail(`Duplicate abbreviation code ${code.toString()}`);
      break;
    }
    const entry = await readEntry(cursor);
    if (!entry) break;
    entries.set(code, entry);
  }
  if (!cursor.failed) cursor.notice("Unterminated abbreviation table");
  return cursor.failed ? null : entries;
};
