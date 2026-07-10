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

const readAttribute = async (cursor: DwarfCursor): Promise<DwarfAbbreviationAttribute | null> => {
  const name = await cursor.uleb();
  const form = await cursor.uleb();
  if (name == null || form == null) return null;
  if (name === DWARF_SENTINEL.attributeListEnd &&
      form === DWARF_SENTINEL.attributeListEnd) return null;
  if (name > BigInt(Number.MAX_SAFE_INTEGER) || form > BigInt(Number.MAX_SAFE_INTEGER)) {
    cursor.fail("Abbreviation attribute or form exceeds the safe integer range");
    return null;
  }
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
    if (attribute) attributes.push(attribute);
    if (cursor.failed || cursor.position === start || !attribute) break;
  }
  return attributes;
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
  while (!cursor.failed && cursor.position < cursor.end) {
    const code = await cursor.uleb();
    if (code == null || code === DWARF_SENTINEL.abbreviationTableEnd) break;
    const tag = await cursor.uleb();
    const children = await cursor.uint8();
    if (tag == null || children == null) break;
    if (children > DWARF_CHILDREN.yes) {
      cursor.fail(`Invalid DW_CHILDREN value ${children}`);
      break;
    }
    if (tag > BigInt(Number.MAX_SAFE_INTEGER)) {
      cursor.fail("Abbreviation tag exceeds the safe integer range");
      break;
    }
    if (entries.has(code)) {
      cursor.fail(`Duplicate abbreviation code ${code.toString()}`);
      break;
    }
    entries.set(code, {
      tag: Number(tag),
      hasChildren: children !== DWARF_CHILDREN.no,
      attributes: await readAttributes(cursor)
    });
  }
  return cursor.failed ? null : entries;
};
