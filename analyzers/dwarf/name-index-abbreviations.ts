import type { DwarfCursor } from "./cursor.js";
import type { DwarfAbbreviationAttribute } from "./types.js";

export type DwarfNameAbbreviation = { tag: number; attributes: DwarfAbbreviationAttribute[] };

const validAttributePair = (cursor: DwarfCursor, name: bigint, form: bigint): boolean => {
  if (name && form && name <= BigInt(Number.MAX_SAFE_INTEGER) && form <= BigInt(Number.MAX_SAFE_INTEGER)) return true;
  cursor.fail("Invalid name index abbreviation attribute/form pair");
  return false;
};

const readAttributes = async (cursor: DwarfCursor): Promise<DwarfAbbreviationAttribute[] | null> => {
  const attributes: DwarfAbbreviationAttribute[] = [];
  while (cursor.position < cursor.end) {
    const name = await cursor.uleb();
    const form = await cursor.uleb();
    if (name == null || form == null) return null;
    if (!name && !form) return attributes;
    if (!validAttributePair(cursor, name, form)) return null;
    const implicitConstant = form === 0x21n ? await cursor.sleb() : null;
    if (cursor.failed) return null;
    attributes.push({ name: Number(name), form: Number(form), implicitConstant });
  }
  cursor.fail("Unterminated name index abbreviation attributes");
  return null;
};

export const readDwarfNameAbbreviations = async (cursor: DwarfCursor): Promise<Map<bigint, DwarfNameAbbreviation>> => {
  const abbreviations = new Map<bigint, DwarfNameAbbreviation>();
  while (cursor.position < cursor.end) {
    const code = await cursor.uleb();
    if (code == null) return abbreviations;
    if (!code) {
      cursor.skip(cursor.end - cursor.position); // Optional table padding: DWARF 5 6.1.1.4.7.
      return abbreviations;
    }
    const tag = await cursor.uleb();
    if (tag == null) return abbreviations;
    if (!tag || tag > BigInt(Number.MAX_SAFE_INTEGER) || abbreviations.has(code)) {
      cursor.fail("Invalid tag or duplicate name index abbreviation code");
      return abbreviations;
    }
    const attributes = await readAttributes(cursor);
    if (!attributes) return abbreviations;
    abbreviations.set(code, { tag: Number(tag), attributes });
  }
  cursor.notice("Name index abbreviation table has no terminator");
  return abbreviations;
};
