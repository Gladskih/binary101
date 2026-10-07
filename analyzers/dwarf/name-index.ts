import { DwarfCursor } from "./cursor.js";
import { dwarfSectionContributions } from "./section-contributions.js";
import { readDwarfNameIndexHeader } from "./name-index-header.js";
import { readDwarfNameAbbreviations } from "./name-index-abbreviations.js";
import { readDwarfNameEntries } from "./name-index-entries.js";
import { validateDwarfNameIndex } from "./name-index-validation.js";
import type { DwarfNameIndex, DwarfNameIndexHeader } from "./name-index-types.js";
import type { DwarfSectionSource, DwarfUnit } from "./types.js";
import type { DwarfStringReader } from "./strings.js";

const readArray = async (cursor: DwarfCursor, count: number, width: number): Promise<bigint[]> => {
  const values: bigint[] = [];
  for (let index = 0; index < count; index += 1) {
    const value = await cursor.unsigned(width);
    if (value == null) break;
    values.push(value);
  }
  return values;
};

const readArrays = async (cursor: DwarfCursor, header: DwarfNameIndexHeader, format: 32 | 64) => ({
  compileUnits: await readArray(cursor, header.compileUnitCount, format / 8),
  localTypeUnits: await readArray(cursor, header.localTypeUnitCount, format / 8),
  foreignTypeUnits: await readArray(cursor, header.foreignTypeUnitCount, 8),
  buckets: (await readArray(cursor, header.bucketCount, 4)).map(Number),
  hashes: header.bucketCount ? (await readArray(cursor, header.nameCount, 4)).map(Number) : [],
  stringOffsets: await readArray(cursor, header.nameCount, format / 8),
  entryOffsets: await readArray(cursor, header.nameCount, format / 8)
});

const readNames = async (source: DwarfSectionSource, cursor: DwarfCursor,
  header: DwarfNameIndexHeader, format: 32 | 64, byteOrder: "little" | "big",
  strings: DwarfStringReader, issues: string[]) => {
  const arrays = await readArrays(cursor, header, format);
  const abbreviationEnd = cursor.position + header.abbreviationSize;
  const abbreviationCursor = new DwarfCursor(source.reader, source.section, cursor.position,
    abbreviationEnd, byteOrder === "little", issues);
  const abbreviations = await readDwarfNameAbbreviations(abbreviationCursor);
  const names: DwarfNameIndex["names"] = [];
  const lists = new Map<bigint, DwarfNameIndex["names"][number]["entries"]>();
  for (const [index, stringOffset] of arrays.stringOffsets.entries()) {
    const text = await strings.resolve({ kind: "string-offset", sectionName: ".debug_str", value: stringOffset },
      { version: 5, format, addressSize: 0, stringOffsetsBase: null });
    const offset = arrays.entryOffsets[index]!;
    if (!lists.has(offset)) {
      lists.set(offset, offset >= BigInt(cursor.end - abbreviationEnd) ? [] : await readDwarfNameEntries(
        new DwarfCursor(source.reader, source.section, abbreviationEnd + Number(offset),
          cursor.end, byteOrder === "little", issues), abbreviationEnd, format, abbreviations));
      if (offset >= BigInt(cursor.end - abbreviationEnd)) cursor.notice("Name entry offset is outside its entry pool");
    }
    names.push({ name: text == null ? { kind: "string-offset", sectionName: ".debug_str", value: stringOffset }
      : { kind: "string", value: text }, hash: arrays.hashes[index] ?? null, entries: lists.get(offset)! });
  }
  return { compileUnits: arrays.compileUnits, localTypeUnits: arrays.localTypeUnits,
    foreignTypeUnits: arrays.foreignTypeUnits, buckets: arrays.buckets, names };
};

export const readDwarfNameIndex = async (source: DwarfSectionSource, units: DwarfUnit[],
  byteOrder: "little" | "big", strings: DwarfStringReader, issues: string[]): Promise<DwarfNameIndex[]> => {
  const tables: DwarfNameIndex[] = [];
  for await (const { cursor, offset, format } of dwarfSectionContributions(source, byteOrder, issues)) {
    const header = await readDwarfNameIndexHeader(cursor, format);
    if (!header) continue;
    const table = { offset, format, augmentation: header.augmentation,
      ...await readNames(source, cursor, header, format, byteOrder, strings, issues) };
    validateDwarfNameIndex(table, units, issues);
    tables.push(table);
  }
  return tables;
};
