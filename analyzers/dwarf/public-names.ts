import { dwarfSectionContributions } from "./section-contributions.js";
import type { DwarfCursor } from "./cursor.js";
import type { DwarfPublicName, DwarfPublicNames } from "./lookup-types.js";
import type { DwarfSectionSource, DwarfUnit } from "./types.js";
import { dwarfSplitFilename, dwarfSplitIdentity } from "./external-files.js";

// DWARF 4 6.1.1/6.1.2; GNU descriptor byte from LLVM DWARFDebugPubTable.cpp.
// https://dwarfstd.org/doc/DWARF4.pdf
const readEntries = async (cursor: DwarfCursor, format: 32 | 64,
  sectionName: string): Promise<DwarfPublicName[]> => {
  const entries: DwarfPublicName[] = [];
  while (cursor.position < cursor.end) {
    const dieOffset = await cursor.unsigned(format / 8);
    if (dieOffset == null) return entries;
    if (!dieOffset) {
      if (cursor.position < cursor.end) cursor.notice("Trailing bytes after public names terminator");
      return entries;
    }
    const descriptor = sectionName.startsWith(".debug_gnu_") ? await cursor.uint8() : null;
    const name = await cursor.cstring();
    if (name == null || cursor.failed) return entries;
    entries.push({ dieOffset, name, descriptor });
  }
  cursor.notice("Public names contribution has no terminator");
  return entries;
};

const validateUnit = (cursor: DwarfCursor, table: DwarfPublicNames, units: DwarfUnit[]): void => {
  const unit = lookupUnit(cursor, table, units);
  if (!unit) return;
  // unit_length includes the initial length field; DWARF 4 Figure 34.
  const actualLength = unit.length + BigInt(unit.format === 32 ? 4 : 12);
  if (actualLength !== table.unitLength) cursor.notice("Public names compilation-unit length mismatch");
  const offsets = new Set(unit.dies.map(die => BigInt(die.offset - unit.offset)));
  for (const entry of table.entries) {
    if (!offsets.has(entry.dieOffset)) cursor.notice(`Public name ${entry.name} references a missing DIE`);
  }
};

const lookupUnit = (cursor: DwarfCursor, table: DwarfPublicNames, units: DwarfUnit[]): DwarfUnit | null => {
  const unit = units.find(unit => unit.sectionName === ".debug_info" && BigInt(unit.offset) === table.unitOffset);
  if (!unit) { cursor.notice("Public names reference a missing compilation unit"); return null; }
  if (unit.unitType !== 4 && !dwarfSplitFilename(unit)) return unit;
  const id = dwarfSplitIdentity(unit);
  const split = id == null ? null : units.find(candidate => candidate.sectionName === ".debug_info.dwo" &&
    dwarfSplitIdentity(candidate) === id);
  if (!split) cursor.notice("Public names refer to the external split compilation unit");
  return split ?? null;
};

export const readDwarfPublicNames = async (source: DwarfSectionSource, units: DwarfUnit[],
  byteOrder: "little" | "big", issues: string[]): Promise<DwarfPublicNames[]> => {
  const tables: DwarfPublicNames[] = [];
  for await (const { cursor, offset, format } of dwarfSectionContributions(source, byteOrder, issues)) {
    const version = await cursor.uint16();
    if (version == null) continue;
    if (version !== 2) { cursor.notice(`Unsupported public names version ${version}`); continue; }
    const unitOffset = await cursor.unsigned(format / 8);
    const unitLength = await cursor.unsigned(format / 8);
    if (unitOffset == null || unitLength == null) continue;
    const table = { sectionName: source.section.name, offset, format, unitOffset, unitLength,
      entries: await readEntries(cursor, format, source.section.name) };
    validateUnit(cursor, table, units);
    tables.push(table);
  }
  return tables;
};
