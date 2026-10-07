import { DwarfCursor } from "./cursor.js";
import { readDwarfPackageHeader } from "./package-header.js";
import { validateDwarfPackageIndex } from "./package-index-validation.js";
import type { DwarfPackageContribution, DwarfPackageHeader, DwarfPackageIndex } from "./package-types.js";
import type { DwarfSectionSource } from "./types.js";

const readSlots = async (cursor: DwarfCursor, count: number): Promise<DwarfPackageIndex["slots"]> => {
  const slots: DwarfPackageIndex["slots"] = [];
  for (let index = 0; index < count; index += 1) {
    const signature = await cursor.uint64();
    if (signature == null) return slots;
    slots.push({ signature, row: 0 });
  }
  for (const slot of slots) slot.row = await cursor.uint32() ?? 0;
  return slots;
};

const readColumns = async (cursor: DwarfCursor, count: number): Promise<number[]> => {
  const columns: number[] = [];
  for (let index = 0; index < count; index += 1) {
    const identifier = await cursor.uint32();
    if (identifier == null) break;
    columns.push(identifier);
  }
  return columns;
};

const readRows = async (cursor: DwarfCursor, header: DwarfPackageHeader): Promise<DwarfPackageContribution[][]> => {
  const rows: DwarfPackageContribution[][] = [];
  for (let index = 0; index < header.unitCount; index += 1) {
    const row: DwarfPackageContribution[] = [];
    for (let column = 0; column < header.sectionCount; column += 1) {
      const offset = await cursor.uint32();
      if (offset == null) return rows;
      row.push({ offset, size: 0 });
    }
    rows.push(row);
  }
  for (const row of rows) for (const contribution of row) contribution.size = await cursor.uint32() ?? 0;
  return rows;
};

export const readDwarfPackageIndex = async (source: DwarfSectionSource,
  sources: Map<string, DwarfSectionSource>, byteOrder: "little" | "big",
  issues: string[]): Promise<DwarfPackageIndex | null> => {
  const cursor = new DwarfCursor(source.reader, source.section, 0, source.section.size, byteOrder === "little", issues);
  const header = await readDwarfPackageHeader(cursor, byteOrder);
  if (!header) return null;
  const slots = await readSlots(cursor, header.slotCount);
  const columns = await readColumns(cursor, header.sectionCount);
  const rows = await readRows(cursor, header);
  if (cursor.failed) return null;
  if (cursor.position < cursor.end) cursor.notice("Trailing bytes after package index matrices");
  const table = { sectionName: source.section.name, version: header.version, slots, columns, rows };
  validateDwarfPackageIndex(table, sources, issues);
  return table;
};
