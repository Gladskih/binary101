import { createFileRangeReader } from "../file-range-reader.js";
import type { ElfRelocationImage } from "./relocation-types.js";
import type { ElfRelocation, ElfRelocationInfo, ElfRelocationSymbol } from "./relocation-types.js";
import type { ElfDynamicEntry } from "./dynamic-entries.js";
import { readElfRelocationTags } from "./relocation-dynamic.js";
import { collectElfRelocationTables } from "./relocation-tables.js";
import { readElfRelocationRecords } from "./relocation-records.js";
import { createElfRelocationSymbolReader } from "./relocation-symbols.js";
import { locateElfRelocationTarget } from "./relocation-targets.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { ELF_SYMBOL_INDEX } from "./abi-constants.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import type { ElfRelocationTable } from "./relocation-types.js";

const resolveEntry = async (
  entry: ElfRelocation, table: ElfRelocationTable, elf: ElfRelocationImage,
  readSymbol: ReturnType<typeof createElfRelocationSymbolReader>, issues: string[],
  layout: ElfBinaryLayout, logicalSizes: Map<number, bigint>
): Promise<ElfRelocation> => ({
  ...entry,
  symbol: entry.symbolIndex != null && entry.symbolIndex !== ELF_SYMBOL_INDEX.UNDEF
    ? await readSymbol(table, entry.symbolIndex) : null,
  target: entry.type === 0 ? null :
    locateElfRelocationTarget(elf, table, entry.offset, issues, layout, logicalSizes)
});

const recordIdentity = (elf: ElfRelocationImage, table: ElfRelocationTable,
  entry: ElfRelocation, ordinal: number): string => {
  const identity = table.encoding === "ANDROID_REL" || table.encoding === "ANDROID_RELA"
    ? `${table.offset}:${ordinal}` : `${entry.recordOffset}:${entry.offset}`;
  const context = elf.header.type === 1 ? `${table.targetSectionIndex}:${table.symbolTableIndex}` : "";
  return `${table.encoding}:${table.compressed ? table.offset : ""}:${identity}:${context}`;
};

export const parseElfRelocations = async (
  file: File, elf: ElfRelocationImage, dynamicEntries?: ElfDynamicEntry[],
  symbolCache?: Map<number, ElfRelocationSymbol>, layout = selectElfBinaryLayout(elf),
  logicalSizes = new Map<number, bigint>()
): Promise<ElfRelocationInfo | null> => {
  const reader = createFileRangeReader(file, 0, file.size);
  const issues: string[] = [];
  const tags = await readElfRelocationTags(reader, elf, issues, dynamicEntries, layout);
  const tables = collectElfRelocationTables(elf, tags, issues, layout);
  if (!tables.length && !issues.length) return null;
  const readSymbol = createElfRelocationSymbolReader(reader, elf, tags, issues, symbolCache, layout);
  const entries: ElfRelocation[] = [];
  const visited = new Set<string>();
  for (const [tableIndex, table] of tables.entries()) {
    // Exact aliases are merged above; overlapping tables need independent RELR cursors.
    let ordinal = 0;
    for await (const entry of readElfRelocationRecords(reader, table, elf, tableIndex, issues, layout)) {
      const key = recordIdentity(elf, table, entry, ordinal++);
      if (visited.has(key)) continue;
      visited.add(key);
      entries.push(await resolveEntry(entry, table, elf, readSymbol, issues, layout, logicalSizes));
    }
  }
  return { tables, entries, issues: [...new Set(issues)] };
};
