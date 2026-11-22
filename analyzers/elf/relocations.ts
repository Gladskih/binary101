import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import type { ElfRelocationImage } from "./relocation-types.js";
import type { ElfRelocation, ElfRelocationInfo, ElfRelocationSymbol } from "./relocation-types.js";
import { readElfDynamicTable, type ElfDynamicEntry, type ElfDynamicTable } from "./dynamic-entries.js";
import { readElfRelocationTags } from "./relocation-dynamic.js";
import { collectElfRelocationTables } from "./relocation-tables.js";
import { readElfRelocationRecords } from "./relocation-records.js";
import { createElfRelocationSymbolReader } from "./relocation-symbols.js";
import { locateElfRelocationTarget } from "./relocation-targets.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { ELF_FILE_TYPE, ELF_SECTION_FLAG, ELF_SYMBOL_INDEX } from "./abi-constants.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import type { ElfRelocationTable } from "./relocation-types.js";
import { ELF_SECTION_COMPRESSED, openElfSectionData } from "./section-data.js";
import { elfRuntimeRelocationOperation, elfRuntimeRelocationWriteSize,
  isElfRuntimeRelocationTable, type ElfRelocationOperation } from "./relocation-operation.js";
import { readElfStoredRelocationAddend } from "./relocation-addend.js";
import { createElfRelativePrefixValidator } from "./relocation-prefix.js";
import { createElfRelocationPermissionCheck } from "./relocation-permissions.js";

const createTargetBoundsReader = (
  reader: FileRangeReader, elf: ElfRelocationImage, issues: string[], prepared: Map<number, bigint>
) => {
  const sizes = new Map(prepared);
  const checked = new Set(prepared.keys());
  return {
    sizes,
    read: async (index: number): Promise<void> => {
      if (checked.has(index)) return;
      checked.add(index);
      const section = elf.sections[index];
      if (!section || !(section.flags & ELF_SECTION_COMPRESSED)) return;
      // Only section-relative targets use the logical bounds.
      if (elf.header.type !== ELF_FILE_TYPE.REL && (section.flags & ELF_SECTION_FLAG.ALLOC)) return;
      const source = await openElfSectionData(reader, section, elf, issues);
      if (source) sizes.set(index, BigInt(source.size));
    }
  };
};

const createEntryResolver = (
  reader: FileRangeReader, elf: ElfRelocationImage,
  readSymbol: ReturnType<typeof createElfRelocationSymbolReader>, issues: string[],
  layout: ElfBinaryLayout, logicalSizes: Map<number, bigint>
) => async (entry: ElfRelocation, table: ElfRelocationTable,
  operation?: ElfRelocationOperation): Promise<ElfRelocation> => {
  const width = elfRuntimeRelocationWriteSize(elf, operation);
  const target = entry.type === 0 ? null :
    locateElfRelocationTarget(elf, table, entry.offset, issues, layout, logicalSizes, width);
  const storedAddend = operation && await readElfStoredRelocationAddend(reader, elf, table, entry, operation, target);
  return { ...entry, target,
    symbol: entry.symbolIndex != null && entry.symbolIndex !== ELF_SYMBOL_INDEX.UNDEF
      ? await readSymbol(table, entry.symbolIndex) : null,
    ...(storedAddend !== undefined && { storedAddend }) };
};

const recordIdentity = (elf: ElfRelocationImage, table: ElfRelocationTable,
  entry: ElfRelocation, ordinal: number): string => {
  const identity = table.encoding === "ANDROID_REL" || table.encoding === "ANDROID_RELA"
    ? `${table.offset}:${ordinal}` : `${entry.recordOffset}:${entry.offset}`;
  const context = elf.header.type === 1 ? `${table.targetSectionIndex}:${table.symbolTableIndex}` : "";
  return `${table.encoding}:${table.compressed ? table.offset : ""}:${identity}:${context}`;
};

export const parseElfRelocations = async (
  file: File, elf: ElfRelocationImage, dynamicEntries?: ElfDynamicEntry[] | ElfDynamicTable,
  symbolCache?: Map<number, ElfRelocationSymbol>, layout = selectElfBinaryLayout(elf),
  logicalSizes = new Map<number, bigint>()
): Promise<ElfRelocationInfo | null> => {
  const reader = createFileRangeReader(file, 0, file.size);
  const issues: string[] = [];
  const dynamic = Array.isArray(dynamicEntries) ? { entries: dynamicEntries, terminated: false } :
    dynamicEntries ?? await readElfDynamicTable(reader, elf, issues, layout);
  const tags = await readElfRelocationTags(reader, elf, issues, dynamic.entries, layout);
  const tables = collectElfRelocationTables(elf, tags, issues, layout);
  if (!tables.length && !issues.length) return null;
  const readSymbol = createElfRelocationSymbolReader(reader, elf, tags, issues, symbolCache, layout);
  const targetBounds = createTargetBoundsReader(reader, elf, issues, logicalSizes);
  const resolveEntry = createEntryResolver(reader, elf, readSymbol, issues, layout, targetBounds.sizes);
  const checkPermissions = createElfRelocationPermissionCheck(elf, dynamic, layout, issues);
  const entries: ElfRelocation[] = [];
  const visited = new Set<string>();
  for (const [tableIndex, table] of tables.entries()) {
    const runtime = isElfRuntimeRelocationTable(elf, table);
    const validatePrefix = runtime && createElfRelativePrefixValidator(elf, table, tags, issues);
    // Exact aliases are merged above; overlapping tables need independent RELR cursors.
    let ordinal = 0;
    let targetIndex = table.targetSectionIndex;
    for await (const entry of readElfRelocationRecords(reader, table, elf, tableIndex, issues, layout)) {
      const operation = runtime ? elfRuntimeRelocationOperation(elf, entry.type) : undefined;
      if (validatePrefix) validatePrefix(ordinal, entry, operation);
      const key = recordIdentity(elf, table, entry, ordinal++);
      if (visited.has(key)) continue;
      visited.add(key);
      if (entry.type !== 0 && targetIndex != null) {
        await targetBounds.read(targetIndex);
        targetIndex = null;
      }
      const resolved = await resolveEntry(entry, table, operation);
      if (resolved.target) {
        checkPermissions?.(table, entry.offset, elfRuntimeRelocationWriteSize(elf, operation));
      }
      entries.push(resolved);
    }
  }
  return { tables, entries, issues: [...new Set(issues)] };
};
