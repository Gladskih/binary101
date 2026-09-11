"use strict";

import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";
import { getNativeAotReflectionTypeTableModel } from "../native-aot/reflection.js";
import { createElfRelocationTableModel } from "./relocations.js";
import { createElfSymbolTableModel } from "./symbol-tables.js";
import { createElfUnwindTableModel } from "./unwind.js";
import { createElfHashTableModel } from "./hash-tables.js";
import { createElfAttributeTableModel } from "./attributes.js";
import { createElfMipsOptionModel } from "./mips.js";
import { getElfLsdaTableModel } from "./lsda.js";
import { createElfCoreTableModel, createElfCoreMappingModel } from "./core-notes.js";

export const getElfPagedTableModel = (
  elf: ElfParseResult,
  tableId: string
): PagedSortableTableModel | null => {
  const lsda = getElfLsdaTableModel(elf, tableId);
  if (lsda) return lsda;
  const mipsIndex = elf.mips?.findIndex((_, index) => tableId === `elf-mips-options-${index}`) ?? -1;
  if (mipsIndex >= 0) return createElfMipsOptionModel(elf.mips![mipsIndex]!, mipsIndex);
  for (const [index, note] of (elf.notes?.entries ?? []).entries()) {
    if (!note.core) continue;
    if (tableId === `elf-core-${index}`) return createElfCoreTableModel(note.core, index);
    if (tableId === `elf-core-mappings-${index}`) return createElfCoreMappingModel(note.core, index);
  }
  const symbols = elf.symbolTables?.find(table => tableId === `elf-symbols-${table.sectionIndex}`);
  const attributes = elf.attributes?.find(section => tableId === `elf-attributes-${section.sectionIndex}`);
  if (attributes) return createElfAttributeTableModel(attributes);
  if (symbols) return createElfSymbolTableModel(symbols);
  const unwind = elf.unwind?.find(section => tableId === `elf-unwind-${section.sectionIndex}`);
  if (unwind) return createElfUnwindTableModel(unwind);
  const hash = elf.hashTables?.find(table => tableId === `elf-hash-${table.kind}-${table.offset}`);
  if (hash) return createElfHashTableModel(hash);
  return tableId === "elf-relocations" && elf.relocations
    ? createElfRelocationTableModel(elf)
    : getNativeAotReflectionTypeTableModel(elf.nativeAot?.reflection, tableId);
};
