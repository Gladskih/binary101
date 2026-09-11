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
import { createElfArmEhabiModel, createElfArmScopeModel } from "./arm-ehabi.js";
import { createElfCoreTableModel, createElfCoreMappingModel } from "./core-notes.js";

const getArmTable = (
  elf: ElfParseResult,
  tableId: string
): PagedSortableTableModel | null => {
  for (const [index, table] of (elf.armEhabi ?? []).entries()) {
    if (tableId === `elf-arm-ehabi-${index}`) return createElfArmEhabiModel(table, index);
    if (tableId === `elf-arm-scopes-${index}`) return createElfArmScopeModel(table, index);
  }
  return null;
};

const getCoreTable = (elf: ElfParseResult, tableId: string): PagedSortableTableModel | null => {
  for (const [index, note] of (elf.notes?.entries ?? []).entries()) {
    if (!note.core) continue;
    if (tableId === `elf-core-${index}`) return createElfCoreTableModel(note.core, index);
    if (tableId === `elf-core-mappings-${index}`) return createElfCoreMappingModel(note.core, index);
  }
  return null;
};

type TableResolver = (elf: ElfParseResult, tableId: string) => PagedSortableTableModel | null;
const tableResolvers: TableResolver[] = [
  getArmTable, getCoreTable, getElfLsdaTableModel,
  (elf, id) => {
    const index = elf.mips?.findIndex((_, index) => id === `elf-mips-options-${index}`) ?? -1;
    return index >= 0 ? createElfMipsOptionModel(elf.mips![index]!, index) : null;
  },
  (elf, id) => {
    const table = elf.symbolTables?.find(table => id === `elf-symbols-${table.sectionIndex}`);
    return table ? createElfSymbolTableModel(table) : null;
  },
  (elf, id) => {
    const section = elf.attributes?.find(section => id === `elf-attributes-${section.sectionIndex}`);
    return section ? createElfAttributeTableModel(section) : null;
  },
  (elf, id) => {
    const section = elf.unwind?.find(section => id === `elf-unwind-${section.sectionIndex}`);
    return section ? createElfUnwindTableModel(section) : null;
  },
  (elf, id) => {
    const table = elf.hashTables?.find(table => id === `elf-hash-${table.kind}-${table.offset}`);
    return table ? createElfHashTableModel(table) : null;
  }
];

export const getElfPagedTableModel: TableResolver = (elf, tableId) => {
  for (const resolve of tableResolvers) {
    const table = resolve(elf, tableId);
    if (table) return table;
  }
  return tableId === "elf-relocations" && elf.relocations
    ? createElfRelocationTableModel(elf)
    : getNativeAotReflectionTypeTableModel(elf.nativeAot?.reflection, tableId);
};
