"use strict";

import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";
import { getNativeAotReflectionTypeTableModel } from "../native-aot/reflection.js";
import { createElfRelocationTableModel } from "./relocations.js";

export const getElfPagedTableModel = (
  elf: ElfParseResult,
  tableId: string
): PagedSortableTableModel | null =>
  tableId === "elf-relocations" && elf.relocations
    ? createElfRelocationTableModel(elf)
    : getNativeAotReflectionTypeTableModel(elf.nativeAot?.reflection, tableId);
